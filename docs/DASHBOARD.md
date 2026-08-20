# Secure OTA Control Center

A web dashboard for watching and operating the OTA system: device status,
firmware management, OTA control, a security monitor and live logs.

```
python server/app.py
```

then open <http://localhost:8000/dashboard>.

The dashboard is a **management layer only**. It sits beside the existing OTA
server; it does not sign, encrypt, decrypt, hash or verify anything, and the
device-facing endpoints the ESP32 uses are untouched.

---

## 1. What it shows

| Page | Path | Contents |
| --- | --- | --- |
| Overview | `/dashboard` | device status card, firmware/update card, crypto status, live OTA progress, the OTA security pipeline, recent activity, security events, log tail |
| Firmware | `/firmware` | upload a `.bin`, create a signed package, publish/withdraw it, package details (hash, nonce, tag, signature prefix) |
| OTA History | `/history` | every OTA attempt and outcome, with versions, result and reason |
| Security | `/security` | cryptography status, the Security Test Lab, the security-event log |
| Live Logs | `/logs` | server + device log stream over Server-Sent Events, filterable |

### Nothing is invented

If the device has never reported a value, the dashboard shows `—`. If no OTA is
running, the progress card says so rather than animating a bar. If the device
has not sent a heartbeat inside the timeout it is `OFFLINE`, and the telemetry
below it is labelled as the last reported state. Progress percentages come from
byte counters the device sends; the pipeline highlights the state the device
reports and nothing more.

---

## 2. How the device talks to it

`main/device_report.c` adds one FreeRTOS task. It does two things.

**Heartbeat** — every 5 s (1.5 s during an update):

```
POST /api/device/heartbeat
{ "device_id": "esp32-demo-01", "ip": "...", "firmware_version": "1.0.0",
  "security_version": 1, "partition": "ota_1", "free_heap": 203108,
  "uptime_s": 42, "ota_state": "DECRYPT", "ota_done": 688128,
  "ota_total": 926688, "wifi_rssi": -52, "chip_model": "ESP32", ... }
```

Everything in that payload is already printed on the serial console. Key
*fingerprints* are included (Ascon-Hash256 of a key, truncated); key bytes never
are.

**Events** — one POST per OTA outcome, queued so the OTA task never blocks:

```
POST /api/device/esp32-demo-01/event
{ "event": "REJECT", "stage": "SIGNATURE_VERIFY", "result": "REJECTED",
  "reason": "Ed25519 signature verification failed", ... }
```

The heartbeat response — and `GET /api/device/<id>/commands` — may carry
commands. **Exactly three exist**, and the firmware compares against string
literals:

| Command | Effect on the device |
| --- | --- |
| `CHECK_UPDATE` | `ota_manager_trigger_now()` |
| `START_OTA` | `ota_manager_trigger_now()` |
| `REBOOT` | `esp_restart()` |

Anything else is logged and ignored. There is no endpoint that runs a shell, no
parameterised command, and no way for the server to supply a URL, a version, a
key or a payload. A command only *starts* the existing state machine; the update
that follows is verified by exactly the same code as a timer-driven one.

This matters for the threat model: the server is untrusted by design. A
compromised dashboard can pester a device into checking for updates and reboot
it. It cannot make it install anything, because the Ed25519 private key is not
on the server, and the device verifies the signature against a public key
compiled into its own image.

---

## 3. Upload → package → publish

The dashboard never handles keys. The browser sends a firmware image, a version
and a security version; everything cryptographic happens in a subprocess on the
build host.

```
browser ── .bin ──▶ server/firmware/uploads/
                         │
                         │ POST /api/firmware/package
                         ▼
              tools/create_ota_package.py        ← reads keys/ on this machine
                 Ascon-Hash256 of the plaintext
                 Ascon-AEAD128 encrypt (fresh nonce, AD = header[0:80])
                 Ed25519 sign header[0:96]
                         │
                         ▼
                  server/staging/firmware_vX.sota      (NOT offered to devices)
                         │
                         │ POST /api/firmware/<file>/publish
                         ▼
                 server/packages/firmware_vX.sota      (the OTA server serves it)
```

Publishing is a byte-for-byte copy. The package is never modified after signing
— it cannot be, since the signature covers the header. A package is never
overwritten either: creating a version that already exists returns `409`.

`server/staging/` is a genuine staging area. No existing route reads it, so a
package that has been built but not published is invisible to the ESP32.

### Key handling

* The Ed25519 private key and the Ascon key stay in `keys/` on the build host.
* No API response contains key material; `tests/test_dashboard.py` asserts this.
* The browser never receives, stores or sends a key.
* Only fingerprints are displayed.

Note the honest limitation: the *package creation* feature requires the signing
key on the machine running the dashboard. That is the same machine a developer
already runs `tools/create_ota_package.py` on. The OTA *serving* path still holds
no keys — if you want the strict separation, run the dashboard on the build host
and serve packages from a machine that only has `server/packages/`.

---

## 4. Security Test Lab

`/security` runs the project's existing attack tooling on demand:
`tools/tamper_package.py` builds a hostile package, `tools/verify_package.py`
refuses it, both in a scratch directory that is deleted afterwards.

| Test | Tamper mode | Expected rejection |
| --- | --- | --- |
| Valid Package | — | accepted |
| Firmware Tampering | `flip-ciphertext` | Ascon-AEAD128 tag |
| Hash Tampering | `hash-mismatch` | Ascon-Hash256 digest |
| Invalid Signature | `bad-signature` | Ed25519 |
| Attacker's Signing Key | `foreign-signer` | Ed25519 |
| Wrong Encryption Key | `wrong-key` | Ascon-AEAD128 tag |
| Metadata Tampering | `flip-metadata` | Ed25519 over `header[0:96]` |
| Rollback Attack | `rollback` | anti-rollback rule |
| Interrupted Transfer | `truncate` | structural check |

`PROTECTED` (green) means the attack was detected and the update rejected.
`VULNERABLE` (red) would mean a tampered package was accepted. Hostile packages
are never published and never offered to a device.

This is a host-side proof about the package format. It is not a substitute for
the on-device demonstration in [`DEMO.md`](DEMO.md), where the ESP32 itself
rejects the package.

---

## 5. Version mismatch

The dashboard shows the version the **device reports**, not the version the
package claimed. When an install reports `2.0.0` and the device comes back
reporting `1.0.0`, the overview shows:

```
⚠ VERSION MISMATCH
The installed package declared firmware 2.0.0, but the device reports 1.0.0
after rebooting.
```

That is a real condition, seen on hardware: it happens when the `.bin` that was
packaged was not rebuilt after changing `FIRMWARE_VERSION_*` / `SECURITY_VERSION`
in `main/app_config.h`. The update itself was cryptographically sound — signature,
tag and hash all passed — but the image inside the package is the old build. The
fix is to edit those constants, run `idf.py build`, and package the new
`build/secure_ota.bin`.

The dashboard reports this instead of assuming success, because "the update
installed" and "the device is now running what you intended" are different
claims.

---

## 6. Online / offline / rebooting

| State | Meaning |
| --- | --- |
| `ONLINE` | a heartbeat arrived within `SOTA_HEARTBEAT_TIMEOUT` seconds (default 15) |
| `REBOOTING` | no heartbeat, but the last reported state was `INSTALL` or `REBOOT` and it has been less than `SOTA_REBOOT_GRACE` seconds (default 120) |
| `OFFLINE` | no heartbeat, and no reason to expect a restart |
| `UNKNOWN` | no device has ever reported in |

Both timeouts are environment variables:

```bash
set SOTA_HEARTBEAT_TIMEOUT=20
set SOTA_REBOOT_GRACE=180
python server/app.py
```

---

## 7. API

Existing endpoints (**unchanged**, used by the ESP32):

```
GET  /api/firmware/latest
GET  /api/firmware/list
GET  /api/firmware/<version>/package
GET  /api/firmware/latest/package
GET  /health
```

Device-facing additions:

```
POST /api/device/heartbeat
GET  /api/device/<device_id>/commands
POST /api/device/<device_id>/event
POST /api/device/log
```

Dashboard-facing:

```
GET  /api/dashboard/summary
GET  /api/devices
GET  /api/devices/<device_id>
GET  /api/devices/<device_id>/heartbeat
GET  /api/devices/<device_id>/commands
POST /api/devices/<device_id>/command        {"command": "START_OTA"}
GET  /api/firmware
POST /api/firmware/upload                    multipart .bin
POST /api/firmware/package                   {"file","version","security_version"}
POST /api/firmware/<file>/publish
POST /api/firmware/<file>/unpublish
GET  /api/ota/history
GET  /api/security/events
GET  /api/security/lab
POST /api/security/lab/<test>
GET  /api/logs
GET  /api/logs/stream                        Server-Sent Events
```

---

## 8. Storage

SQLite, at `server/ota.db`, created on first run:

| Table | Rows |
| --- | --- |
| `devices` | latest heartbeat per device |
| `firmware_releases` | packages created through the dashboard |
| `ota_events` | update attempts, checks, downloads, boots |
| `security_events` | rejections, rollback attempts, lab results |
| `device_commands` | the command queue |

No secrets are stored. Deleting `server/ota.db` resets the dashboard's history
and nothing else; packages and keys are untouched.

---

## 9. Testing without hardware

```bash
python tools/simulate_device.py --ota
```

A simulator that speaks the heartbeat/command protocol so the UI can be checked
on a laptop. **It is not a device**: it performs no cryptography, downloads
nothing and installs nothing, and every value it reports is invented. It uses the
device id `esp32-sim-01` so it can never be confused with the real
`esp32-demo-01`. Use it to rehearse the interface — never to demonstrate that the
OTA pipeline works.

---

## 10. Limitations — read before you demonstrate this

**There is no authentication.** The server binds `0.0.0.0` so the ESP32 can reach
it, which means anyone on the same network can open the dashboard, queue a
`REBOOT`, upload a `.bin` and create a package. That is acceptable for a lab
demonstration on a private network and nothing more. Do not expose port 8000
beyond it, and do not port-forward it.

The worst an unauthenticated LAN user can do is real but bounded: reboot the
device, make it check for updates, fill the uploads directory, and publish a
package **that was signed by the key on this machine**. What they cannot do is
make the device install unsigned firmware — that would need the Ed25519 private
key, and the device verifies against a public key compiled into its own image.

Other honest limits:

* Package creation needs the signing key on the machine running the dashboard
  (see §3). The serving path still holds no keys.
* The dashboard's SQLite record is bookkeeping. It has no bearing on what the
  device accepts; anti-rollback state lives in the device's NVS.
* Heartbeat telemetry is unauthenticated, so a device id is a label, not an
  identity. It is fine for a demonstration and would need per-device
  authentication in anything real.
* The Security Test Lab proves the host-side verifier rejects tampered packages.
  The device runs the same checks in C, and `docs/DEMO.md` is where you show it
  doing so on hardware.

---

## 11. Files

```
server/app.py                     unchanged OTA endpoints + dashboard registration
server/dashboard/__init__.py      blueprint: routes and APIs
server/dashboard/db.py            SQLite schema and queries
server/dashboard/inventory.py     read-only view of packages/ and staging/
server/dashboard/packaging.py     wrapper around tools/create_ota_package.py
server/dashboard/sectest.py       wrapper around the tamper/verify tools
server/dashboard/logbus.py        in-memory log ring buffer + SSE source
server/dashboard/templates/       dashboard, firmware, history, security, logs
server/dashboard/static/          one stylesheet, one JS file per page
main/device_report.c              heartbeat, events, command polling
tools/simulate_device.py          simulated device for UI testing
tests/test_dashboard.py           35 tests, including "the OTA API still works"
```
