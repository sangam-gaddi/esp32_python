# The web interface

One page, at <http://localhost:8000/>, with one job: get a firmware `.bin` onto
an ESP32 safely.

```
python server/app.py
```

The page has three steps and a **How to use** section that tells you what to
type. It replaces the five-page control centre that used to live here; the
device-facing JSON APIs it was built on are unchanged and still documented in
§6.

```
  1  Upload your firmware        a .bin, checked on the way in
  2  Make it a secure package    Ascon-Hash256 + Ascon-AEAD128 + Ed25519
  3  Send it to your devices     publish the signed bytes, unmodified
```

The interface is a **management layer only**. It does not sign, encrypt,
decrypt, hash or verify anything itself — step 2 shells out to
`tools/create_ota_package.py`, exactly as a person would — and the endpoints the
ESP32 uses are untouched.

---

## 1. Upload security

This is a file-upload endpoint running on the machine that holds the Ed25519
signing key, so an uploaded file is treated as hostile until it has been
measured. Everything below is in [`server/dashboard/uploads.py`](../server/dashboard/uploads.py)
and covered by `tests/test_dashboard.py`.

### Any `.bin` is accepted

The client's file name is **sanitised, not trusted, and not rejected for being
ugly**. Directory components, drive letters, `..`, control characters, unicode
and whitespace are removed or replaced; the result always matches
`[A-Za-z0-9._-]+\.bin`.

| Sent by the browser | Stored as |
| --- | --- |
| `My Firmware (v2).BIN` | `My_Firmware_v2.bin` |
| `../../../../etc/passwd.bin` | `passwd.bin` |
| `C:\Users\me\build\secure_ota.bin` | `secure_ota.bin` |
| `firmwareéé.bin` | `firmware.bin` |
| `.bin` | `firmware.bin` |
| `NUL.bin` | `_NUL.bin` |

The last row matters on Windows, where `NUL`, `CON`, `COM1` and friends are
still device names. After the name is built, the destination path is re-checked
to be a **direct child** of `server/firmware/uploads/` before anything is moved
into place.

The one refusal is a file that is not named `*.bin` at all. That is a content
decision, not a safety boundary — see "what this does not prove" below.

### Nothing oversized, nothing tiny, nothing partial

| Rule | Value | Enforced |
| --- | --- | --- |
| Maximum | 16 MB | twice: Werkzeug's `MAX_CONTENT_LENGTH` refuses the body at the door, and the stream is capped again as it is written |
| Minimum | 1024 B | after the write; there is not even room for an image header below that |
| Completeness | — | the upload streams into a `.part` file and is moved into place with `os.replace()` only when it is finished |

An interrupted or oversized upload leaves **nothing** behind — no fragment that
could be listed, selected or signed. 16 MB is the largest flash any ESP32
variant carries, so no legitimate image exceeds it.

### Identified by its bytes, not by its name

SHA-256 is computed as the file is written and recorded with it. Uploading the
same bytes again under a different name reuses the existing copy and says so.
An upload **never overwrites** an existing file; a name collision with different
content gets a timestamp suffix.

### The image is inspected and reported

The ESP32 image header and the `esp_app_desc` structure are parsed, so the page
can say what it thinks it received:

```
Looks like      ESP32 application image
Chip            ESP32
Project name    secure_ota
App version     2.1.0
Built with      v5.3.1
Compiled        Aug 21 2025 12:04:33
```

This is **advisory**. A file that does not begin with `0xE9` is flagged in amber,
recorded as a security event, and **still stored** — you asked for any `.bin` to
be accepted. What it is not is quietly passed off as firmware. The authority on
whether an image is bootable is `esp_ota_end()` on the device, which refuses one
that is not.

### What this does not prove

An uploaded `.bin` is **plaintext, unsigned and untrusted**. It becomes
trustworthy only when `tools/create_ota_package.py` signs it in step 2. Nothing
in the upload path reads a key.

The uploads directory is never exposed over HTTP — no route serves a file back
out of it — so an upload cannot become a download. That, and not the `.bin`
extension check, is what makes the endpoint safe to point at: the extension
check exists so you notice you picked the wrong file, not to stop an attacker.

There is **no authentication**. See §7.

---

## 2. Upload → package → publish

The browser sends a firmware image, a version and a security version. Everything
cryptographic happens in a subprocess on the build host.

```
browser ── .bin ──▶ server/firmware/uploads/      sanitised, hashed, inspected
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

`server/staging/` is a genuine staging area. No route reads it, so a package
that has been built but not published is invisible to the ESP32.

### Key handling

* The Ed25519 private key and the Ascon key stay in `keys/` on the build host.
* No API response contains key material; `tests/test_dashboard.py` asserts this.
* The browser never receives, stores or sends a key.

The honest limitation: *package creation* requires the signing key on the
machine running this page. That is the same machine a developer already runs
`tools/create_ota_package.py` on. The OTA *serving* path still holds no keys — if
you want the strict separation, run this on the build host and serve packages
from a machine that only has `server/packages/`.

---

## 3. How the device talks to it

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
are. The page uses one field of it — the status chip in the corner.

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
compromised server can pester a device into checking for updates and reboot it.
It cannot make it install anything, because the Ed25519 private key is not on
the server, and the device verifies the signature against a public key compiled
into its own image.

---

## 4. Online / offline / rebooting

| State | Meaning |
| --- | --- |
| `ONLINE` | a heartbeat arrived within `SOTA_HEARTBEAT_TIMEOUT` seconds (default 15) |
| `REBOOTING` | no heartbeat, but the last reported state was `INSTALL` or `REBOOT` and it has been less than `SOTA_REBOOT_GRACE` seconds (default 120) |
| `OFFLINE` | no heartbeat, and no reason to expect a restart |
| `UNKNOWN` | no device has ever reported in |

Both timeouts are environment variables. In the ESP-IDF PowerShell:

```powershell
$env:SOTA_HEARTBEAT_TIMEOUT = "20"
$env:SOTA_REBOOT_GRACE = "180"
python server/app.py
```

---

## 5. Nothing is invented

If the device has never reported a value, the answer is `null` and the page
shows a dash. If no device has ever reported in, the status chip says so rather
than inventing one. Version numbers on the page come from the signed package
header or from what the device itself reported — never from a guess.

---

## 6. API

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

Used by the page:

```
GET  /api/firmware                           packages, uploads, key status
POST /api/firmware/upload                    multipart .bin  -- see §1
POST /api/firmware/package                   {"file","version","security_version"}
POST /api/firmware/<file>/publish
POST /api/firmware/<file>/unpublish
GET  /api/dashboard/summary                  the status chip
```

Still served, with no UI of their own — they are the device protocol and the
project's test surface, and they cost the page nothing:

```
GET  /api/devices
GET  /api/devices/<device_id>
GET  /api/devices/<device_id>/heartbeat
GET  /api/devices/<device_id>/commands
POST /api/devices/<device_id>/command        {"command": "START_OTA"}
GET  /api/ota/history
GET  /api/security/events
GET  /api/security/lab
POST /api/security/lab/<test>                runs tools/tamper_package.py
GET  /api/logs
GET  /api/logs/stream                        Server-Sent Events
```

The attack lab behind `/api/security/lab` runs the project's existing tooling:
`tools/tamper_package.py` builds a hostile package and `tools/verify_package.py`
refuses it, in a scratch directory that is deleted afterwards. Nine tamper modes
are available; hostile packages are never published and never offered to a
device. The on-device version of that demonstration is in
[`DEMO.md`](DEMO.md).

---

## 7. Storage

SQLite, at `server/ota.db`, created on first run:

| Table | Rows |
| --- | --- |
| `devices` | latest heartbeat per device |
| `firmware_uploads` | one row per accepted `.bin`: name, original name, size, SHA-256, and what the image said about itself |
| `firmware_releases` | packages created through the page |
| `ota_events` | update attempts, checks, downloads, boots |
| `security_events` | rejections, rollback attempts, lab results, flagged uploads |
| `device_commands` | the command queue |

No secrets are stored. Deleting `server/ota.db` resets the history and nothing
else; uploads, packages and keys are untouched. A `.bin` that is on disk but not
in the database — copied in by hand, or predating the table — still appears in
the list, marked "not inspected".

---

## 8. Limitations — read before you demonstrate this

**There is no authentication.** The server binds `0.0.0.0` so the ESP32 can
reach it, which means anyone on the same network can open the page, upload a
`.bin`, create a package and publish it. That is acceptable for a lab
demonstration on a private network and nothing more. Do not expose port 8000
beyond it, and do not port-forward it.

The worst an unauthenticated LAN user can do is real but bounded: reboot the
device, make it check for updates, fill the uploads directory up to 16 MB a
time, and publish a package **that was signed by the key on this machine**. What
they cannot do is make the device install unsigned firmware — that would need
the Ed25519 private key, and the device verifies against a public key compiled
into its own image.

Other honest limits:

* Package creation needs the signing key on the machine running this page
  (see §2). The serving path still holds no keys.
* Upload inspection is advisory. It tells you a file is probably not firmware;
  it does not tell you a file *is* safe firmware. Only the signature does that,
  and only on the device.
* There is no disk quota on the uploads directory beyond the per-file cap.
* The SQLite record is bookkeeping. It has no bearing on what the device
  accepts; anti-rollback state lives in the device's NVS.
* Heartbeat telemetry is unauthenticated, so a device id is a label, not an
  identity. Fine for a demonstration; anything real needs per-device
  authentication.

---

## 9. Testing without hardware

```bash
python tools/simulate_device.py --ota
```

A simulator that speaks the heartbeat/command protocol so the interface can be
checked on a laptop. **It is not a device**: it performs no cryptography,
downloads nothing and installs nothing, and every value it reports is invented.
It uses the device id `esp32-sim-01` so it can never be confused with the real
`esp32-demo-01`. Use it to rehearse the interface — never to demonstrate that
the OTA pipeline works.

---

## 10. Files

```
server/app.py                     OTA endpoints + web interface registration
server/dashboard/__init__.py      blueprint: the page and every API
server/dashboard/uploads.py       upload security: names, sizes, hashing, inspection
server/dashboard/db.py            SQLite schema and queries
server/dashboard/inventory.py     read-only view of packages/ and staging/
server/dashboard/packaging.py     wrapper around tools/create_ota_package.py
server/dashboard/sectest.py       wrapper around the tamper/verify tools
server/dashboard/logbus.py        in-memory log ring buffer + SSE source
server/dashboard/templates/       index.html -- the whole page
server/dashboard/static/          one stylesheet, one script
main/device_report.c              heartbeat, events, command polling
tools/simulate_device.py          simulated device for interface testing
tests/test_dashboard.py           the APIs, upload security, and "the OTA API still works"
```
