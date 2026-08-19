# OTA Update Server

A small Flask server that publishes `.sota` packages and answers a metadata query
so devices can decide whether to download.

```bash
pip install -r server/requirements.txt
python server/app.py                        # HTTP  on 0.0.0.0:8000
python server/app.py --https --port 8443    # HTTPS (see below)
```

---

## It holds no keys

Not the Ed25519 private key, not the Ascon encryption key, nothing. Packages are
signed and encrypted on the **build host**; this server only stores bytes and
copies them out. It reads a package's *public* header fields to build its index,
which needs no key at all.

That is the main structural reason a compromised server cannot push malicious
firmware. An attacker who owns this machine can:

* delete packages, or serve a stale one;
* lie in the JSON metadata;
* refuse to serve anything at all (denial of service).

What they cannot do is produce a package a device accepts, because that needs a
signature under a key this machine has never held.

`tests/test_server.py::test_server_module_holds_no_key_material` asserts that
`app.py` does not even reference a key-loading function.

---

## Endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /` | HTML status page: packages, versions, digests, transport warning |
| `GET /health` | `{"status":"ok","packages":N,"invalid_packages":M,"scheme":...}` |
| `GET /api/firmware/latest` | metadata for the highest `firmware_version` |
| `GET /api/firmware/list` | every valid package, plus any files it rejected |
| `GET /api/firmware/<version>/package` | the package bytes (`2.0.0`, or a filename) |
| `GET /api/firmware/latest/package` | the newest package |

Optional query parameters, used only for logging: `?device=<id>&current=<version>`.

### The metadata is untrusted

```json
{
  "firmware_version": "2.0.0",
  "firmware_version_code": 131072,
  "security_version": 2,
  "firmware_size": 926208,
  "package_size": 926368,
  "package_url": "/api/firmware/2.0.0/package",
  "firmware_hash": "5a770841e1bfedaf...",
  "built": "2026-08-19 07:31:15 UTC"
}
```

The device uses this **only** to decide whether a download is worth starting.
Every value that affects a security decision is re-read from the signed package
header. A hostile server can lie here freely; the worst it achieves is making the
device fetch a package that is then rejected.

---

## Publishing a package

Drop it in `server/packages/`. The directory is rescanned on every request, so no
restart is needed.

```bash
python tools/create_ota_package.py --firmware build/secure_ota.bin \
    --version 2.0.0 --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota
```

`/api/firmware/latest` always offers the highest `firmware_version`, compared
numerically — so `10.0.0` correctly beats `2.0.0`.

### Corrupt packages are excluded, not served

Every `.sota` is parsed during the scan, and parsed **again** immediately before
being sent — a file can change between the two. Anything that fails is reported in
`/api/firmware/list` under `invalid` and on the status page, and is never handed to
a device:

```
[WARNING] ignoring unusable package cut.sota: package is 5099 bytes,
          header declares 5163 (truncated)
```

---

## HTTPS

```bash
python tools/make_dev_certs.py --ip 192.168.1.42     # your PC's LAN address
python server/app.py --https
```

`make_dev_certs.py` creates a development CA and a server certificate (P-256, with
the address in `subjectAltName`) in `server/certs/`, and copies the CA certificate
to `main/server_ca_cert.pem`, which the firmware embeds at build time. Rebuild and
re-flash after generating certificates.

The device **pins that one CA** rather than trusting a bundle of public roots —
correct for a private server, and about 64 KB smaller. Certificate verification is
never disabled in the firmware; if TLS fails, the update does not happen.

The `--ip` value must match `OTA_SERVER_URL` exactly, because the device checks the
certificate against the address it dialled.

---

## HTTP is for development only

The server prints a warning at start-up and on its status page. To be precise
about what plain HTTP does and does not cost:

* **Still fully enforced:** the Ed25519 signature, the Ascon-AEAD128 tag, the
  Ascon-Hash256 digest, and anti-rollback. A tampered package delivered over a
  hostile link is still rejected — none of the negative tests depend on the
  transport.
* **Lost:** confidentiality of the metadata, concealment of the fact that an
  update is happening, and any protection against an attacker who blocks or
  redirects the request.

Plain HTTP is not secure. Do not describe an HTTP demonstration as a secure
transport.

---

## Not production-ready either

This is Flask's development server: single-process, no rate limiting, no
authentication, no access control on downloads. For anything real, put it behind a
proper WSGI server and reverse proxy. Its security posture is fine — it holds no
secrets — but its availability and robustness are not.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Device logs `Cannot reach the OTA server` | Wrong IP in `OTA_SERVER_URL`, or PC and board on different networks. Test from a phone browser. |
| `no firmware packages available` (404) | `server/packages/` is empty, or every file failed to parse — check the start-up log. |
| Device says `Already up to date` | The package's `firmware_version` is not greater than the running one. |
| TLS handshake fails | The certificate's `subjectAltName` does not include the address the device dialled. Regenerate with the right `--ip` and re-flash. |
| Windows Firewall blocks the connection | Allow inbound Python on the private network, or use `--port` above 1024 and permit it explicitly. |
