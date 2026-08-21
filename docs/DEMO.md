# Demonstration Script

A complete run-through: one successful OTA update, then five attacks the device
rejects.

**Important:** no ESP32 was available while this project was built, so the
hardware steps below have **never been executed**. They follow the standard
ESP-IDF flow and the firmware compiles cleanly, but treat them as instructions to
follow, not as a transcript of something observed. The host-side sections *have*
been run and their output is real.

Total time: about 25 minutes for the full script, or 5 minutes for
[the host-only version](#part-0-host-only-demonstration-no-hardware) if you have
no board.

**Presenting to someone?** Run the same script with
<http://localhost:8000/dashboard> on screen. The Secure OTA Control Center shows
the device, the versions, the verification pipeline and the live progress of each
step described below, and its Security Test Lab runs the attack tools in §5 at the
click of a button. It changes nothing about how the update works — see
[`DASHBOARD.md`](DASHBOARD.md).

---

## What you need

| | |
| --- | --- |
| Hardware | ESP32 dev board (ESP32-WROOM-32 / DevKitC), **4 MB flash**, USB cable |
| Toolchain | ESP-IDF **5.3.1** |
| Host | Python 3.9+ |
| Network | Wi-Fi the board can join, and a PC on the same network |

Nothing works if the PC and the board are on different networks — a phone hotspot
with both joined is the reliable fallback.

---

## Part 0 — Host-only demonstration (no hardware)

Everything cryptographic can be shown without a board. This part is real, tested
output.

```bash
pip install -r server/requirements.txt

# 1. the cryptography, against official NIST vectors
python -m pytest tests/test_ascon_kat.py -v

# 2. the C code the firmware uses, compiled and run on this machine
python tests/host/make_fixtures.py
python tests/host/build_and_run.py

# 3. every attack scenario
python -m pytest tests/test_negative.py -v
```

Expected: 1025 Ascon-Hash256 and 1089 Ascon-AEAD128 official vectors pass in both
Python and C, 26 cross-validation fixtures behave exactly as specified, and all
seven attack scenarios are rejected.

Then the pipeline by hand, which is the part worth showing on a projector:

```bash
python tools/generate_keys.py --write-device-config
python tools/create_ota_package.py --firmware build/secure_ota.bin \
    --version 2.0.0 --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota
python tools/verify_package.py server/packages/firmware_v2.0.0.sota
```

```
  [1] structure                    PASS  format v1, header 160 B, payload 178016 B
  [2] Ed25519 signature            PASS  signed header[0:96] is authentic
  [3] Ascon-AEAD128 tag            PASS  decrypted 178016 bytes
  [4] Ascon-Hash256                PASS  matches the signed digest

RESULT: ACCEPTED -- this package would install on the device
```

Now break it, one attack at a time — see [Part 3](#part-3-the-attacks).

---

## Part 1 — Setup

### Step 1. Install dependencies and generate keys

```bash
pip install -r server/requirements.txt
python tools/generate_keys.py --write-device-config
```

This creates three keys with three different homes:

```
keys/ed25519_private.pem   signing host only -- never leaves this machine
keys/ed25519_public.pem    embedded in the firmware (the trust anchor)
keys/ota_enc_key.hex       shared by the packager and the device
main/crypto_config.h       generated: public key + provisioning key
```

Note the printed **raw public key** — that value is now the device's root of
trust. `keys/` and `main/crypto_config.h` are git-ignored.

### Step 2. Configure the device

Find your PC's LAN address (`ipconfig` on Windows, `ip addr` on Linux), then:

```bash
cp main/device_config.h.example main/device_config.h
```

Edit three lines:

```c
#define WIFI_SSID       "your-network"
#define WIFI_PASSWORD   "your-password"
#define OTA_SERVER_URL  "http://192.168.1.42:8000"   /* your PC's LAN IP */
```

`localhost` will not work — on the ESP32 that means the ESP32.

> Plain HTTP is fine for the demonstration and is clearly labelled as
> development-only. Every cryptographic check still applies, so the attack
> demonstrations in Part 3 work identically. For HTTPS, see
> [Part 4](#part-4-optional-https).

---

## Part 2 — The successful update

### Step 3. Build and flash firmware V1

`main/app_config.h` ships as version 1.0.0, security version 1. Leave it.

```bash
idf.py set-target esp32     # first time only
idf.py build flash monitor
```

Expected serial output:

```
I (312) BOOT: ==========================================================
I (312) BOOT:  Secure OTA Firmware Update with Lightweight Cryptography
I (322) BOOT: ==========================================================
I (322) BOOT: Current Firmware Version: 1.0.0
I (332) BOOT: Security Version        : 1
I (342) BOOT: Running partition       : factory @ 0x00020000
I (352) BOOT: Crypto                  : Ascon-Hash256 + Ascon-AEAD128 (NIST SP 800-232), Ed25519
I (362) BOOT: NVS ready
W (372) CRYPTO: No OTA key in NVS -- provisioning the compiled-in DEMONSTRATION key
I (382) CRYPTO: Trusted Ed25519 public key: 20aa..1b53 (fingerprint ...)
I (392) CRYPTO: Ascon-AEAD128 OTA key: present, fingerprint ... (provisioned this boot)
I (402) VERSION: Running firmware version : 1.0.0 (0x010000)
I (412) WIFI: Connecting to SSID "your-network" ...
I (2412) WIFI: Connected. IP address 192.168.1.77
I (2422) OTA: OTA task started; waiting for Wi-Fi
```

**Point out:** `Current Firmware Version: 1.0.0`, and that the key fingerprint is
printed rather than the key.

Leave the monitor running. `Ctrl+]` exits when you need it.

### Step 4. Save V1 and build V2

In a second terminal:

```bash
cp build/secure_ota.bin build/firmware_v1.bin      # keep V1 for the rollback attack
```

Now edit `main/app_config.h`:

```c
#define FIRMWARE_VERSION_MAJOR 2      /* was 1 */
#define FIRMWARE_VERSION_MINOR 0
#define FIRMWARE_VERSION_PATCH 0
#define SECURITY_VERSION       2      /* was 1 */
```

```bash
idf.py build
```

Do **not** flash it. The whole point is that it arrives over the air.

### Step 5. Package V2

```bash
python tools/create_ota_package.py \
    --firmware build/secure_ota.bin \
    --version 2.0.0 --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota
```

```
OTA package created

  firmware version  : 2.0.0 (0x020000)
  security version  : 2
  firmware size     : 926720 bytes
  Ascon-Hash256     : 5a770841e1bfedafcc0e33994994de25...
  Ascon nonce       : 42d73d1bac061b56c1b178f1ab40d620
  Ascon tag         : 9a90a2570eb15154e140823e8a9c8d3b
  Ed25519 signature : 870668ebf005888a7b050bea53ec32fa...
  package           : server/packages/firmware_v2.0.0.sota

  self-verification : PASS
```

**Point out:** a fresh random nonce, and that the key appears nowhere.

### Step 6. Start the server

```bash
python server/app.py
```

```
[INFO] Secure OTA update server
[INFO] packages available : 1 valid, 0 rejected
[INFO]    firmware_v2.0.0.sota   firmware 2.0.0   security 2
[INFO] listening on       : http://0.0.0.0:8000
[WARNING] transport        : plain HTTP -- DEVELOPMENT ONLY, not secure
[INFO] this server holds NO keys
```

**Point out:** *this server holds no keys.* Owning it does not let you push
firmware.

Open `http://localhost:8000` in a browser for a status page.

### Steps 7–13. Watch the update happen

Within 60 seconds the device checks in. Expected serial output:

```
I (10412) OTA: state -> CHECK
I (10422) OTA: Checking for update: http://192.168.1.42:8000/api/firmware/latest?device=esp32-demo-01
I (10632) OTA: Server offers firmware 2.0.0 (security 2); device has 1.0.0 (security 1)
I (10642) OTA: Update available: version 2.0.0
I (10652) OTA: state -> METADATA
I (10662) OTA: Downloading package: http://192.168.1.42:8000/api/firmware/2.0.0/package
I (10892) OTA: Package header parsed:
I (10902) OTA:   firmware version  2.0.0
I (10912) OTA:   security version  2
I (10922) OTA:   firmware size     926720 bytes
I (10932) OTA:   Ascon-Hash256     5a770841...f36e45ec
I (10942) OTA: state -> SIGNATURE_VERIFY
I (10952) OTA: Verifying Ed25519 signature over the 96-byte signed header...
I (11102) OTA: Signature verification successful (nnnnn us)
I (11112) OTA: state -> VERSION_VERIFY
I (11122) OTA: Checking firmware version and anti-rollback...
I (11132) OTA: Version accepted
I (11142) OTA: Running from 'factory' at 0x00020000; writing to 'ota_0' at 0x00160000
I (11152) OTA: state -> DOWNLOAD
I (11162) OTA: Streaming 926720 bytes; decrypting and hashing in 4096-byte chunks
I (11172) OTA: state -> DECRYPT
I (12182) OTA:   32768 / 926720 bytes (3%), heap 178xxx
...
I (4xxxx) OTA: Package downloaded (926720 bytes in nnnnn ms)
I (4xxxx) OTA: state -> HASH_VERIFY
I (4xxxx) OTA: Finalising Ascon-AEAD128 and comparing Ascon-Hash256...
I (4xxxx) OTA: Ascon authentication successful (tag verified)
I (4xxxx) OTA: Hash verification successful
I (4xxxx) OTA: state -> INSTALL
I (4xxxx) OTA: Writing OTA partition...
I (4xxxx) OTA: OTA update successful
I (4xxxx) OTA:   installed version 2.0.0 (security 2) into 'ota_0'
I (4xxxx) OTA: state -> REBOOT
I (4xxxx) OTA: Rebooting in 3000 ms...
```

Then, after the reboot:

```
I (312) BOOT: Current Firmware Version: 2.0.0
I (322) BOOT: Security Version        : 2
I (342) BOOT: Running partition       : ota_0 @ 0x00160000
I (352) BOOT: This image is on probation (PENDING_VERIFY) after an update
I (2422) BOOT: Self-test passed -- image marked valid, rollback cancelled
I (2432) VERSION: Version state persisted: firmware 0x020000, security 2
```

**Three things to point out:**

1. The version changed 1.0.0 → 2.0.0 without touching the USB cable.
2. The running partition changed `factory` → `ota_0`. V1 is still intact in
   `factory`.
3. The image booted on probation and only marked itself valid *after* Wi-Fi came
   up. Had it been broken, the bootloader would have reverted.

---

## Part 3 — The attacks

Now show that the device rejects bad updates. Each one is a one-line command.

Set up a working directory:

```bash
mkdir -p build/attacks
GOOD=server/packages/firmware_v2.0.0.sota
```

For the on-device demonstrations, move the good package out of the way and put the
attack package in `server/packages/` under a higher version number so the device
tries it.

### Attack 1 — Tampered firmware (Ascon tag)

```bash
python tools/tamper_package.py --mode flip-ciphertext \
    --input $GOOD --output build/attacks/tampered.sota
python tools/verify_package.py build/attacks/tampered.sota
```

```
  [2] Ed25519 signature            PASS  signed header[0:96] is authentic
  [3] Ascon-AEAD128 tag            FAIL  wrong encryption key, or the ciphertext was modified

RESULT: REJECTED (ASCON AUTHENTICATION FAILED)
```

Device log:

```
E OTA: ASCON AUTHENTICATION FAILED (tag mismatch)
E OTA: UPDATE REJECTED at DECRYPT -- running firmware is unchanged
I OTA: Device continues running firmware 2.0.0
```

**One flipped bit out of 7.4 million.** The signature still passes — only the
header was left alone — which shows the two layers catching different things.

### Attack 2 — Invalid signature

```bash
python tools/tamper_package.py --mode bad-signature \
    --input $GOOD --output build/attacks/badsig.sota
python tools/verify_package.py build/attacks/badsig.sota
```

```
  [2] Ed25519 signature            FAIL  not signed by the trusted key, or the header was altered

RESULT: REJECTED (INVALID SIGNATURE)
```

Note it is rejected **before** decryption is attempted — stage 3 never runs.

### Attack 3 — Unauthorised signer

The more realistic version: an attacker builds their own firmware and signs it
with their own key.

```bash
python tools/tamper_package.py --mode foreign-signer \
    --input $GOOD --output build/attacks/attacker.sota
python tools/verify_package.py build/attacks/attacker.sota
```

```
RESULT: REJECTED (INVALID SIGNATURE)
```

The package is internally perfectly consistent. It is refused because the device
trusts one specific public key, compiled into the image, and never accepts one
that arrives with the package.

### Attack 4 — Wrong encryption key

```bash
python tools/tamper_package.py --mode wrong-key \
    --input $GOOD --output build/attacks/wrongkey.sota
python tools/verify_package.py build/attacks/wrongkey.sota
```

```
  [2] Ed25519 signature            PASS
  [3] Ascon-AEAD128 tag            FAIL

RESULT: REJECTED (ASCON AUTHENTICATION FAILED)
```

Correctly signed by the real key, but encrypted for a different fleet. The
signature passes; the tag does not.

### Attack 5 — Rollback

The most interesting one, because nothing is corrupt. This is a genuinely signed,
genuinely encrypted package — just an older one.

```bash
python tools/tamper_package.py --mode rollback \
    --input $GOOD --output build/attacks/rollback.sota \
    --security-version 1 --version 1.0.0
python tools/verify_package.py build/attacks/rollback.sota \
    --current-version 2.0.0 --current-security-version 2
```

```
  [2] Ed25519 signature            PASS
  [3] Ascon-AEAD128 tag            PASS
  [4] Ascon-Hash256                PASS
  [5] version / anti-rollback      FAIL  security 1 < 2: ROLLBACK

RESULT: REJECTED (version check failed)
```

Device log:

```
E OTA: Package security version 1 is below the accepted floor 2
E OTA: ROLLBACK DETECTED
E OTA: UPDATE REJECTED at VERSION_VERIFY -- running firmware is unchanged
```

**Every cryptographic check passes.** It is refused purely on policy, because the
version fields are inside the signed region and the device remembers what it has
already accepted. This is why a filename like `firmware_v2.bin` proves nothing.

### Bonus — Corrupted package, and hash mismatch in isolation

```bash
python tools/tamper_package.py --mode truncate --input $GOOD \
    --output build/attacks/cut.sota
python tools/verify_package.py build/attacks/cut.sota
#   [1] structure  FAIL  package is ... bytes, header declares ... (truncated)

python tools/tamper_package.py --mode hash-mismatch --input $GOOD \
    --output build/attacks/hashbad.sota
python tools/verify_package.py build/attacks/hashbad.sota
#   [4] Ascon-Hash256  FAIL   -> REJECTED (HASH MISMATCH)
```

The second is worth explaining: it is correctly encrypted *and* correctly signed,
but the signed digest does not describe the firmware — i.e. a broken or malicious
build server. It is the only case where the hash comparison is the *first* thing
to fail, which is what shows that check is genuinely enforced rather than implied
by the tag.

### All nine at once

```bash
for m in flip-ciphertext flip-metadata bad-signature foreign-signer \
         wrong-key hash-mismatch rollback truncate bad-magic; do
  python tools/tamper_package.py --mode $m --input $GOOD \
      --output build/attacks/$m.sota >/dev/null
  echo -n "$m -> "
  python tools/verify_package.py build/attacks/$m.sota \
      --current-version 1.0.0 --current-security-version 2 | grep RESULT
done
```

Every line reads `REJECTED`.

---

## Part 4 — Optional: HTTPS

```bash
python tools/make_dev_certs.py --ip 192.168.1.42     # your PC's LAN IP
```

This writes `server/certs/` and overwrites `main/server_ca_cert.pem`, which the
firmware embeds. Then in `main/device_config.h`:

```c
#define OTA_SERVER_URL "https://192.168.1.42:8443"
```

```bash
idf.py build flash monitor
python server/app.py --https
```

The device pins that one CA certificate. Certificate verification is never
disabled — if TLS fails, the update simply does not happen.

The IP in `--ip` must match the URL, because it goes into the certificate's
`subjectAltName` and the device checks it.

---

## Part 5 — Interrupted update

Worth showing because it demonstrates the safety property rather than a rejection.

Start an update, then kill the server (`Ctrl+C`) mid-download.

```
E OTA: Connection closed after 401408 of 926720 bytes
E OTA: UPDATE REJECTED at DOWNLOAD -- running firmware is unchanged
I OTA: Device continues running firmware 2.0.0
```

The device keeps running. The inactive partition holds a half-written image that
will never execute, because `esp_ota_set_boot_partition()` was never reached.
Restart the server and the next check installs cleanly.

---

## Talking points

If you have two minutes to explain the design:

**Why three layers rather than one?**
The AEAD tag proves the ciphertext came from someone with the *shared* key. The
signature proves the plaintext is what the *signer* approved. The shared key is on
every device, so it can be extracted; the private key never leaves the build host.
Because the signature covers the tag, stealing the shared key costs
confidentiality but not authenticity.

**Why is the hash of the plaintext, not the ciphertext?**
So the signature attests to what will actually execute, independently of
transport encryption.

**Why check the signature before downloading?**
The header arrives first and is self-contained. An unauthorised package costs 160
bytes instead of a megabyte, and never touches flash.

**Why two version numbers?**
`firmware_version` answers "is there something newer?"; `security_version`
answers "is this allowed at all?". Separating them means routine releases do not
need to raise the anti-rollback floor.

**What are you honest about?**
The shared Ascon key is extractable from flash in this build — that is a
demonstration shortcut, and it costs confidentiality, not authenticity. And none
of the device-side behaviour has been run on real hardware. See
`docs/SECURITY.md` §5 and §9.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `Cannot reach the OTA server` | Wrong IP, or PC and board on different networks. Check with a browser on your phone. |
| `Trusted public key is all zeroes` | `crypto_config.h` was never generated. Run `python tools/generate_keys.py --write-device-config`. |
| `ASCON AUTHENTICATION FAILED` on a package you just built | Keys were regenerated after flashing. Re-flash, or erase NVS with `idf.py erase-flash`. |
| `Already up to date` | The package's `firmware_version` is not greater than the running one. Bump `app_config.h` and repackage. |
| `ROLLBACK DETECTED` unexpectedly | The device's NVS floor is above the package's `security_version`. `idf.py erase-flash` resets it. |
| Device reboots into the old version | The new image never marked itself valid — usually Wi-Fi failed. That is the rollback protection working. |
| `Smallest app partition is ... bytes` build error | Flash size is not set to 4 MB, or `partitions.csv` is not selected. Delete `sdkconfig` and rebuild. |
