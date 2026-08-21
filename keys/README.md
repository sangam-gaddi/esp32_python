# `keys/` — which key belongs where

Generate everything in this directory with:

```bash
python tools/generate_keys.py --write-device-config
```

**Everything in here except this README is git-ignored.** Check before you commit:

```bash
git check-ignore -v keys/ed25519_private.pem keys/ota_enc_key.hex
```

---

## The three keys

| File | Belongs to | Secret? | If it leaks |
| --- | --- | --- | --- |
| `ed25519_private.pem` | the **signing host only** | **yes, critically** | an attacker can sign firmware every device will accept — total compromise |
| `ed25519_public.pem` | embedded in the **firmware** | no, publish freely | nothing. It is the trust anchor; it is *meant* to be in the image |
| `ota_enc_key.hex` | the **packaging tool and the device** | **yes** | an attacker can decrypt firmware packages, but **cannot forge them** |

### `ed25519_private.pem` — the authority

This key *is* the permission to update the fleet. It must never appear in:

* the firmware image, `main/`, or any `components/` directory
* the OTA server (which needs no keys at all)
* a git commit
* a shared drive or a chat message

`tools/create_ota_package.py` is the only thing that reads it, and only on the
build machine.

Losing it means you can never issue another update that existing devices accept.
Leaking it means someone else can. Both are unrecoverable without re-flashing every
device over USB, which is why real deployments keep it in an HSM or on an
air-gapped signer.

### `ed25519_public.pem` — the trust anchor

Compiled into the firmware by `tools/generate_keys.py --write-device-config`, which
writes it into `main/crypto_config.h` as a 32-byte array.

Hard-coding it is the entire point. The device must accept **only** this key, and
must never use a public key that arrives with a package — that would reduce the
signature to a checksum any attacker can recompute. The `.sota` format has no field
for a public key, by design.

### `ota_enc_key.hex` — the shared secret

128 bits of hex. The packager encrypts with it (Ascon-AEAD128); the device decrypts
with it.

It is **never transmitted**. It is not in the package — only the nonce is, and a
nonce is not secret. `tests/test_package.py::test_encryption_key_does_not_appear_in_the_package`
asserts this.

Because the Ed25519 signature covers the AEAD tag, an attacker holding this key can
read firmware but cannot produce a package that verifies. See `docs/SECURITY.md` §3.

---

## How the device gets its keys

`main/crypto_config.h` (generated, git-ignored) carries both device-side values:

```c
static const uint8_t OTA_TRUSTED_ED25519_PUBLIC_KEY[32] = { ... };  /* public  */
static const uint8_t OTA_DEFAULT_ENCRYPTION_KEY[16]     = { ... };  /* SECRET  */
```

On first boot `main/device_keys.c` finds NVS empty and provisions the Ascon key
there from the compiled-in value, logging a warning. Afterwards the NVS copy is
authoritative.

The boot log prints an Ascon-Hash256 **fingerprint** of each key, never the key
itself, so host and device can be compared without disclosing anything:

```
I CRYPTO: Ascon-AEAD128 OTA key: present, fingerprint 1e66187f5ecb349b (from NVS)
```

---

## This is not production key management

Compiling a shared secret into a firmware image is a **demonstration shortcut**, so
that one `idf.py flash` produces a working device. It has a real cost, stated
plainly in `docs/SECURITY.md` §5.1:

> Anyone who can read the flash — a chip reader, or `esptool.py read_flash` over
> USB — recovers the Ascon key. Every device shares one key, so that ends
> confidentiality for the whole fleet. Authenticity survives, because forging still
> needs the Ed25519 private key.

A real product would instead:

1. generate a **unique key per device**, so one extraction compromises one unit;
2. provision it at manufacture into **eFuse** or NVS-encrypted storage, never into
   a distributed image;
3. enable **flash encryption**, so a flash read-out yields ciphertext;
4. keep the signing key in an **HSM**, with rotation and revocation planned;
5. enable **Secure Boot**, so an attacker with flash write access cannot bypass the
   OTA path entirely.

The NVS-backed design in `device_keys.c` is already the right shape for (1) and
(2) — it reads from NVS and only falls back to the compiled-in key on a virgin
device. It is the fallback that makes this build extractable.

---

## Rotating keys

Regenerating the **signing** key invalidates every package that existing devices
trust — they hold the old public key and will reject anything signed with the new
one. Devices must be re-flashed over USB.

```bash
python tools/generate_keys.py --force --write-device-config
idf.py build flash            # every device needs the new trust anchor
```

`generate_keys.py` refuses to overwrite without `--force`, and says why.

Rotating only the **encryption** key is less disruptive but still requires a
re-flash, since the new key must reach the device somehow. Repackage all firmware
afterwards; packages built with the old key will fail the tag check with
`ASCON AUTHENTICATION FAILED` — which, if you see it unexpectedly after
regenerating keys, is the usual explanation. `idf.py erase-flash` clears the stale
NVS copy.
