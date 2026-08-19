# `server/packages/`

Built `.sota` packages go here. The server rescans this directory on every
request, so adding a package needs no restart.

```bash
python tools/create_ota_package.py --firmware build/secure_ota.bin \
    --version 2.0.0 --security-version 2 \
    --output server/packages/firmware_v2.0.0.sota
```

`*.sota` files are git-ignored: they are build artefacts, and they are large.
Anything in here that fails to parse is reported and never served.
