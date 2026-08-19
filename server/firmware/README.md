# `server/firmware/`

A convenient place to keep the plaintext `.bin` images you packaged, so you can
tell later which firmware a given package contains — e.g. `firmware_v1.bin` and
`firmware_v2.bin` from the demonstration.

The server never reads this directory. Only `server/packages/` is published, and
only encrypted packages live there.

`*.bin` files here are git-ignored.
