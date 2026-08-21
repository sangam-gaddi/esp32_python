# Ascon lightweight cryptography (NIST SP 800-232).
#
#   permutations.c    Ascon-p, the shared permutation (audited, KAT-proven)
#   hash.c            original one-shot Ascon-Hash256 (crypto_hash)
#   ascon_hash256.c   incremental Ascon-Hash256, used by the streaming OTA path
#   ascon_aead128.c   Ascon-AEAD128 authenticated encryption
#   printstate.c      debug dumps; compiles to nothing unless ASCON_PRINT_STATE
#                     is defined, which printstate.h refuses to allow on-device
#
# No ESP-IDF dependencies, so the same sources compile and run on the host --
# see tests/host/build_and_run.py.
idf_component_register(
    SRCS "src/hash.c"
         "src/permutations.c"
         "src/ascon_hash256.c"
         "src/ascon_aead128.c"
         "src/printstate.c"
    INCLUDE_DIRS "include"
)
