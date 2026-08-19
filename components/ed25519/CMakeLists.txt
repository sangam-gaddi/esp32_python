# Ed25519 signature verification, backed by TweetNaCl.
#
# tweetnacl.h is kept in src/ (PRIV_INCLUDE_DIRS) rather than include/ on
# purpose: it defines `crypto_hash` as a macro for SHA-512, which would collide
# with the Ascon component's crypto_hash(). Dependents see only
# ed25519_verify.h.
#
# esp_hw_support supplies esp_fill_random() for the randombytes() symbol
# TweetNaCl requires at link time (verification never calls it).
idf_component_register(
    SRCS "src/tweetnacl.c"
         "src/ed25519_verify.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES esp_hw_support
)
