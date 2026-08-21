# .sota OTA package parsing and cryptographic verification.
#
# No ESP-IDF dependencies on purpose: the same sources compile and run on the
# development host against packages built by the Python packager
# (tests/host/test_package_parser.c), so the parser the device trusts is the
# parser that gets tested.
idf_component_register(
    SRCS "src/ota_package.c"
    INCLUDE_DIRS "include"
    REQUIRES ascon ed25519
)
