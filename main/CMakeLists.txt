# Application sources.
#
# main.c is the entry point only; the OTA logic, key handling and version state
# live in their own translation units, and the cryptography lives in components/.
#
# server_ca_cert.pem is embedded so the device can pin the development CA when
# OTA_SERVER_URL is https://. Regenerate it with tools/make_dev_certs.py. The
# tracked copy is a placeholder, so the build always succeeds; TLS will simply
# fail at run time until you generate a real one.
idf_component_register(
    SRCS "main.c"
         "ota_manager.c"
         "wifi_manager.c"
         "device_keys.c"
         "device_report.c"
         "version_manager.c"
    INCLUDE_DIRS "."
    REQUIRES ascon ed25519 ota_package
             nvs_flash esp_wifi esp_netif esp_event
             esp_http_client app_update json esp_timer
             esp_hw_support spi_flash
    EMBED_TXTFILES "server_ca_cert.pem"
)
