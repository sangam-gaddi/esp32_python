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
         "arduino_compat.cpp"
         "user_code.cpp"
         "ota_manager.c"
         "wifi_manager.c"
         "device_keys.c"
         "device_report.c"
         "version_manager.c"
         "crypto_bench.c"
    INCLUDE_DIRS "."
    REQUIRES ascon ed25519 ota_package
             nvs_flash esp_wifi esp_netif esp_event
             esp_http_client app_update json esp_timer
             esp_hw_support spi_flash driver
    EMBED_TXTFILES "server_ca_cert.pem"
)

# The user's Arduino sketch. The website puts it in main/user_sketch/sketch.ino
# (uploading an Arduino .bin fetches the .ino it was built from; uploading a
# .ino uses it directly). When that file exists its setup()/loop() are what
# runs on the board -- see user_code.cpp. Editing it triggers a rebuild
# through the normal header dependency tracking. USER_SKETCH overrides it.
set(USER_SKETCH "$ENV{USER_SKETCH}")
if(NOT USER_SKETCH)
    set(USER_SKETCH "${CMAKE_CURRENT_LIST_DIR}/user_sketch/sketch.ino")
endif()
target_include_directories(${COMPONENT_LIB} PRIVATE "arduino_include")
if(EXISTS "${USER_SKETCH}")
    message(STATUS "User sketch: ${USER_SKETCH}")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        USER_SKETCH_PATH="${USER_SKETCH}")
else()
    message(STATUS "User sketch: none found, using main/user_code.cpp")
endif()
