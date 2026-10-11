/* =========================================================================
 *
 *   YOUR CODE.
 *
 *   The website puts your Arduino sketch in main/user_sketch/sketch.ino and
 *   THAT is what runs: upload your Arduino .bin (or the .ino) on the website
 *   and it is built, signed and published for you. The fallback code below
 *   runs only when there is no sketch file.
 *
 *   Paste your Arduino sketch into the two functions below:
 *
 *       setup()  ->  user_setup()     runs once
 *       loop()   ->  user_loop()      runs again and again
 *
 *   Then open the website, press "Build firmware", "Create secure package"
 *   and "Publish". Your code reaches the board over the air.
 *
 *   DO NOT build this in the Arduino IDE and upload the .bin. An Arduino
 *   build replaces the whole firmware, including the part that receives
 *   updates, and the board then needs a USB cable to recover. Writing here
 *   keeps your code AND the OTA client running together.
 *
 *   WHAT YOU CAN USE
 *       Serial.begin / Serial.print / Serial.println / Serial.printf
 *       pinMode, digitalWrite, digitalRead, HIGH, LOW, INPUT, OUTPUT
 *       delay, delayMicroseconds, millis, micros
 *       ESP.getChipModel(), ESP.getFreeHeap(), ESP.getCpuFreqMHz(), ...
 *
 *   ONE DIFFERENCE FROM ARDUINO
 *       delay() here does not freeze the board. The Wi-Fi, the OTA client
 *       and the heartbeat keep running while your code waits. So a long
 *       delay in user_loop() is safe -- an update can still arrive during it.
 *
 * ========================================================================= */

#include "arduino_compat.h"
#include "esp_log.h"
#include "user_code.h"

#ifdef USER_SKETCH_PATH
/* ---------------------------------------------------------------------------
 * Your Arduino sketch, compiled straight from the file named in
 * main/CMakeLists.txt (USER_SKETCH). Edit it in the Arduino IDE, then press
 * "Build firmware" on the website -- no copying into this file.
 * ------------------------------------------------------------------------- */
#define setup user_sketch_setup
#define loop user_sketch_loop
#include USER_SKETCH_PATH
#undef setup
#undef loop

void user_setup(void) {
  ESP_LOGI("USER", "Running sketch %s", USER_SKETCH_PATH);
  user_sketch_setup();
}

void user_loop(void) { user_sketch_loop(); }

#else
/* No sketch file found: the code below runs instead. */

#define LED_PIN 2  // Common inbuilt LED pin on ESP32

void user_setup(void) {
  pinMode(LED_PIN, OUTPUT);
}

void user_loop(void) {
  digitalWrite(LED_PIN, HIGH);  // LED ON
  delay(1000);                  // Wait 1 second

  digitalWrite(LED_PIN, LOW);   // LED OFF
  delay(1000);                  // Wait 1 second
}
#endif
