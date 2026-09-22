/* =========================================================================
 *
 *   PUT YOUR CODE HERE.  This is the only file you need to edit.
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
#include "user_code.h"

/* ------------------------------------------------------------------------- */

void user_setup(void) {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("================================");
  Serial.println("       ESP32 SYSTEM MONITOR");
  Serial.println("================================");

  Serial.print("Chip Model: ");
  Serial.println(ESP.getChipModel());

  Serial.print("Chip Revision: ");
  Serial.println(ESP.getChipRevision());

  Serial.print("CPU Frequency: ");
  Serial.print(ESP.getCpuFreqMHz());
  Serial.println(" MHz");

  Serial.print("Flash Size: ");
  Serial.print(ESP.getFlashChipSize() / (1024 * 1024));
  Serial.println(" MB");

  Serial.print("SDK Version: ");
  Serial.println(ESP.getSdkVersion());

  Serial.println("================================");
}

/* ------------------------------------------------------------------------- */

void user_loop(void) {
  Serial.print("Uptime: ");
  Serial.print(millis() / 1000);
  Serial.println(" seconds");

  Serial.print("Free Heap: ");
  Serial.print(ESP.getFreeHeap());
  Serial.println(" bytes");

  Serial.print("Free PSRAM: ");
  Serial.print(ESP.getFreePsram());
  Serial.println(" bytes");

  Serial.println("--------------------------------");

  delay(2000);
}
