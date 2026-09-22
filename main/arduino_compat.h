/*
 * A small Arduino-compatible layer, so sketch code can be pasted into this
 * project almost unchanged.
 *
 * WHY THIS EXISTS
 *
 * An Arduino sketch compiled by the Arduino IDE is a *complete, standalone
 * program*. Installing one over OTA replaces this firmware entirely -- which
 * removes the Wi-Fi manager and the OTA client along with it, and the device
 * can then never be updated again without a USB cable.
 *
 * So instead of building the sketch separately, the sketch's code is brought
 * *into* this firmware. user_setup() and user_loop() in user_code.cpp run as
 * one more FreeRTOS task, next to the OTA state machine rather than in place
 * of it. The board keeps its Wi-Fi, its heartbeat and its ability to receive
 * the next update, and you keep writing setup/loop.
 *
 * WHAT IS PROVIDED
 *
 *   delay, millis, micros
 *   pinMode, digitalWrite, digitalRead, HIGH/LOW/INPUT/OUTPUT/INPUT_PULLUP
 *   Serial.begin/print/println   (line-buffered, printed through the IDF log)
 *   ESP.getChipModel() and the other ESP.* calls a sketch usually makes
 *
 * This is a convenience layer, not an emulation of the Arduino core. There is
 * no String class, no Wire, no analogWrite. If you need one of those, write it
 * against ESP-IDF directly -- it is the same chip and the same C++.
 *
 * NOTHING HERE TOUCHES THE UPDATE PATH. It cannot weaken the signature check,
 * the version check, the decryption or the hash check; it has no access to
 * keys and runs in its own task at low priority.
 */

#ifndef ARDUINO_COMPAT_H_
#define ARDUINO_COMPAT_H_

#ifdef __cplusplus

#include <stdint.h>

/* ----------------------------------------------------------------- pins --- */

#define LOW 0
#define HIGH 1

#define INPUT 0
#define OUTPUT 1
#define INPUT_PULLUP 2
#define INPUT_PULLDOWN 3

void pinMode(int pin, int mode);
void digitalWrite(int pin, int value);
int digitalRead(int pin);

/* ----------------------------------------------------------------- time --- */

/* delay() yields to FreeRTOS, so unlike an Arduino sketch this does not stall
 * the rest of the firmware. The OTA task keeps running throughout. */
void delay(uint32_t ms);
void delayMicroseconds(uint32_t us);
uint32_t millis(void);
uint64_t micros(void);

/* --------------------------------------------------------------- serial --- */

/* Output is line-buffered and emitted through ESP_LOGI with the tag "USER", so
 * sketch output appears in the same console, with the same timestamps, as the
 * rest of the firmware. print() adds to the line; println() ends it. */
class SerialShim {
 public:
  void begin(unsigned long baud = 115200);
  void flush(void);

  void print(const char *text);
  void print(char value);
  void print(int value);
  void print(unsigned int value);
  void print(long value);
  void print(unsigned long value);
  void print(long long value);
  void print(unsigned long long value);
  void print(double value, int decimals = 2);

  void println(void);
  void println(const char *text);
  void println(char value);
  void println(int value);
  void println(unsigned int value);
  void println(long value);
  void println(unsigned long value);
  void println(long long value);
  void println(unsigned long long value);
  void println(double value, int decimals = 2);

  void printf(const char *format, ...) __attribute__((format(printf, 2, 3)));
};

extern SerialShim Serial;

/* ------------------------------------------------------------------ ESP --- */

class EspShim {
 public:
  const char *getChipModel(void);
  uint8_t getChipRevision(void);
  uint8_t getChipCores(void);
  uint32_t getCpuFreqMHz(void);
  uint32_t getFlashChipSize(void);
  const char *getSdkVersion(void);
  uint32_t getFreeHeap(void);
  uint32_t getMinFreeHeap(void);
  uint32_t getHeapSize(void);
  uint32_t getFreePsram(void);
  uint64_t getEfuseMac(void);
  void restart(void);
};

extern EspShim ESP;

#endif /* __cplusplus */

#endif /* ARDUINO_COMPAT_H_ */
