#define LED_PIN 2  // Common inbuilt LED pin on ESP32

void setup() {
  pinMode(LED_PIN, OUTPUT);
}

void loop() {
  digitalWrite(LED_PIN, HIGH);  // LED ON
  delay(6000);                  // Wait 1 second

  digitalWrite(LED_PIN, LOW);   // LED OFF
  delay(6000);                  // Wait 1 second
}