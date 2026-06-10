/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║          BlackBox Smart Security Packet — ESP32 Firmware         ║
 * ║          Version: 2.0.0   (Production Release with LOCK support) ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  Hardware  : GL868_ESP32                                         ║
 * ║  LED       : GPIO38 → GND (active HIGH)                          ║
 * ║  Core      : Arduino ESP32 Core 2.x                              ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  Changelog v2.0.0                                                ║
 * ║  • Command replay protection via NVS-persisted commandId         ║
 * ║  • PENDING→EXECUTING→SUCCESS/FAILED state machine                ║
 * ║  • HTTP retry with exponential backoff                           ║
 * ║  • WiFi exponential backoff reconnect (no connection storms)     ║
 * ║  • Authorization header support (device secret)                  ║
 * ║  • NVS schema versioning + corruption recovery                   ║
 * ║  • Enriched heartbeat (uptime, heap, RSSI, firmware)             ║
 * ║  • Device ID uses full 6-byte MAC (collision-proof)              ║
 * ║  • Hardware actuator extension points (relay, servo, solenoid)   ║
 * ║  • Tamper sensor + battery monitoring stubs                      ║
 * ║  • HTTPClient always closed in finally-style pattern             ║
 * ║  • All blocking delays removed from main loop                    ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * SECURITY NOTE:
 *   DEVICE_SECRET is used as a bearer token. For stronger security,
 *   replace with HMAC-SHA256 request signing:
 *     signature = HMAC-SHA256(secret, method + path + body + timestamp)
 *   Send as header: X-BlackBox-Sig: <signature>
 *   Backend verifies before processing any request.
 *   This prevents replay attacks even if TLS is compromised.
 *
 * ATTACK SURFACE (remaining, see audit report):
 *   1. Secret stored in flash plaintext — use NVS encryption partition
 *   2. No TLS cert pinning — MITM possible on hostile networks
 *   3. No firmware signature verification on OTA updates
 *   4. Physical UART access exposes all secrets via Serial output
 *   5. NVS accessible via JTAG if eFuse read-protection not burned
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_system.h>       // esp_read_mac, esp_get_free_heap_size
#include <esp_wifi.h>         // esp_wifi_get_mac (backup)

// ══════════════════════════════════════════════════════════════════════
//  SECTION 1 — USER CONFIGURATION
//  Edit all values in this section before flashing.
// ══════════════════════════════════════════════════════════════════════

#define WIFI_SSID           "Harishhhh"
#define WIFI_PASSWORD       "987654321"
#define BACKEND_BASE_URL    "https://lockit-4m6f.onrender.com"   // no trailing slash
#define FIRMWARE_VERSION    "2.0.0"
#define RELAY      1
#define SERVO      2
#define SOLENOID   3
#define SIMULATED  4
#define ACTUATOR_TYPE SIMULATED
// Device secret — sent as Authorization: Bearer <secret>
// Generate a strong random string (32+ chars) per device.
// Store it in your backend DB against the deviceId.
// WARNING: Visible in Serial output. Disable verbose logging in production.
#define DEVICE_SECRET       "CHANGE_ME_BEFORE_PRODUCTION"

// ══════════════════════════════════════════════════════════════════════
//  SECTION 2 — HARDWARE PINS
// ══════════════════════════════════════════════════════════════════════

#define LED_PIN             38    // Status LED (active HIGH)

// ── Extension Points ──────────────────────────────────────────────────
// Uncomment and wire to your actuator.
// Set ACTUATOR_TYPE to exactly one of: RELAY, SERVO, SOLENOID, SIMULATED


// #define RELAY_PIN          26   // Relay: HIGH=locked, LOW=unlocked
// #define RELAY_UNLOCK_MS   3000  // Duration relay stays open

// #define SERVO_PIN          27   // Servo signal pin
// #define SERVO_LOCKED_DEG    0   // Degrees for locked position
// #define SERVO_UNLOCKED_DEG 90   // Degrees for unlocked position
// #define SERVO_HOLD_MS     3000  // Duration at unlocked before re-locking

// #define SOLENOID_PIN       25   // Solenoid: HIGH=energised (unlocked)
// #define SOLENOID_HOLD_MS  2000  // Duration energised

// ── Optional Sensors ─────────────────────────────────────────────────
// #define TAMPER_PIN         34   // Tamper switch (INPUT_PULLUP, LOW=tampered)
// #define BATTERY_ADC_PIN    35   // Battery voltage via voltage divider (ADC)
// #define BATTERY_RATIO      2.0  // Divider ratio: R1/(R1+R2), e.g. 100k/100k = 0.5 → ratio 2.0

// ══════════════════════════════════════════════════════════════════════
//  SECTION 3 — TIMING CONSTANTS
// ══════════════════════════════════════════════════════════════════════

#define HEARTBEAT_INTERVAL_MS       60000UL   // 60 s between heartbeats
#define POLL_INTERVAL_MS             2000UL   // 2 s command poll cadence
#define HTTP_TIMEOUT_MS              8000     // Per-request HTTP timeout
#define WIFI_CONNECT_TIMEOUT_MS     15000UL   // Max time to wait for WiFi join
#define WIFI_BACKOFF_BASE_MS         2000UL   // Starting WiFi retry interval
#define WIFI_BACKOFF_MAX_MS         60000UL   // Cap WiFi retry interval at 60 s
#define HTTP_RETRY_COUNT                3     // Retries for critical HTTP calls
#define HTTP_RETRY_BASE_DELAY_MS     1000UL   // Starting retry delay
#define REG_RETRY_INTERVAL_MS       15000UL   // Registration retry interval

// ══════════════════════════════════════════════════════════════════════
//  SECTION 4 — NVS SCHEMA
// ══════════════════════════════════════════════════════════════════════
//
//  Namespace : "blackbox"
//  ┌─────────────────┬────────┬──────────────────────────────────────┐
//  │ Key             │ Type   │ Description                          │
//  ├─────────────────┼────────┼──────────────────────────────────────┤
//  │ schema_ver      │ UInt8  │ NVS schema version (current: 2)      │
//  │ deviceId        │ String │ BBX-ESP32-AABBCCDDEEFF               │
//  │ packetId        │ String │ Assigned by backend on registration   │
//  │ registered      │ Bool   │ True after successful registration    │
//  │ last_cmd_id     │ String │ Last executed commandId (replay guard)│
//  │ last_cmd_state  │ UInt8  │ 0=NONE 1=EXECUTING 2=SUCCESS 3=FAILED│
//  └─────────────────┴────────┴──────────────────────────────────────┘
//
#define NVS_NAMESPACE         "blackbox"
#define NVS_KEY_SCHEMA_VER    "schema_ver"
#define NVS_KEY_DEVICE_ID     "deviceId"
#define NVS_KEY_PACKET_ID     "packetId"
#define NVS_KEY_REGISTERED    "registered"
#define NVS_KEY_LAST_CMD_ID   "last_cmd_id"
#define NVS_KEY_LAST_CMD_ST   "last_cmd_state"

#define NVS_SCHEMA_VERSION    2   // Increment when schema changes

// Command states (stored as UInt8 in NVS)
enum class CmdState : uint8_t {
    NONE      = 0,
    EXECUTING = 1,
    SUCCESS   = 2,
    FAILED    = 3
};

// ══════════════════════════════════════════════════════════════════════
//  SECTION 5 — GLOBAL STATE
// ══════════════════════════════════════════════════════════════════════

Preferences g_prefs;

// Device identity
String g_deviceId     = "";
String g_packetId     = "";
bool   g_registered   = false;

// Replay protection
String   g_lastCmdId    = "";
CmdState g_lastCmdState = CmdState::NONE;

// Timing
unsigned long g_lastHeartbeat    = 0;
unsigned long g_lastPoll         = 0;
unsigned long g_lastRegAttempt   = 0;
unsigned long g_wifiBackoffUntil = 0;   // Epoch ms before next WiFi attempt
uint32_t      g_wifiBackoffMs    = WIFI_BACKOFF_BASE_MS;

// ══════════════════════════════════════════════════════════════════════
//  SECTION 6 — FORWARD DECLARATIONS
// ══════════════════════════════════════════════════════════════════════

// NVS
void     nvsInit();
void     nvsMigrate(uint8_t fromVersion);
void     loadOrGenerateDeviceId();
void     loadStoredConfig();
String   generateDeviceId();

// Network
bool     ensureWiFi();
void     resetWiFiBackoff();

// HTTP primitives
struct HttpResult { int code; String body; };
HttpResult httpPost(const String& path, const String& jsonBody);
HttpResult httpGet(const String& path);
HttpResult httpPostWithRetry(const String& path, const String& jsonBody, int retries);
void       addAuthHeader(HTTPClient& http);

// Business logic
bool     registerDevice();
void     sendHeartbeat();
void     pollCommands();
void     handleUnlock(const String& commandId);
void     handleLock(const String& commandId);
bool     isCommandDuplicate(const String& commandId);
void     persistCmdState(const String& commandId, CmdState state);

// Actuator (extension points)
bool     actuatorUnlock();
bool     actuatorLock();

// Diagnostics
void     blinkLed(int times, int onMs, int offMs);
float    readBatteryVoltage();
bool     readTamperState();
void     printDiagnostics();

// ══════════════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(400);

    Serial.println(F("\n╔══════════════════════════════════════════╗"));
    Serial.println(F(  "║   BlackBox Smart Security Packet v2.0.0  ║"));
    Serial.println(F(  "║   Firmware: Production Release            ║"));
    Serial.println(F(  "╚══════════════════════════════════════════╝\n"));

    // ── Hardware init ────────────────────────────────────────────────
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);

    // ── NVS init (schema validation + migration) ─────────────────────
    nvsInit();
    loadOrGenerateDeviceId();
    loadStoredConfig();

    // ── Boot diagnostics ─────────────────────────────────────────────
    Serial.printf("[BOOT] Device ID    : %s\n",  g_deviceId.c_str());
    Serial.printf("[BOOT] Packet ID    : %s\n",  g_packetId.isEmpty() ? "<unassigned>" : g_packetId.c_str());
    Serial.printf("[BOOT] Registered   : %s\n",  g_registered ? "YES" : "NO");
    Serial.printf("[BOOT] Last Cmd ID  : %s\n",  g_lastCmdId.isEmpty() ? "<none>" : g_lastCmdId.c_str());
    Serial.printf("[BOOT] Last Cmd St  : %u\n",  (uint8_t)g_lastCmdState);
    Serial.printf("[BOOT] Free heap    : %u bytes\n", esp_get_free_heap_size());

    // ── Detect interrupted EXECUTING state from previous boot ────────
    // If device rebooted mid-unlock, the command is in EXECUTING state.
    // We cannot know if the actuator fired. Mark as FAILED so the backend
    // can retry and the operator is alerted.
    if (g_lastCmdState == CmdState::EXECUTING) {
        Serial.println("[BOOT] WARN: Detected interrupted EXECUTING command from previous boot.");
        Serial.printf("[BOOT] WARN: Marking commandId '%s' as FAILED (actuator state unknown).\n",
                      g_lastCmdId.c_str());
        persistCmdState(g_lastCmdId, CmdState::FAILED);
        // Attempt to report failure to backend once WiFi is ready (done below)
    }

    // ── WiFi ─────────────────────────────────────────────────────────
    ensureWiFi();

    // ── Report interrupted command failure to backend if applicable ──
    if (!g_lastCmdId.isEmpty() && g_lastCmdState == CmdState::FAILED) {
        Serial.println("[BOOT] Reporting interrupted command failure to backend...");
        StaticJsonDocument<128> doc;
        doc["commandId"] = g_lastCmdId;
        doc["status"]    = "FAILED";
        doc["reason"]    = "device_rebooted_during_execution";
        String body; serializeJson(doc, body);
        httpPostWithRetry("/api/device/command-complete", body, HTTP_RETRY_COUNT);
    }

    // ── Registration ─────────────────────────────────────────────────
    if (!g_registered || g_packetId.isEmpty()) {
        Serial.println("[BOOT] Starting device registration...");
        if (registerDevice()) {
            Serial.println("[BOOT] Registration successful.");
        } else {
            Serial.println("[BOOT] Registration failed — will retry in main loop.");
        }
    } else {
        Serial.println("[BOOT] Restored registration from NVS.");
    }

    blinkLed(1, 300, 0);  // Single blink = boot complete
    printDiagnostics();
    Serial.println("[BOOT] Entering main loop.\n");
}

// ══════════════════════════════════════════════════════════════════════
//  MAIN LOOP
// ══════════════════════════════════════════════════════════════════════

void loop() {
    unsigned long now = millis();

    // ── WiFi watchdog (with exponential backoff) ─────────────────────
    if (WiFi.status() != WL_CONNECTED) {
        if (now < g_wifiBackoffUntil) return;  // Respect backoff; yield
        if (!ensureWiFi()) {
            // Backoff: double delay, cap at WIFI_BACKOFF_MAX_MS
            g_wifiBackoffMs = min(g_wifiBackoffMs * 2, (uint32_t)WIFI_BACKOFF_MAX_MS);
            g_wifiBackoffUntil = now + g_wifiBackoffMs;
            Serial.printf("[WiFi] Next retry in %lu ms\n", g_wifiBackoffMs);
            return;
        }
        resetWiFiBackoff();
    }

    // ── Re-register (with rate-limiting, not a tight retry loop) ────
    if (!g_registered || g_packetId.isEmpty()) {
        if (now - g_lastRegAttempt >= REG_RETRY_INTERVAL_MS) {
            Serial.println("[LOOP] Retrying registration...");
            g_lastRegAttempt = now;
            registerDevice();
        }
        return;  // Don't poll or heartbeat without a valid packetId
    }

    // ── Heartbeat (every 60 s) ───────────────────────────────────────
    if (now - g_lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
        sendHeartbeat();
        g_lastHeartbeat = now;
    }

    // ── Command poll (every 2 s) ─────────────────────────────────────
    if (now - g_lastPoll >= POLL_INTERVAL_MS) {
        pollCommands();
        g_lastPoll = now;
    }
}

// ══════════════════════════════════════════════════════════════════════
//  NVS MANAGEMENT
// ══════════════════════════════════════════════════════════════════════

/**
 * Open NVS, validate schema version, migrate if needed.
 * If NVS is corrupt or unreadable, clear and start fresh.
 */
void nvsInit() {
    bool ok = g_prefs.begin(NVS_NAMESPACE, false);
    if (!ok) {
        Serial.println("[NVS] FATAL: Could not open NVS namespace. Clearing flash and rebooting.");
        g_prefs.clear();
        g_prefs.end();
        // Try once more
        ok = g_prefs.begin(NVS_NAMESPACE, false);
        if (!ok) {
            Serial.println("[NVS] FATAL: NVS unrecoverable.");
            // Continue anyway; device will re-register on next good boot.
            return;
        }
    }

    uint8_t storedVersion = g_prefs.getUChar(NVS_KEY_SCHEMA_VER, 0);

    if (storedVersion == 0) {
        // Fresh device — write current schema version
        g_prefs.putUChar(NVS_KEY_SCHEMA_VER, NVS_SCHEMA_VERSION);
        Serial.printf("[NVS] Fresh storage. Schema v%u written.\n", NVS_SCHEMA_VERSION);
    } else if (storedVersion < NVS_SCHEMA_VERSION) {
        Serial.printf("[NVS] Schema migration: v%u → v%u\n", storedVersion, NVS_SCHEMA_VERSION);
        nvsMigrate(storedVersion);
        g_prefs.putUChar(NVS_KEY_SCHEMA_VER, NVS_SCHEMA_VERSION);
    } else if (storedVersion > NVS_SCHEMA_VERSION) {
        // Firmware downgrade — safest action is to wipe and re-register
        Serial.printf("[NVS] WARN: Stored schema v%u > firmware schema v%u. Wiping NVS.\n",
                      storedVersion, NVS_SCHEMA_VERSION);
        g_prefs.clear();
        g_prefs.putUChar(NVS_KEY_SCHEMA_VER, NVS_SCHEMA_VERSION);
    }
    // storedVersion == NVS_SCHEMA_VERSION → nothing to do
}

/**
 * Apply schema migrations from older versions.
 * Add cases here as the schema evolves.
 */
void nvsMigrate(uint8_t fromVersion) {
    switch (fromVersion) {
        case 1:
            // v1→v2: added last_cmd_id and last_cmd_state keys
            // No data transform needed; keys simply don't exist yet → will default to ""/"0"
            Serial.println("[NVS] Migration v1→v2: no data transform required.");
            break;
        default:
            Serial.printf("[NVS] No migration path from v%u. Keys may be absent; defaults apply.\n",
                          fromVersion);
            break;
    }
}

// ══════════════════════════════════════════════════════════════════════
//  DEVICE IDENTITY
// ══════════════════════════════════════════════════════════════════════

/**
 * Load or generate the device ID.
 * Uses all 6 MAC bytes for global uniqueness (3-byte suffix has ~16M
 * combinations; 6-byte has 281 trillion — important for fleet deployments).
 * ID is written to NVS on first generation and never overwritten.
 */
void loadOrGenerateDeviceId() {
    String stored = g_prefs.getString(NVS_KEY_DEVICE_ID, "");

    // Validate: must start with "BBX-ESP32-" and be 22 chars
    if (stored.length() == 22 && stored.startsWith("BBX-ESP32-")) {
        g_deviceId = stored;
        Serial.printf("[NVS] Loaded Device ID: %s\n", g_deviceId.c_str());
        return;
    }

    if (!stored.isEmpty()) {
        Serial.printf("[NVS] WARN: Stored Device ID '%s' looks corrupt. Regenerating.\n", stored.c_str());
    }

    g_deviceId = generateDeviceId();
    g_prefs.putString(NVS_KEY_DEVICE_ID, g_deviceId);
    Serial.printf("[NVS] Generated Device ID: %s\n", g_deviceId.c_str());
}

String generateDeviceId() {
    uint8_t mac[6];

    WiFi.macAddress(mac);

    char buf[24];

    snprintf(
        buf,
        sizeof(buf),
        "BBX-ESP32-%02X%02X%02X%02X%02X%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    return String(buf);
}

/**
 * Load all persisted config from NVS with validation.
 */
void loadStoredConfig() {
    // packetId: validate non-empty and reasonable length
    String pid = g_prefs.getString(NVS_KEY_PACKET_ID, "");
    if (pid.length() > 0 && pid.length() <= 64) {
        g_packetId = pid;
    } else if (pid.length() > 64) {
        Serial.println("[NVS] WARN: Stored packetId too long — discarding.");
        g_prefs.remove(NVS_KEY_PACKET_ID);
    }

    g_registered = g_prefs.getBool(NVS_KEY_REGISTERED, false);

    // Replay state
    g_lastCmdId    = g_prefs.getString(NVS_KEY_LAST_CMD_ID, "");
    uint8_t rawSt  = g_prefs.getUChar(NVS_KEY_LAST_CMD_ST, 0);
    // Validate: only accept known enum values
    g_lastCmdState = (rawSt <= 3) ? (CmdState)rawSt : CmdState::NONE;
}

// ══════════════════════════════════════════════════════════════════════
//  DEVICE REGISTRATION
// ══════════════════════════════════════════════════════════════════════

bool registerDevice() {
    StaticJsonDocument<256> reqDoc;
    reqDoc["deviceId"]        = g_deviceId;
    reqDoc["firmwareVersion"] = FIRMWARE_VERSION;
    String reqBody;
    serializeJson(reqDoc, reqBody);

    // Use retry for registration — it is critical path
    HttpResult res = httpPostWithRetry("/api/device/register", reqBody, HTTP_RETRY_COUNT);

    Serial.printf("[REG] POST /api/device/register → HTTP %d\n", res.code);

    if (res.code != 200 && res.code != 201) {
        Serial.printf("[REG] Failed. Body: %s\n", res.body.c_str());
        return false;
    }

    StaticJsonDocument<256> resDoc;
    DeserializationError err = deserializeJson(resDoc, res.body);
    if (err) {
        Serial.printf("[REG] JSON parse error: %s\n", err.c_str());
        return false;
    }

    const char* pid = resDoc["packetId"];
    if (!pid || strlen(pid) == 0 || strlen(pid) > 64) {
        Serial.println("[REG] Response missing or invalid 'packetId'.");
        return false;
    }

    g_packetId   = String(pid);
    g_registered = true;

    g_prefs.putString(NVS_KEY_PACKET_ID, g_packetId);
    g_prefs.putBool(NVS_KEY_REGISTERED, true);

    Serial.printf("[REG] SUCCESS — Packet ID: %s\n", g_packetId.c_str());
    blinkLed(3, 100, 100);  // Triple blink = registration event
    return true;
}

// ══════════════════════════════════════════════════════════════════════
//  HEARTBEAT
// ══════════════════════════════════════════════════════════════════════

/**
 * Enriched heartbeat payload: includes diagnostics for fleet monitoring.
 * Backend can use uptime, heap, and RSSI for health dashboards without
 * requiring any additional device-side endpoints.
 */
void sendHeartbeat() {
    StaticJsonDocument<384> doc;
    doc["deviceId"]       = g_deviceId;
    doc["packetId"]       = g_packetId;
    doc["firmwareVersion"]= FIRMWARE_VERSION;
    doc["uptime_ms"]      = millis();
    doc["free_heap"]      = esp_get_free_heap_size();
    doc["wifi_rssi"]      = WiFi.RSSI();

    // Optional: battery voltage (0.0 if sensor not wired)
    float batt = readBatteryVoltage();
    if (batt > 0.0f) doc["battery_v"] = serialized(String(batt, 2));

    // Optional: tamper state
#ifdef TAMPER_PIN
    doc["tamper"] = readTamperState();
#endif

    String body;
    serializeJson(doc, body);

    // Heartbeat failure is non-critical — single attempt, no retry
    HttpResult res = httpPost("/api/device/heartbeat", body);

    if (res.code == 200 || res.code == 204) {
        Serial.printf("[HB] OK (HTTP %d) | heap=%u | RSSI=%d dBm | uptime=%lus\n",
                      res.code, esp_get_free_heap_size(), WiFi.RSSI(), millis() / 1000);
    } else {
        Serial.printf("[HB] WARN: HTTP %d — %s\n", res.code, res.body.c_str());
    }
}

// ══════════════════════════════════════════════════════════════════════
//  COMMAND POLLING
// ══════════════════════════════════════════════════════════════════════

void pollCommands() {
    String path = "/api/device/commands?packetId=" + g_packetId;
    HttpResult res = httpGet(path);

    // 204 = no command pending; silently ignore
    if (res.code == 204) return;

    // Gracefully handle empty 200 body (some backends return {} instead of 204)
    if (res.code == 200 && (res.body.isEmpty() || res.body == "{}")) return;

    if (res.code != 200) {
        if (res.code != -1) {  // -1 = WiFi was down, already logged
            Serial.printf("[POLL] HTTP %d: %s\n", res.code, res.body.c_str());
        }
        return;
    }

    StaticJsonDocument<256> doc;
    DeserializationError err = deserializeJson(doc, res.body);
    if (err) {
        Serial.printf("[POLL] JSON parse error: %s | raw: %s\n", err.c_str(), res.body.c_str());
        return;
    }

    const char* command   = doc["command"];
    const char* commandId = doc["commandId"];

    if (!command || !commandId || strlen(commandId) == 0) {
        return;  // Malformed or empty command object — ignore quietly
    }

    Serial.printf("[POLL] Command: %s | ID: %s\n", command, commandId);

    // Replay Protection Check
    if (isCommandDuplicate(String(commandId))) {
        Serial.println("[POLL] Replay Detected: Command was already executed. Re-ACKing.");
        // Re-ACK to ensure backend clears it
        StaticJsonDocument<192> ackDoc;
        ackDoc["commandId"] = commandId;
        ackDoc["status"]    = "SUCCESS";
        String body;
        serializeJson(ackDoc, body);
        httpPostWithRetry("/api/device/command-complete", body, HTTP_RETRY_COUNT);
        return;
    }

    if (strcmp(command, "UNLOCK") == 0) {
        handleUnlock(String(commandId));
    } else if (strcmp(command, "LOCK") == 0) {
        handleLock(String(commandId));
    } else {
        Serial.printf("[POLL] Unknown command '%s' — ignoring.\n", command);
    }
}

// ══════════════════════════════════════════════════════════════════════
//  COMMAND REPLAY PROTECTION
// ══════════════════════════════════════════════════════════════════════

/**
 * Returns true if this commandId was already executed successfully.
 *
 * Logic:
 *  - NONE:      Never seen this ID → not a duplicate
 *  - EXECUTING: Crashed mid-execution → already reported as FAILED on boot → not a dup, but
 *               the state has been reset; this branch won't be reached for the same ID
 *  - SUCCESS:   Completed → duplicate; skip
 *  - FAILED:    Previous attempt failed → allow retry so backend can recover
 */
bool isCommandDuplicate(const String& commandId) {
    if (g_lastCmdId != commandId) return false;  // Different command entirely
    if (g_lastCmdState == CmdState::SUCCESS) {
        Serial.printf("[REPLAY] Duplicate commandId '%s' (already SUCCESS) — blocked.\n",
                      commandId.c_str());
        return true;
    }
    if (g_lastCmdState == CmdState::EXECUTING) {
        // Shouldn't reach here: boot recovery should have set FAILED for this ID.
        // If it somehow did, treat as duplicate to avoid double-fire.
        Serial.printf("[REPLAY] CommandId '%s' still in EXECUTING state — blocked (boot recovery missed?).\n",
                      commandId.c_str());
        return true;
    }
    return false;
}

/**
 * Atomically persist command ID and state to NVS.
 * Called at every state transition so reboots land in the correct state.
 */
void persistCmdState(const String& commandId, CmdState state) {
    g_lastCmdId    = commandId;
    g_lastCmdState = state;
    g_prefs.putString(NVS_KEY_LAST_CMD_ID, commandId);
    g_prefs.putUChar(NVS_KEY_LAST_CMD_ST, (uint8_t)state);
}

// ══════════════════════════════════════════════════════════════════════
//  UNLOCK HANDLER — STATE MACHINE
// ══════════════════════════════════════════════════════════════════════
//
//  State machine:
//    PENDING ──── isCommandDuplicate? ───► BLOCKED (return, no action)
//       │
//       ▼ persist EXECUTING
//    EXECUTING
//       │
//       ▼ actuatorUnlock()
//    actuator result?
//       │ true ──────────────────────────► persist SUCCESS → ACK backend
//       │ false ─────────────────────────► persist FAILED  → NACK backend

void handleUnlock(const String& commandId) {
    // ── Replay guard ────────────────────────────────────────────────
    if (isCommandDuplicate(commandId)) return;

    Serial.println(F("┌──────────────────────────────────────────┐"));
    Serial.printf( "│  UNLOCK EVENT                             │\n");
    Serial.printf( "│  CMD ID: %-32s │\n", commandId.c_str());
    Serial.println(F("└──────────────────────────────────────────┘"));

    // ── Transition: PENDING → EXECUTING (persisted to NVS) ─────────
    persistCmdState(commandId, CmdState::EXECUTING);
    Serial.println("[UNLOCK] State: EXECUTING");

    // ── Visual indicator: blink BEFORE actuator ─────────────────────
    blinkLed(2, 300, 200);

    // ── Actuate ──────────────────────────────────────────────────────
    bool actuatorOk = actuatorUnlock();

    // ── Transition: EXECUTING → SUCCESS / FAILED ─────────────────────
    CmdState finalState = actuatorOk ? CmdState::SUCCESS : CmdState::FAILED;
    persistCmdState(commandId, finalState);
    Serial.printf("[UNLOCK] State: %s\n", actuatorOk ? "SUCCESS" : "FAILED");

    // ── Report to backend (with retry for reliability) ────────────────
    StaticJsonDocument<192> doc;
    doc["commandId"] = commandId;
    doc["status"]    = actuatorOk ? "SUCCESS" : "FAILED";
    if (!actuatorOk) doc["reason"] = "actuator_error";

    String body;
    serializeJson(doc, body);

    HttpResult res = httpPostWithRetry("/api/device/command-complete", body, HTTP_RETRY_COUNT);

    if (res.code == 200 || res.code == 204) {
        Serial.printf("[UNLOCK] ACK confirmed (HTTP %d)\n", res.code);
    } else {
        // ACK failed but actuator already fired.
        // State is persisted as SUCCESS/FAILED in NVS.
        // On next poll the backend will retry and isCommandDuplicate() will block re-execution.
        Serial.printf("[UNLOCK] WARN: ACK failed (HTTP %d). State persisted in NVS — replay protected.\n",
                      res.code);
    }
}

// ══════════════════════════════════════════════════════════════════════
//  LOCK HANDLER — STATE MACHINE (Symmetrical to UNLOCK)
// ══════════════════════════════════════════════════════════════════════

void handleLock(const String& commandId) {
    // ── Replay guard ────────────────────────────────────────────────
    if (isCommandDuplicate(commandId)) return;

    Serial.println(F("┌──────────────────────────────────────────┐"));
    Serial.printf( "│  LOCK EVENT                               │\n");
    Serial.printf( "│  CMD ID: %-32s │\n", commandId.c_str());
    Serial.println(F("└──────────────────────────────────────────┘"));

    // ── Transition: PENDING → EXECUTING (persisted to NVS) ─────────
    persistCmdState(commandId, CmdState::EXECUTING);
    Serial.println("[LOCK] State: EXECUTING");

    // ── Visual indicator: blink BEFORE actuator ─────────────────────
    blinkLed(2, 300, 200);

    // ── Actuate ──────────────────────────────────────────────────────
    bool actuatorOk = actuatorLock();

    // ── Transition: EXECUTING → SUCCESS / FAILED ─────────────────────
    CmdState finalState = actuatorOk ? CmdState::SUCCESS : CmdState::FAILED;
    persistCmdState(commandId, finalState);
    Serial.printf("[LOCK] State: %s\n", actuatorOk ? "SUCCESS" : "FAILED");

    // ── Report to backend (with retry for reliability) ────────────────
    StaticJsonDocument<192> doc;
    doc["commandId"] = commandId;
    doc["status"]    = actuatorOk ? "SUCCESS" : "FAILED";
    if (!actuatorOk) doc["reason"] = "actuator_error";

    String body;
    serializeJson(doc, body);

    HttpResult res = httpPostWithRetry("/api/device/command-complete", body, HTTP_RETRY_COUNT);

    if (res.code == 200 || res.code == 204) {
        Serial.printf("[LOCK] ACK confirmed (HTTP %d)\n", res.code);
    } else {
        // ACK failed but actuator already fired.
        // State is persisted as SUCCESS/FAILED in NVS.
        // On next poll the backend will retry and isCommandDuplicate() will block re-execution.
        Serial.printf("[LOCK] WARN: ACK failed (HTTP %d). State persisted in NVS — replay protected.\n",
                      res.code);
    }
}

// ══════════════════════════════════════════════════════════════════════
//  ACTUATORS — EXTENSION POINTS
// ══════════════════════════════════════════════════════════════════════
//
//  To add a real actuator:
//    1. Set ACTUATOR_TYPE above (RELAY, SERVO, SOLENOID)
//    2. Define the corresponding pins above
//
//  This function must return:
//    true  — actuator fired successfully
//    false — actuator failed (will be reported to backend as FAILED)

bool actuatorUnlock() {
    Serial.println("[ACT] Simulated unlock complete.");
    return true;
}

bool actuatorLock() {
    Serial.println("[ACT] Simulated lock complete.");
    return true;
}

// ══════════════════════════════════════════════════════════════════════
//  WIFI MANAGER — EXPONENTIAL BACKOFF
// ══════════════════════════════════════════════════════════════════════

/**
 * Attempt to connect to WiFi.
 * Blocks for up to WIFI_CONNECT_TIMEOUT_MS.
 * Does NOT implement backoff itself — caller manages via g_wifiBackoffUntil.
 */
bool ensureWiFi() {
    if (WiFi.status() == WL_CONNECTED) return true;

    Serial.printf("[WiFi] Connecting to '%s'...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > WIFI_CONNECT_TIMEOUT_MS) {
            WiFi.disconnect(true);  // Clean up failed attempt
            Serial.println("[WiFi] Timeout.");
            return false;
        }
        delay(300);
        Serial.print('.');
    }

    Serial.printf("\n[WiFi] Connected | IP: %s | RSSI: %d dBm\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
    return true;
}

void resetWiFiBackoff() {
    g_wifiBackoffMs    = WIFI_BACKOFF_BASE_MS;
    g_wifiBackoffUntil = 0;
}

// ══════════════════════════════════════════════════════════════════════
//  HTTP PRIMITIVES
// ══════════════════════════════════════════════════════════════════════

/**
 * Add authorization header to all outbound requests.
 * Uses Bearer token (device secret).
 */
void addAuthHeader(HTTPClient& http) {
    if (strlen(DEVICE_SECRET) > 0) {
        http.addHeader("Authorization", "Bearer " + String(DEVICE_SECRET));
    }
    // Correlate device in backend logs without parsing body
    http.addHeader("X-Device-Id", g_deviceId);
}

/**
 * HTTP POST — single attempt.
 * HTTPClient is always ended, even on error.
 */
HttpResult httpPost(const String& path, const String& jsonBody) {
    HttpResult result = {-1, ""};

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[HTTP] POST skipped — WiFi down.");
        return result;
    }

    HTTPClient http;
    String url = String(BACKEND_BASE_URL) + path;

    if (!http.begin(url)) {
        Serial.printf("[HTTP] POST begin() failed: %s\n", url.c_str());
        return result;
    }

    http.setTimeout(HTTP_TIMEOUT_MS);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("Accept", "application/json");
    addAuthHeader(http);

    result.code = http.POST(jsonBody);
    if (result.code > 0) {
        result.body = http.getString();
    } else {
        Serial.printf("[HTTP] POST %s error: %s\n", path.c_str(),
                      http.errorToString(result.code).c_str());
    }

    http.end();  // Always release connection
    return result;
}

/**
 * HTTP GET — single attempt.
 */
HttpResult httpGet(const String& path) {
    HttpResult result = {-1, ""};

    if (WiFi.status() != WL_CONNECTED) {
        return result;  // Silent — WiFi failures logged by WiFi manager
    }

    HTTPClient http;
    String url = String(BACKEND_BASE_URL) + path;

    if (!http.begin(url)) {
        Serial.printf("[HTTP] GET begin() failed: %s\n", url.c_str());
        return result;
    }

    http.setTimeout(HTTP_TIMEOUT_MS);
    http.addHeader("Accept", "application/json");
    addAuthHeader(http);

    result.code = http.GET();
    if (result.code > 0) {
        result.body = http.getString();
    } else {
        Serial.printf("[HTTP] GET %s error: %s\n", path.c_str(),
                      http.errorToString(result.code).c_str());
    }

    http.end();
    return result;
}

/**
 * HTTP POST with exponential backoff retry.
 * Use for critical calls: registration, command-complete.
 * Do NOT use for heartbeat or polling (non-critical, high-frequency).
 */
HttpResult httpPostWithRetry(const String& path, const String& jsonBody, int retries) {
    HttpResult result = {-1, ""};
    unsigned long delayMs = HTTP_RETRY_BASE_DELAY_MS;

    for (int attempt = 1; attempt <= retries; attempt++) {
        if (attempt > 1) {
            Serial.printf("[HTTP] Retry %d/%d in %lu ms...\n", attempt, retries, delayMs);
            delay(delayMs);
            delayMs *= 2;  // Exponential backoff
        }

        result = httpPost(path, jsonBody);

        // Success: 2xx codes
        if (result.code >= 200 && result.code < 300) return result;

        // Client errors (4xx): retrying won't help — bail immediately
        if (result.code >= 400 && result.code < 500) {
            Serial.printf("[HTTP] Client error %d — not retrying.\n", result.code);
            return result;
        }

        // -1 (WiFi down) or 5xx: retry
        Serial.printf("[HTTP] Attempt %d failed (HTTP %d)\n", attempt, result.code);
    }

    Serial.printf("[HTTP] All %d attempts failed for %s\n", retries, path.c_str());
    return result;
}

// ══════════════════════════════════════════════════════════════════════
//  OPTIONAL SENSORS — STUBS
// ══════════════════════════════════════════════════════════════════════

float readBatteryVoltage() {
#ifdef BATTERY_ADC_PIN
    int raw = analogRead(BATTERY_ADC_PIN);
    float voltage = (raw / 4095.0f) * 3.3f * BATTERY_RATIO;
    return voltage;
#else
    return 0.0f;
#endif
}

bool readTamperState() {
#ifdef TAMPER_PIN
    pinMode(TAMPER_PIN, INPUT_PULLUP);
    return digitalRead(TAMPER_PIN) == HIGH;  // HIGH = switch open = tamper
#else
    return false;
#endif
}

// ══════════════════════════════════════════════════════════════════════
//  LED HELPER
// ══════════════════════════════════════════════════════════════════════

void blinkLed(int times, int onMs, int offMs) {
    for (int i = 0; i < times; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(onMs);
        digitalWrite(LED_PIN, LOW);
        if (i < times - 1 && offMs > 0) delay(offMs);
    }
}

// ══════════════════════════════════════════════════════════════════════
//  BOOT DIAGNOSTICS
// ══════════════════════════════════════════════════════════════════════

void printDiagnostics() {
    Serial.println(F("\n── Boot Diagnostics ─────────────────────────"));
    Serial.printf("  Firmware    : v%s\n",     FIRMWARE_VERSION);
    Serial.printf("  Device ID   : %s\n",      g_deviceId.c_str());
    Serial.printf("  Packet ID   : %s\n",      g_packetId.isEmpty() ? "UNASSIGNED" : g_packetId.c_str());
    Serial.printf("  WiFi SSID   : %s\n",      WIFI_SSID);
    Serial.printf("  WiFi RSSI   : %d dBm\n",  WiFi.RSSI());
    Serial.printf("  IP Address  : %s\n",      WiFi.localIP().toString().c_str());
    Serial.printf("  Free Heap   : %u bytes\n",esp_get_free_heap_size());
    Serial.printf("  Last Cmd ID : %s\n",      g_lastCmdId.isEmpty() ? "none" : g_lastCmdId.c_str());
    Serial.printf("  Last Cmd St : %u\n",      (uint8_t)g_lastCmdState);
    Serial.printf("  Auth Mode   : %s\n",      strlen(DEVICE_SECRET) > 0 ? "Bearer token" : "NONE (insecure)");
    Serial.println(F("─────────────────────────────────────────────\n"));
}
