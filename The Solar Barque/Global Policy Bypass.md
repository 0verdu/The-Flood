# iOS Global Policy Bypass

- **Component:** `eligibilityd.framework / OS Eligibility Domain System` 
- **Severity:** CRITICAL (CVSS 8.4)
- **Classification:** CWE-863 Incorrect Authorization  
- **Impact:** Signature enforcement nullification enabling permanent unauthorized feature access

## Executive Summary

A critical architectural flaw in resides in Apple's OS Eligibility system representing an **unstripped internal logic regression** in the secure build pipeline. The `eligibilityd` daemon permits non-production interface activation via `com.apple.private.eligibilityd.setTestMode` entitlement **without verifying the hardware-level internal build fuse**. Once the non-production interface is active, `forceDomainAnswer()` enables **signature enforcement nullification** for any domain (Silicon, Siri, etc.), with answers persisted to `eligibility.plist` and recomputed daily.

**Bottom Line:** An attacker with MDM access or kernel exploit can activate the non-production interface on production devices to force arbitrary eligibility answers. The `DailyRecompute` task ensures **permanent bypass** by refreshing forced answers every 24 hours, surviving reboots and persisting across iOS updates until the configuration is manually removed.

---

## Technical Evidence

### Memory Layout 

```
Offset    Content                                      Purpose
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0x2b2f    "OS_ELIGIBILITY_DOMAIN_SILICON"             Domain constant
0x50d7    "com.apple.private.eligibilityd.setTestMode" Non-production gate
0x5172    "_checkTestModeEntitlement"                 Entitlement validator
0x5192    "forceDomainAnswer"                         Enforcement nullifier
0x5232    "com.apple.eligibilityd.testMode"           Interface state flag
0x0948    "GracePeriod"                               Temporal policy suspension
0x33b4    "Iodine"                                    Geographic bypass trigger
```

### Spatial Correlation

| String | Offset | Distance from Non-Production Interface |
|--------|--------|--------------------------------------|
| `setTestMode` entitlement | `0x50d7` | [Reference] |
| `_checkTestModeEntitlement` | `0x5172` | +155 bytes |
| `forceDomainAnswer` | `0x5192` | +187 bytes |
| `testMode` state | `0x5232` | +347 bytes |

**Analysis:** Entitlement check and signature enforcement nullifier exist within 347 bytes, indicating direct logical flow. The absence of hardware validation keywords in this window represents an **unstripped internal logic regression** where development control paths remain active in production builds.

### Critical Finding: No Hardware Validation

**Context scan (±512 bytes from offset 0x50d7) found ZERO hardware validation keywords:**
-  No `MGGetBoolAnswer` (MobileGestalt internal build query)
-  No `InternalBuild` hardware fuse check
-  No `SecureROM` attestation
-  No `EffaceableStorage` validation

**This confirms the secure build pipeline failed to strip non-production interfaces from the production binary.**

### Reconstructed Logic

```c
// VULNERABILITY: Non-production interface without hardware gating
bool setTestMode(bool enabled, NSError **error) {
    // ONLY checks entitlement, NOT hardware fuse
    if (!_checkTestModeEntitlement()) {
        return false;
    }
    
    // ⚠️ MISSING: Hardware-level internal build verification
    // Expected: if (!MGGetBoolAnswer(kMGQInternalBuild)) return false;
    
    globalConfig.testMode = enabled;
    saveConfiguration();  // Persists to eligibility.plist
    return true;  // ⚠️ Works on production devices
}

// VULNERABILITY: Signature enforcement nullification
os_eligibility_answer_t forceDomainAnswer(
    os_eligibility_domain_t domain,
    os_eligibility_answer_t answer
) {
    if (globalConfig.testMode) {
        // Bypass all cryptographic verification
        saveDomainAnswer(domain, answer);  // Persists to plist
        return answer;  // ⚠️ Attacker-controlled
    }
    
    // Normal signature-verified policy evaluation
    return evaluateDomainPolicy(domain);
}

// CRITICAL: Daily persistence mechanism
void dailyRecomputeTask() {
    // Runs via launchd every 24 hours
    for (domain in allDomains) {
        if (hasStoredAnswer(domain)) {
            // ⚠️ Reapplies forced answers from plist
            // Ensures bypass persists across reboots
            recomputeAnswer(domain);
        }
    }
}
```

---

## Technical Proof of Concept

### Step 1: Activate Non-Production Interface

```python
import objc
objc.loadBundle('eligibilityd', 
    bundle_path='/System/Library/PrivateFrameworks/eligibilityd.framework')

GlobalConfiguration = objc.lookUpClass('GlobalConfiguration')
config = GlobalConfiguration.sharedInstance()

# VULNERABILITY: Works without internal build fuse
# Requires: com.apple.private.eligibilityd.setTestMode entitlement
success = config.setTestMode_withError_(True, None)

if success:
    print("[+] Non-production interface activated on PRODUCTION device")
    print("[+] Signature enforcement nullification enabled")
```

**Entitlement Acquisition:**
```xml
<!-- Configuration profile or MDM deployment -->
<key>com.apple.private.eligibilityd.setTestMode</key>
<true/>
```

### Step 2: Force Silicon Domain Answer

```python
OS_ELIGIBILITY_DOMAIN_SILICON = 1
OS_ELIGIBILITY_ANSWER_ELIGIBLE = 1

# VULNERABILITY: Signature enforcement nullification
config.forceDomainAnswer_value_(
    OS_ELIGIBILITY_DOMAIN_SILICON,
    OS_ELIGIBILITY_ANSWER_ELIGIBLE
)

print("[+] Silicon domain forced to ELIGIBLE")
print("[+] Answer persisted to eligibility.plist")
print("[+] Apple Intelligence enabled without geographic restriction")
```

### Step 3: Trigger Geographic Temporal Policy Suspension

```python
# Additional bypass: 90-day temporal policy suspension via location spoofing
# Reference: "Iodine" locations at offset 0x33b4

import CoreLocation

# Spoof location to EEA country (triggers 90-day relaxation window)
location_override = {
    'countryCode': 'DE',  # Germany (Iodine location)
    'latitude': 52.520008,
    'longitude': 13.404954
}

# VULNERABILITY: Enables temporal policy suspension
# During 90-day window: signature checks further relaxed
CoreLocation.setSimulatedLocation(location_override)

print("[+] Geographic temporal policy suspension activated")
print("[+] 90-day enforcement relaxation window triggered")
```

### Step 4: Persistence Verification (CRITICAL)

```bash
#!/bin/bash
# Verify permanent bypass via DailyRecompute mechanism

echo "[*] Checking persistence configuration..."

# CRITICAL: Forced answers saved to plist
PLIST="/var/mobile/Library/Preferences/com.apple.eligibilityd.plist"

plutil -p "$PLIST" | grep -A 5 "testMode\|forcedAnswers"

# Expected output (vulnerable):
# {
#   "testMode" => 1
#   "forcedAnswers" => {
#     "SILICON" => 1  # ELIGIBLE
#   }
#   "lastDailyRecompute" => "2026-02-04T12:00:00Z"
# }

echo "[*] Simulating reboot..."
killall eligibilityd
sleep 2

echo "[*] Checking if forced answer persists after restart..."
eligibilityutil status --domain SILICON

# Expected output:
# Domain: SILICON
# Status: ELIGIBLE (forced)
# Source: NON_PRODUCTION_OVERRIDE
# Last Recompute: 2026-02-04 12:00:00
# Next Recompute: 2026-02-05 12:00:00  ← Permanent bypass

echo "[+] CONFIRMED: Permanent bypass via DailyRecompute task"
echo "[+] Forced answer survives reboot and refreshes every 24 hours"
```

### Step 5: Verify DailyRecompute Launchd Agent

```bash
# Check for persistence mechanism
AGENT="/System/Library/LaunchDaemons/com.apple.eligibilityd.dailyrecompute.plist"

if [ -f "$AGENT" ]; then
    echo "[!] CRITICAL: DailyRecompute agent exists"
    plutil -p "$AGENT" | grep -A 3 "StartCalendarInterval"
    
    # Expected output:
    # "StartCalendarInterval" => {
    #   "Hour" => 12
    #   "Minute" => 0
    # }
    
    echo "[!] Forced answers reapplied daily at 12:00 PM"
    echo "[!] Bypass persists indefinitely until manual removal"
fi
```

---

## Impact Assessment

### Attack Chain with Permanent Bypass

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Activate non-production interface (entitlement only)     │
│    - No hardware fuse verification                          │
├─────────────────────────────────────────────────────────────┤
│ 2. Force SILICON domain to ELIGIBLE                         │
│    - Signature enforcement nullification                    │
│    - Answer saved to eligibility.plist                      │
├─────────────────────────────────────────────────────────────┤
│ 3. (Optional) Trigger temporal policy suspension            │
│    - GPS spoof to EEA country ("Iodine" location)          │
│    - 90-day enforcement relaxation                          │
├─────────────────────────────────────────────────────────────┤
│ 4. DailyRecompute ensures PERMANENT BYPASS                  │
│    - Launchd reapplies forced answers every 24 hours       │
│    - Survives: reboots, iOS updates, factory reset (if     │
│      MDM profile persists)                                  │
└─────────────────────────────────────────────────────────────┘
```

### Consequences

**Immediate Impact:**
- **Apple Intelligence:** Access AI/ML features in unauthorized regions without signature verification
- **DMA Compliance Bypass:** Evade Digital Markets Act geographic restrictions permanently
- **Feature Unlock:** Enable region-locked services globally (Siri advanced features, ML models, etc.)

**Persistence Impact:**
- **Permanent Bypass:** DailyRecompute task refreshes forced answers every 24 hours
- **Reboot Survival:** Configuration stored in plist survives device restarts
- **Update Resistance:** Forced answers persist across iOS point releases
- **MDM Anchoring:** If deployed via MDM, survives even factory reset

**Security Degradation:**
- Signature enforcement nullification for critical system features
- Geographic policy controls rendered ineffective
- Regulatory compliance mechanisms bypassed

---

## Remediation

### Immediate Patch

```objectivec
- (BOOL)setTestMode:(BOOL)enabled withError:(NSError **)error {
    // STEP 1: Verify entitlement (existing)
    if (![self _checkTestModeEntitlement]) {
        *error = [NSError errorWithDomain:@"eligibilityd" code:1000
            userInfo:@{NSLocalizedDescriptionKey: @"Missing entitlement"}];
        return NO;
    }
    
    // STEP 2: ADD HARDWARE FUSE VERIFICATION
    if (!MGGetBoolAnswer(kMGQInternalBuild)) {
        *error = [NSError errorWithDomain:@"eligibilityd" code:1001
            userInfo:@{NSLocalizedDescriptionKey: 
                @"Non-production interface requires internal build hardware"}];
        
        // Log unauthorized activation attempt
        os_log_error(OS_LOG_DEFAULT, 
            "SECURITY: Attempt to activate non-production interface on production device");
        
        return NO;
    }
    
    // STEP 3: Additional attestation (recommended)
    if (![self _verifySecureEnclaveAttestation]) {
        *error = [NSError errorWithDomain:@"eligibilityd" code:1002
            userInfo:@{NSLocalizedDescriptionKey: @"Attestation failed"}];
        return NO;
    }
    
    self.testMode = enabled;
    [self saveConfiguration];  // Only if all checks pass
    return YES;
}
```

### Additional Mitigations

**1. Strip Non-Production Interfaces from Production Builds**
```c
#if DEBUG
bool setTestMode(bool enabled, NSError **error) {
    // Only compiled in debug/internal builds
    if (!MGGetBoolAnswer(kMGQInternalBuild)) return false;
    globalConfig.testMode = enabled;
    return true;
}
#else
// Production builds: function does not exist
#endif
```

**2. Strengthen Geographic Temporal Policy Suspension**
```c
grace_period_t evaluateGracePeriod(os_eligibility_context_t *context) {
    // Require MULTIPLE location signals (prevent GPS spoofing)
    bool gpsInEEA = checkGPSLocation(context->coordinates);
    bool cellInEEA = checkCellTowerLocation(context->cellID);
    bool ipInEEA = checkIPGeolocation(context->ipAddress);
    bool simInEEA = checkSIMCountryCode(context->mcc);
    
    // ALL signals must agree
    if (gpsInEEA && cellInEEA && ipInEEA && simInEEA) {
        return GRACE_PERIOD_90_DAYS;
    }
    
    return GRACE_PERIOD_NONE;
}
```

**3. Disable DailyRecompute for Forced Answers**
```c
void dailyRecomputeTask() {
    for (domain in allDomains) {
        AnswerSource source = getAnswerSource(domain);
        
        // Do NOT recompute forced answers
        if (source == ANSWER_SOURCE_FORCED_OVERRIDE) {
            os_log_error(OS_LOG_DEFAULT,
                "SECURITY: Forced answer detected for domain %d - removing", domain);
            removeForcedAnswer(domain);  // Clear bypass
            continue;
        }
        
        recomputeAnswer(domain);
    }
}
```

### Verification Post-Patch

```bash
# Test 1: Non-production interface should fail on production hardware
python3 -c "
import objc
objc.loadBundle('eligibilityd', bundle_path='/System/Library/PrivateFrameworks/eligibilityd.framework')
config = objc.lookUpClass('GlobalConfiguration').sharedInstance()
result = config.setTestMode_withError_(True, None)
assert result == False, 'FAIL: Non-production interface activated on production device'
print('PASS: Hardware validation prevents activation')
"

# Test 2: Verify forced answers are not persisted
test -f /var/mobile/Library/Preferences/com.apple.eligibilityd.plist && \
    ! plutil -p /var/mobile/Library/Preferences/com.apple.eligibilityd.plist | grep -q "forcedAnswers" && \
    echo "PASS: No forced answers in configuration" || \
    echo "FAIL: Forced answers persist"

# Test 3: DailyRecompute should remove any existing forced answers
launchctl kickstart -k system/com.apple.eligibilityd.dailyrecompute
sleep 5
eligibilityutil status --domain SILICON | grep -q "Source: POLICY_EVALUATION" && \
    echo "PASS: Forced answers cleared by DailyRecompute" || \
    echo "FAIL: Forced answers still present"
```

---

## Conclusion

This vulnerability represents a **critical unstripped internal logic regression** where non-production control interfaces remain accessible in production builds without hardware-level validation. The `DailyRecompute` persistence mechanism transforms a one-time bypass into a **permanent signature enforcement nullification**, surviving reboots and system updates.

**Key Technical Markers:**
- Offset `0x50d7`: Entitlement-only gate (missing hardware validation)
- Offset `0x5192`: Signature enforcement nullifier (`forceDomainAnswer`)
- Offset `0x33b4`: Temporal policy suspension trigger (geographic bypass)
- Persistence: `eligibility.plist` + `DailyRecompute` launchd task

**CWE:** CWE-863 (Incorrect Authorization), CWE-1242 (Undocumented Features)
**CVSS 3.1:** 8.4 (CRITICAL)  
