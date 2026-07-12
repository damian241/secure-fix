# secure-fix

`secure-fix` reprovisions UEFI Secure Boot keys on older Windows systems that cannot complete Microsoft’s 2023 Secure Boot certificate update.

It preserves OEM-specific keys, installs Microsoft’s current Secure Boot objects, and restores the original OEM Platform Key.

## Disclaimer

This tool modifies the UEFI Secure Boot variables:

```text
PK
KEK
db
dbx
```

Incorrect use can prevent Windows, recovery media, firmware tools, option ROMs, or BitLocker-protected volumes from booting.

Before using it:

* back up important data;
* save and verify the BitLocker recovery key;
* suspend BitLocker;
* confirm the BIOS can restore factory Secure Boot keys;
* make sure Secure Boot can be disabled for recovery;
* keep the machine connected to reliable power.

Use this software at your own risk.

The software is provided **as is**, without warranty. Damian Wright, contributors, and distributors are not liable for data loss, loss of access, equipment damage, recovery costs, or other losses caused by use or misuse of this software.

This project is independent and is not affiliated with or endorsed by Microsoft, Dell, or any other manufacturer.

## The problem

Microsoft is replacing the original 2011 Secure Boot certificates with newer 2023 certificates.

The main Secure Boot variables are:

| Variable | Purpose                                                       |
| -------- | ------------------------------------------------------------- |
| `PK`     | Platform Key; controls ownership of the Secure Boot hierarchy |
| `KEK`    | Authorises updates to `db` and `dbx`                          |
| `db`     | Allowed certificates and hashes                               |
| `dbx`    | Revoked certificates and hashes                               |

On some older systems, Windows cannot install the new Microsoft KEK because the OEM has not provided a KEK update authorised by the machine’s Platform Key.

The new Microsoft keys may be valid, but Windows cannot apply them through the existing OEM-controlled hierarchy.

## Why OEM keys must be preserved

OEM systems often contain manufacturer-specific Secure Boot certificates or hashes.

A Dell system may contain:

```text
PK:
  Dell Platform Key

KEK:
  Dell Key Exchange Key
  Microsoft KEK

db:
  Dell UEFI DB certificate
  Microsoft Windows certificates
```

OEM entries may be required for:

* recovery tools;
* BIOS update utilities;
* option ROMs;
* storage or network firmware;
* OEM preboot applications.

Replacing everything with Microsoft-only keys can cause boot validation failures.

`secure-fix` therefore preserves entries that are not already present in the selected Microsoft baseline.

## What the tool installs

```text
dbx:
  Microsoft dbx only

db:
  Microsoft db
  + extracted OEM db entries

KEK:
  Microsoft KEK
  + extracted OEM KEK entries

PK:
  original OEM Platform Key
```

The original OEM PK is restored last.

This keeps the manufacturer’s original Secure Boot ownership identity. If the OEM later publishes a correctly PK-authorised KEK update, the machine will still have the expected OEM PK.

## Commands

The tool has two actions:

```powershell
.\secure-fix.ps1 -Extract -ReleaseTag <tag>
```

```powershell
.\secure-fix.ps1 -Provision
```

## PowerShell setup

Open **64-bit Windows PowerShell as Administrator** and run:

```powershell
Set-ExecutionPolicy Unrestricted
```

## Choosing a release tag

Microsoft publishes Secure Boot objects in:

```text
https://github.com/microsoft/secureboot_objects/releases
```

Use the newest suitable release that does **not** end in:

```text
-signed
```

Example:

```text
v1.6.5
```

Do not use:

```text
v1.6.5-signed
```

Run extraction with the selected unsigned release:

```powershell
.\secure-fix.ps1 -Extract -ReleaseTag v1.6.5
```

The selected release and payload hashes are saved in:

```text
ExtractedSecureBootKeys\extracted-keys-manifest.json
```

`-Provision` automatically reuses that exact release.

To move to a newer release later, repeat extraction using the newer unsigned tag.

## Extraction

Run extraction while the factory or original Secure Boot keys are installed:

```powershell
.\secure-fix.ps1 -Extract -ReleaseTag v1.6.5
```

The tool:

1. Downloads and verifies the selected Microsoft release.
2. Reads the active `KEK` and `db`.
3. Saves the active `PK`, or `PKDefault` when the active PK is absent.
4. Compares the installed entries with the Microsoft baseline.
5. Saves the machine-specific entries.

Output:

```text
ExtractedSecureBootKeys\
├── Original-PK.esl
├── OEM-KEK.esl
├── OEM-db.esl
├── extracted-keys-manifest.json
└── extracted-keys-report.txt
```

Do not continue unless these files were created successfully.

## BitLocker preparation

Check the recovery key:

```powershell
manage-bde -protectors -get C:
```

Suspend BitLocker:

```powershell
Suspend-BitLocker -MountPoint C: -RebootCount 0
```

Keep the recovery key somewhere accessible without the affected computer.

## Provisioning process

### 1. Restore OEM defaults

In BIOS:

1. Restore or reset the factory Secure Boot keys.
2. Disable Secure Boot temporarily.
3. Save and boot Windows.

Then run:

```powershell
Set-ExecutionPolicy Unrestricted
.\secure-fix.ps1 -Extract -ReleaseTag v1.6.5
```

### 2. Suspend BitLocker

```powershell
manage-bde -protectors -get C:
Suspend-BitLocker -MountPoint C: -RebootCount 0
```

### 3. Clear the active Secure Boot keys

Reboot into BIOS and delete all Secure Boot keys.

When there is no single delete-all option, delete:

```text
PK
KEK
db
dbx
```

Enable Secure Boot and save the BIOS settings.

The BIOS may warn that the Platform Key is not initialised. This is expected because the machine is now in Setup Mode.

Boot Windows.

### 4. Provision

Open elevated PowerShell:

```powershell
Set-ExecutionPolicy Unrestricted
.\secure-fix.ps1 -Provision
```

Review the displayed keys and confirm with:

```text
y
```

or:

```text
yes
```

The tool writes:

```text
Microsoft dbx
→ merged db
→ merged KEK
→ original OEM PK
```

### 5. Reboot

Reboot once more.

Some firmware does not report the change from Setup Mode until after this reboot.

## Verification

Run:

```powershell
Confirm-SecureBootUEFI
```

Expected:

```text
True
```

Check Setup Mode:

```powershell
(Get-SecureBootUEFI -Name SetupMode).Bytes[0]
```

Expected:

```text
0
```

Check Secure Boot:

```powershell
(Get-SecureBootUEFI -Name SecureBoot).Bytes[0]
```

Expected:

```text
1
```

Check PK presence:

```powershell
(Get-SecureBootUEFI -Name PK).Bytes.Count
```

The result should be greater than zero.

## Windows Security status

Windows Security may continue to show a Secure Boot certificate warning immediately after provisioning.

Leave the machine online and check again after roughly one hour. Windows may need time to refresh its Secure Boot servicing state.

The important checks are:

```text
SetupMode = 0
SecureBoot = 1
PK present
Windows boots successfully
```

## Resume BitLocker

After Secure Boot has been verified:

```powershell
Resume-BitLocker -MountPoint C:
```

## Dell example

### Restore factory keys

1. Reboot and press `F2`.
2. Open **Secure Boot**.
3. Open **Expert Key Management**.
4. Enable **Custom Mode** if required.
5. Select one of:

   * **Reset All Keys**
   * **Restore Factory Keys**
   * **Restore All Factory Keys**
   * **Install Default Secure Boot Keys**
6. Disable Secure Boot temporarily.
7. Save and boot Windows.

Run:

```powershell
Set-ExecutionPolicy Unrestricted
.\secure-fix.ps1 -Extract -ReleaseTag v1.6.5
```

A Dell extraction may contain:

```text
Original PK:
  Dell Platform Key

OEM KEK:
  Dell Inc. Key Exchange Key

OEM db:
  Dell Inc. UEFI DB
```

### Clear the Dell keys

1. Reboot and press `F2`.
2. Open **Secure Boot**.
3. Open **Expert Key Management**.
4. Enable **Custom Mode** if required.
5. Select **Delete All Keys** or delete `PK`, `KEK`, `db`, and `dbx` individually.
6. Enable Secure Boot.
7. Save and boot Windows.

The warning that PK is not initialised is expected.

### Provision the Dell

```powershell
Set-ExecutionPolicy Unrestricted
.\secure-fix.ps1 -Provision
```

Confirm with:

```text
y
```

The tool installs:

```text
Microsoft dbx
→ Microsoft + Dell db
→ Microsoft + Dell KEK
→ original Dell PK
```

Reboot and verify:

```powershell
Confirm-SecureBootUEFI
(Get-SecureBootUEFI -Name SetupMode).Bytes[0]
(Get-SecureBootUEFI -Name SecureBoot).Bytes[0]
```

Expected:

```text
True
0
1
```

## Recovery

When the machine does not boot:

1. Enter BIOS.
2. Disable Secure Boot.
3. Boot Windows if possible.
4. Enter the BitLocker recovery key when requested.
5. Restore the factory Secure Boot keys.
6. Re-enable Secure Boot after the factory keys are restored.

## Keep these backups

Retain:

```text
ExtractedSecureBootKeys\
SecureBootBackup-<timestamp>\
SecureBoot-State-<timestamp>\
```

The extracted package is machine-specific. Do not use it on another system without verifying that the keys are appropriate.

## Limitations

`secure-fix` cannot:

* obtain the OEM private Platform Key;
* sign updates on behalf of the OEM;
* guarantee compatibility with every firmware;
* fix insufficient UEFI variable storage;
* guarantee that every option ROM supports the selected revocations;
* prevent BitLocker recovery prompts;
* make unsupported hardware officially supported.

Prefer an official OEM firmware update when one is available.

## Summary

```text
Restore OEM factory keys
→ disable Secure Boot
→ boot Windows
→ Set-ExecutionPolicy Unrestricted
→ secure-fix -Extract -ReleaseTag <unsigned-tag>
→ suspend BitLocker
→ save the recovery key
→ clear PK, KEK, db, and dbx
→ enable Secure Boot in Setup Mode
→ boot Windows
→ Set-ExecutionPolicy Unrestricted
→ secure-fix -Provision
→ reboot
→ verify SecureBoot=1 and SetupMode=0
→ resume BitLocker
```

## Licence

Copyright © 2026 Damian Wright.

Licensed under the GNU General Public License, version 3 or later.

See `LICENSE` for the full licence.
