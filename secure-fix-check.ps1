#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Read-only UEFI Secure Boot variable extractor and comparison tool.

.DESCRIPTION
    Exports the active Secure Boot variables:
        PK, KEK, db, dbx

    It also attempts to export firmware-provided default variables when present:
        PKDefault, KEKDefault, dbDefault, dbxDefault

    For each variable it creates:
        <name>.bin          Exact variable payload returned by Windows
        <name>.json         Parsed EFI_SIGNATURE_LIST entries
        <name>.txt          Human-readable certificate/hash report
        certificates\...   Extracted DER X.509 certificates

    It can optionally compare the installed active variables against raw ESL
    payloads in a reference directory, such as a downloaded Microsoft
    secureboot_objects Firmware folder.

    This script performs no firmware writes.

.EXAMPLES
    .\Export-SecureBoot-State.ps1

    .\Export-SecureBoot-State.ps1 `
        -OutputDirectory E:\SecureBoot-State

    .\Export-SecureBoot-State.ps1 `
        -ReferenceDirectory C:\MicrosoftSecureBootObjects\v1.6.5\MicrosoftAndThirdParty\Firmware

    .\Export-SecureBoot-State.ps1 `
        -ReferenceDb C:\payloads\DB.bin `
        -ReferenceDbx C:\payloads\DBX.bin `
        -ReferenceKek C:\payloads\KEK.bin
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputDirectory = (
        Join-Path $PSScriptRoot ('SecureBoot-State-{0:yyyyMMdd-HHmmss}' -f (Get-Date))
    ),

    [Parameter()]
    [string] $ReferenceDirectory,

    [Parameter()]
    [string] $ReferencePk,

    [Parameter()]
    [string] $ReferenceKek,

    [Parameter()]
    [string] $ReferenceDb,

    [Parameter()]
    [string] $ReferenceDbx,

    [Parameter()]
    [switch] $IncludeAllHashEntries
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$EfiCertX509Guid   = 'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$EfiCertSha256Guid = 'c1c41626-504c-4092-aca9-41f936934328'

function Write-Stage {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-U32LE {
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][int] $Offset
    )

    if ($Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) {
        throw "Cannot read UInt32 at offset $Offset."
    }

    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Convert-EfiGuidBytesToGuid {
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][int] $Offset
    )

    if (($Offset + 16) -gt $Bytes.Length) {
        throw "Cannot read GUID at offset $Offset."
    }

    $guidBytes = New-Object byte[] 16
    [Array]::Copy($Bytes, $Offset, $guidBytes, 0, 16)
    return (New-Object Guid (,$guidBytes)).ToString()
}

function Get-DerObjectLength {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    if ($Bytes.Length -lt 2 -or $Bytes[0] -ne 0x30) {
        throw 'Entry is not a DER ASN.1 SEQUENCE.'
    }

    $lengthByte = [int]$Bytes[1]

    if (($lengthByte -band 0x80) -eq 0) {
        $headerLength = 2
        $contentLength = $lengthByte
    }
    else {
        $lengthOctets = $lengthByte -band 0x7F

        if ($lengthOctets -eq 0 -or $lengthOctets -gt 4) {
            throw "Unsupported DER length field: $lengthOctets byte(s)."
        }

        if ($Bytes.Length -lt (2 + $lengthOctets)) {
            throw 'Truncated DER length field.'
        }

        $headerLength = 2 + $lengthOctets
        $contentLength = 0

        for ($i = 0; $i -lt $lengthOctets; $i++) {
            $contentLength = ($contentLength -shl 8) -bor [int]$Bytes[2 + $i]
        }
    }

    $totalLength = $headerLength + $contentLength

    if ($totalLength -gt $Bytes.Length) {
        throw "DER object claims $totalLength bytes; entry has $($Bytes.Length)."
    }

    return $totalLength
}

function Get-SecureBootVariableBytes {
    param([Parameter(Mandatory)][string] $Name)

    try {
        $result = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        return ,([byte[]]@($result.Bytes))
    }
    catch {
        return $null
    }
}

function ConvertFrom-EfiSignatureList {
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][string] $VariableName,
        [Parameter(Mandatory)][string] $CertificateDirectory
    )

    if ($Bytes.Length -lt 28) {
        throw "$VariableName is too small to contain EFI_SIGNATURE_LIST data."
    }

    $offset = 0
    $listIndex = 0
    $globalEntryIndex = 0
    $entries = @()

    while ($offset -lt $Bytes.Length) {
        if (($Bytes.Length - $offset) -lt 28) {
            throw "$VariableName has a truncated list header at offset $offset."
        }

        $signatureType = Convert-EfiGuidBytesToGuid -Bytes $Bytes -Offset $offset
        $listSize = Get-U32LE -Bytes $Bytes -Offset ($offset + 16)
        $headerSize = Get-U32LE -Bytes $Bytes -Offset ($offset + 20)
        $signatureSize = Get-U32LE -Bytes $Bytes -Offset ($offset + 24)

        if ($listSize -lt 28) {
            throw "$VariableName list $listIndex has invalid size $listSize."
        }

        if (($offset + $listSize) -gt $Bytes.Length) {
            throw "$VariableName list $listIndex extends beyond the variable."
        }

        if ($signatureSize -lt 16) {
            throw "$VariableName list $listIndex has invalid SignatureSize $signatureSize."
        }

        $entryAreaSize = [int64]$listSize - 28 - [int64]$headerSize

        if ($entryAreaSize -lt 0 -or ($entryAreaSize % $signatureSize) -ne 0) {
            throw "$VariableName list $listIndex has inconsistent size fields."
        }

        $entryCount = [int]($entryAreaSize / $signatureSize)
        $entryOffset = $offset + 28 + $headerSize

        for ($entryIndex = 0; $entryIndex -lt $entryCount; $entryIndex++) {
            $ownerGuid = Convert-EfiGuidBytesToGuid -Bytes $Bytes -Offset $entryOffset
            $dataLength = [int]$signatureSize - 16
            $data = New-Object byte[] $dataLength
            [Array]::Copy($Bytes, $entryOffset + 16, $data, 0, $dataLength)

            $record = [ordered]@{
                Variable          = $VariableName
                ListIndex         = $listIndex
                EntryIndex        = $entryIndex
                GlobalEntryIndex  = $globalEntryIndex
                SignatureTypeGuid = $signatureType
                SignatureOwner    = $ownerGuid
                EntryDataBytes    = $dataLength
                EntryDataSHA256   = Get-Sha256Hex -Bytes $data
                Kind              = 'Unknown'
                Subject           = $null
                Issuer            = $null
                SerialNumber      = $null
                NotBeforeUTC      = $null
                NotAfterUTC       = $null
                CertificateSHA1   = $null
                CertificateSHA256 = $null
                CertificateFile   = $null
                HashValue         = $null
                ParseError        = $null
            }

            if ($signatureType -ieq $EfiCertX509Guid) {
                $record.Kind = 'X509'

                try {
                    $derLength = Get-DerObjectLength -Bytes $data
                    $certBytes = New-Object byte[] $derLength
                    [Array]::Copy($data, 0, $certBytes, 0, $derLength)

                    $cert = New-Object `
                        System.Security.Cryptography.X509Certificates.X509Certificate2 `
                        -ArgumentList @(,$certBytes)

                    $safeVariable = $VariableName -replace '[^A-Za-z0-9_.-]', '_'
                    $certHash = Get-Sha256Hex -Bytes $cert.RawData
                    $certFileName = '{0}-{1:D3}-{2}.cer' -f $safeVariable, $globalEntryIndex, $certHash.Substring(0, 16)
                    $certPath = Join-Path $CertificateDirectory $certFileName
                    [IO.File]::WriteAllBytes($certPath, $cert.RawData)

                    $record.Subject = $cert.Subject
                    $record.Issuer = $cert.Issuer
                    $record.SerialNumber = $cert.SerialNumber
                    $record.NotBeforeUTC = $cert.NotBefore.ToUniversalTime().ToString('o')
                    $record.NotAfterUTC = $cert.NotAfter.ToUniversalTime().ToString('o')
                    $record.CertificateSHA1 = $cert.Thumbprint
                    $record.CertificateSHA256 = $certHash
                    $record.CertificateFile = $certPath
                }
                catch {
                    $record.ParseError = $_.Exception.Message
                }
            }
            elseif ($signatureType -ieq $EfiCertSha256Guid -and $data.Length -eq 32) {
                $record.Kind = 'SHA256'
                $record.HashValue = ([BitConverter]::ToString($data)).Replace('-', '')
            }
            else {
                $record.Kind = 'Binary'
            }

            $entries += [pscustomobject]$record
            $globalEntryIndex++
            $entryOffset += $signatureSize
        }

        $listIndex++
        $offset += $listSize
    }

    return ,$entries
}

function Write-VariableReport {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][object[]] $Entries,
        [Parameter(Mandatory)][string] $Directory
    )

    $safeName = $Name -replace '[^A-Za-z0-9_.-]', '_'
    $binaryPath = Join-Path $Directory "$safeName.bin"
    $jsonPath = Join-Path $Directory "$safeName.json"
    $textPath = Join-Path $Directory "$safeName.txt"

    [IO.File]::WriteAllBytes($binaryPath, $Bytes)
    @($Entries) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $x509 = @($Entries | Where-Object Kind -eq 'X509')
    $sha256Entries = @($Entries | Where-Object Kind -eq 'SHA256')
    $other = @($Entries | Where-Object { $_.Kind -notin @('X509', 'SHA256') })

    $lines = New-Object Collections.Generic.List[string]
    $lines.Add("Variable: $Name")
    $lines.Add("Bytes: $($Bytes.Length)")
    $lines.Add("Payload SHA-256: $(Get-Sha256Hex -Bytes $Bytes)")
    $lines.Add("Entries: $(@($Entries).Count)")
    $lines.Add("X.509 certificates: $($x509.Count)")
    $lines.Add("SHA-256 hashes: $($sha256Entries.Count)")
    $lines.Add("Other entries: $($other.Count)")
    $lines.Add('')

    foreach ($entry in $x509) {
        $lines.Add("Certificate entry $($entry.GlobalEntryIndex)")
        $lines.Add("  Subject:       $($entry.Subject)")
        $lines.Add("  Issuer:        $($entry.Issuer)")
        $lines.Add("  Serial:        $($entry.SerialNumber)")
        $lines.Add("  Valid from:    $($entry.NotBeforeUTC)")
        $lines.Add("  Valid until:   $($entry.NotAfterUTC)")
        $lines.Add("  SHA-1:         $($entry.CertificateSHA1)")
        $lines.Add("  SHA-256:       $($entry.CertificateSHA256)")
        $lines.Add("  Owner GUID:    $($entry.SignatureOwner)")
        $lines.Add("  Exported file: $($entry.CertificateFile)")
        if ($entry.ParseError) {
            $lines.Add("  Parse error:   $($entry.ParseError)")
        }
        $lines.Add('')
    }

    if ($IncludeAllHashEntries) {
        foreach ($entry in $sha256Entries) {
            $lines.Add("Revocation/trust hash entry $($entry.GlobalEntryIndex)")
            $lines.Add("  SHA-256 value: $($entry.HashValue)")
            $lines.Add("  Owner GUID:    $($entry.SignatureOwner)")
            $lines.Add('')
        }
    }
    elseif ($sha256Entries.Count -gt 0) {
        $lines.Add("SHA-256 entry details omitted. Use -IncludeAllHashEntries to print all $($sha256Entries.Count) hashes.")
        $lines.Add('')
    }

    $lines | Set-Content -LiteralPath $textPath -Encoding UTF8

    return [pscustomobject]@{
        Name           = $Name
        Present        = $true
        Bytes          = $Bytes.Length
        PayloadSHA256  = Get-Sha256Hex -Bytes $Bytes
        EntryCount     = @($Entries).Count
        X509Count      = $x509.Count
        SHA256Count    = $sha256Entries.Count
        OtherCount     = $other.Count
        BinaryFile     = $binaryPath
        JsonFile       = $jsonPath
        TextFile       = $textPath
        Entries        = @($Entries)
    }
}

function Resolve-ReferenceFile {
    param(
        [Parameter(Mandatory)][string] $VariableName,
        [string] $ExplicitPath,
        [string] $Root
    )

    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Reference file does not exist: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).ProviderPath
    }

    if (-not $Root) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Reference directory does not exist: $Root"
    }

    $matches = @(
        Get-ChildItem -LiteralPath $Root -File -Recurse |
            Where-Object {
                $_.Extension -match '^\.(bin|esl)$' -and
                $_.BaseName -ieq $VariableName -and
                $_.Name -notmatch '(?i)dbxupdate|\.auth'
            }
    )

    if ($matches.Count -eq 0) {
        return $null
    }

    if ($matches.Count -gt 1) {
        Write-Host "Reference candidates for ${VariableName}:"
        $matches | ForEach-Object { Write-Host "  $($_.FullName)" }
        throw "More than one reference file matched $VariableName. Pass an explicit path."
    }

    return $matches[0].FullName
}

function Compare-SignatureEntries {
    param(
        [Parameter(Mandatory)][string] $VariableName,
        [Parameter(Mandatory)][object[]] $InstalledEntries,
        [Parameter(Mandatory)][object[]] $ReferenceEntries
    )

    # EntryDataSHA256 compares the exact signature data:
    # DER certificate bytes for X.509 entries, or the raw hash bytes for hash entries.
    $installedMap = @{}
    foreach ($entry in @($InstalledEntries)) {
        $installedMap[$entry.EntryDataSHA256] = $entry
    }

    $referenceMap = @{}
    foreach ($entry in @($ReferenceEntries)) {
        $referenceMap[$entry.EntryDataSHA256] = $entry
    }

    $missing = @(
        foreach ($hash in $referenceMap.Keys) {
            if (-not $installedMap.ContainsKey($hash)) {
                $referenceMap[$hash]
            }
        }
    )

    $extra = @(
        foreach ($hash in $installedMap.Keys) {
            if (-not $referenceMap.ContainsKey($hash)) {
                $installedMap[$hash]
            }
        }
    )

    $common = @(
        foreach ($hash in $referenceMap.Keys) {
            if ($installedMap.ContainsKey($hash)) {
                $installedMap[$hash]
            }
        }
    )

    return [pscustomobject]@{
        Variable        = $VariableName
        InstalledCount  = @($InstalledEntries).Count
        ReferenceCount  = @($ReferenceEntries).Count
        CommonCount     = $common.Count
        MissingCount    = $missing.Count
        ExtraCount      = $extra.Count
        ExactEntryMatch = ($missing.Count -eq 0 -and $extra.Count -eq 0)
        Missing         = $missing
        Extra           = $extra
    }
}

function Format-EntryIdentity {
    param([Parameter(Mandatory)] $Entry)

    if ($Entry.Kind -eq 'X509') {
        return "$($Entry.Subject) [SHA256 $($Entry.CertificateSHA256)]"
    }

    if ($Entry.Kind -eq 'SHA256') {
        return "SHA256 hash $($Entry.HashValue)"
    }

    return "$($Entry.Kind) entry [data SHA256 $($Entry.EntryDataSHA256)]"
}

Write-Stage 'Checking environment'

if (-not (Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)) {
    throw 'Get-SecureBootUEFI is unavailable. Run elevated 64-bit Windows PowerShell on a UEFI system.'
}

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    throw 'Run 64-bit Windows PowerShell.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$certDirectory = Join-Path $resolvedOutput 'certificates'
$referenceOutput = Join-Path $resolvedOutput 'reference'
New-Item -ItemType Directory -Path $certDirectory -Force | Out-Null

Write-Host "Output directory: $resolvedOutput"

Write-Stage 'Reading Secure Boot state'

$state = [ordered]@{}
foreach ($name in @('SetupMode', 'SecureBoot', 'AuditMode', 'DeployedMode', 'VendorKeys')) {
    $bytes = Get-SecureBootVariableBytes -Name $name
    if ($null -ne $bytes -and @($bytes).Count -gt 0) {
        $state[$name] = [int]$bytes[0]
        Write-Host "${name}: $($state[$name])"
    }
    else {
        $state[$name] = $null
        Write-Host "${name}: unavailable"
    }
}

$state | ConvertTo-Json | Set-Content `
    -LiteralPath (Join-Path $resolvedOutput 'secureboot-state.json') `
    -Encoding UTF8

Write-Stage 'Exporting active and default variables'

$variableNames = @(
    'PK',
    'KEK',
    'db',
    'dbx',
    'PKDefault',
    'KEKDefault',
    'dbDefault',
    'dbxDefault'
)

$exports = @{}

foreach ($name in $variableNames) {
    $bytes = Get-SecureBootVariableBytes -Name $name

    if ($null -eq $bytes -or @($bytes).Count -eq 0) {
        Write-Host "${name}: not present"
        $exports[$name] = [pscustomobject]@{
            Name    = $name
            Present = $false
        }
        continue
    }

    try {
        $entries = ConvertFrom-EfiSignatureList `
            -Bytes $bytes `
            -VariableName $name `
            -CertificateDirectory $certDirectory

        $report = Write-VariableReport `
            -Name $name `
            -Bytes $bytes `
            -Entries $entries `
            -Directory $resolvedOutput

        $exports[$name] = $report

        Write-Host (
            '{0,-10} {1,8:N0} bytes  {2,4} entries  {3,2} certs  SHA256={4}' -f
            $name,
            $report.Bytes,
            $report.EntryCount,
            $report.X509Count,
            $report.PayloadSHA256
        )
    }
    catch {
        Write-Warning "$name could not be parsed: $($_.Exception.Message)"

        $safeName = $name -replace '[^A-Za-z0-9_.-]', '_'
        $binaryPath = Join-Path $resolvedOutput "$safeName.bin"
        [IO.File]::WriteAllBytes($binaryPath, $bytes)

        $exports[$name] = [pscustomobject]@{
            Name          = $name
            Present       = $true
            Bytes         = $bytes.Length
            PayloadSHA256 = Get-Sha256Hex -Bytes $bytes
            BinaryFile    = $binaryPath
            ParseError    = $_.Exception.Message
            Entries       = @()
        }
    }
}

$summary = @(
    foreach ($name in $variableNames) {
        $item = $exports[$name]
        [pscustomobject]@{
            Name          = $name
            Present       = $item.Present
            Bytes         = if ($item.Present -and $item.PSObject.Properties.Name -contains 'Bytes') { $item.Bytes } else { $null }
            PayloadSHA256 = if ($item.Present -and $item.PSObject.Properties.Name -contains 'PayloadSHA256') { $item.PayloadSHA256 } else { $null }
            EntryCount    = if ($item.Present -and $item.PSObject.Properties.Name -contains 'EntryCount') { $item.EntryCount } else { $null }
            X509Count     = if ($item.Present -and $item.PSObject.Properties.Name -contains 'X509Count') { $item.X509Count } else { $null }
            SHA256Count   = if ($item.Present -and $item.PSObject.Properties.Name -contains 'SHA256Count') { $item.SHA256Count } else { $null }
        }
    }
)

$summary |
    Export-Csv -LiteralPath (Join-Path $resolvedOutput 'variable-summary.csv') -NoTypeInformation

$summary |
    Format-Table -AutoSize |
    Out-String -Width 240 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput 'variable-summary.txt') -Encoding UTF8

Write-Stage 'Comparing active variables with firmware defaults'

$defaultPairs = @(
    @{Active='PK';  Default='PKDefault'},
    @{Active='KEK'; Default='KEKDefault'},
    @{Active='db';  Default='dbDefault'},
    @{Active='dbx'; Default='dbxDefault'}
)

$defaultComparisons = @()

foreach ($pair in $defaultPairs) {
    $active = $exports[$pair.Active]
    $default = $exports[$pair.Default]

    if (-not $active.Present -or -not $default.Present -or
        -not ($active.PSObject.Properties.Name -contains 'Entries') -or
        -not ($default.PSObject.Properties.Name -contains 'Entries')) {
        Write-Host "$($pair.Active) vs $($pair.Default): comparison unavailable"
        continue
    }

    $comparison = Compare-SignatureEntries `
        -VariableName $pair.Active `
        -InstalledEntries @($active.Entries) `
        -ReferenceEntries @($default.Entries)

    $defaultComparisons += $comparison

    Write-Host (
        '{0,-4} vs {1,-10}: exact={2}, common={3}, missing={4}, extra={5}' -f
        $pair.Active,
        $pair.Default,
        $comparison.ExactEntryMatch,
        $comparison.CommonCount,
        $comparison.MissingCount,
        $comparison.ExtraCount
    )
}

$defaultComparisons |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput 'active-vs-default.json') -Encoding UTF8

Write-Stage 'Optional reference payload comparison'

$referencePaths = [ordered]@{
    PK  = Resolve-ReferenceFile -VariableName 'PK'  -ExplicitPath $ReferencePk  -Root $ReferenceDirectory
    KEK = Resolve-ReferenceFile -VariableName 'KEK' -ExplicitPath $ReferenceKek -Root $ReferenceDirectory
    db  = Resolve-ReferenceFile -VariableName 'DB'  -ExplicitPath $ReferenceDb  -Root $ReferenceDirectory
    dbx = Resolve-ReferenceFile -VariableName 'DBX' -ExplicitPath $ReferenceDbx -Root $ReferenceDirectory
}

$hasReference = $false
foreach ($path in $referencePaths.Values) {
    if ($path) {
        $hasReference = $true
        break
    }
}

if ($hasReference) {
    New-Item -ItemType Directory -Path $referenceOutput -Force | Out-Null
    $referenceCertDirectory = Join-Path $referenceOutput 'certificates'
    New-Item -ItemType Directory -Path $referenceCertDirectory -Force | Out-Null

    $referenceComparisons = @()

    foreach ($name in @('PK', 'KEK', 'db', 'dbx')) {
        $path = $referencePaths[$name]

        if (-not $path) {
            Write-Host "$name reference: not provided/found"
            continue
        }

        if (-not $exports[$name].Present) {
            Write-Host "$name reference: active variable is absent"
            continue
        }

        $referenceBytes = [IO.File]::ReadAllBytes($path)
        $referenceEntries = ConvertFrom-EfiSignatureList `
            -Bytes $referenceBytes `
            -VariableName "reference-$name" `
            -CertificateDirectory $referenceCertDirectory

        $referenceReport = Write-VariableReport `
            -Name "reference-$name" `
            -Bytes $referenceBytes `
            -Entries $referenceEntries `
            -Directory $referenceOutput

        $comparison = Compare-SignatureEntries `
            -VariableName $name `
            -InstalledEntries @($exports[$name].Entries) `
            -ReferenceEntries @($referenceReport.Entries)

        $referenceComparisons += $comparison

        Write-Host (
            '{0,-4}: exact={1}, common={2}, missing from installed={3}, extra installed={4}' -f
            $name,
            $comparison.ExactEntryMatch,
            $comparison.CommonCount,
            $comparison.MissingCount,
            $comparison.ExtraCount
        )

        if ($comparison.MissingCount -gt 0) {
            Write-Host '  Missing from installed:' -ForegroundColor Yellow
            foreach ($entry in @($comparison.Missing)) {
                Write-Host "    $(Format-EntryIdentity -Entry $entry)"
            }
        }

        if ($comparison.ExtraCount -gt 0) {
            Write-Host '  Extra in installed:' -ForegroundColor Yellow
            foreach ($entry in @($comparison.Extra)) {
                Write-Host "    $(Format-EntryIdentity -Entry $entry)"
            }
        }
    }

    $referenceComparisons |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $resolvedOutput 'installed-vs-reference.json') -Encoding UTF8
}
else {
    Write-Host 'No reference payloads supplied; reference comparison skipped.'
}

Write-Stage 'Complete'

Write-Host "Reports written to: $resolvedOutput" -ForegroundColor Green
Write-Host
Write-Host 'Most useful files:'
Write-Host "  $(Join-Path $resolvedOutput 'variable-summary.txt')"
Write-Host "  $(Join-Path $resolvedOutput 'KEK.txt')"
Write-Host "  $(Join-Path $resolvedOutput 'db.txt')"
Write-Host "  $(Join-Path $resolvedOutput 'active-vs-default.json')"
if ($hasReference) {
    Write-Host "  $(Join-Path $resolvedOutput 'installed-vs-reference.json')"
}
