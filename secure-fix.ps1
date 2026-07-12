#Requires -Version 5.1
#Requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-or-later
#
# SecureBoot-Merge.ps1
# Copyright (C) 2026 Damian Wright
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

<#
.SYNOPSIS
    Extract the machine's original Secure Boot keys, or provision a merged
    Microsoft + manufacturer Secure Boot policy and restore the original
    Platform Key.

.MODES
    -Extract
        Downloads and verifies a Microsoft unsigned firmware payload.
        Reads the currently installed KEK and db.
        Removes entries already present in the Microsoft baseline.
        Saves the remaining machine/platform-specific entries in:
            Original-PK.esl
            OEM-KEK.esl
            OEM-db.esl
            extracted-keys-manifest.json
    -Provision
        Downloads the Microsoft baseline recorded during extraction.
        Uses Microsoft's dbx exactly as published.
        Merges Microsoft's KEK and db with the extracted OEM KEK/db entries.
        Restores the original extracted Platform Key last.

        Extraction saves the active PK when present; otherwise it saves
        PKDefault. Provisioning requires that extracted PK and will not
        generate a replacement Platform Key.

        Some firmware exposes SetupMode=1 until the next reboot even after PK
        was accepted. PK presence is therefore treated as success, with a
        reboot-required warning when the mode transition is deferred.

.NOTES
    Version: 1.0.0
    Author: Damian Wright
    License: GPL-3.0-or-later

    Run in elevated 64-bit Windows PowerShell 5.1.
    Firmware must be in Setup Mode for Provision.
    Provision restores the original extracted Platform Key last.

.EXAMPLES
    .\SecureBoot-Merge.ps1 -Extract -ReleaseTag v1.6.5

    .\SecureBoot-Merge.ps1 -Provision

    .\SecureBoot-Merge.ps1 -Provision `
        -KeyPackageDirectory E:\SecureBoot-OEM
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Extract', Mandatory)]
    [switch] $Extract,

    [Parameter(ParameterSetName = 'Provision', Mandatory)]
    [switch] $Provision,

    [Parameter(ParameterSetName = 'Extract', Mandatory)]
    [string] $ReleaseTag,

    [Parameter()]
    [ValidateSet('x64', 'ia32', 'aarch64', 'arm')]
    [string] $Architecture = 'x64',

    [Parameter()]
    [ValidateSet('MicrosoftAndThirdParty', 'MicrosoftAndOptionRoms', 'MicrosoftOnly')]
    [string] $Policy = 'MicrosoftAndThirdParty',

    [Parameter()]
    [ValidateSet('Firmware')]
    [string] $PayloadClass = 'Firmware',

    [Parameter()]
    [string] $DownloadDirectory = (
        Join-Path $PSScriptRoot 'MicrosoftSecureBootObjects'
    ),

    [Parameter()]
    [string] $KeyPackageDirectory = (
        Join-Path $PSScriptRoot 'ExtractedSecureBootKeys'
    ),

    [Parameter()]
    [string] $BackupDirectory = (
        Join-Path $PSScriptRoot (
            'SecureBootBackup-{0:yyyyMMdd-HHmmss}' -f (Get-Date)
        )
    ),

    [Parameter()]
    [switch] $ForceUnverifiedAssetDigest,

    [Parameter()]
    [switch] $ShowAllEntries
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$EfiCertX509Guid = 'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$EfiCertSha256Guid = 'c1c41626-504c-4092-aca9-41f936934328'

function Write-Stage {
    param([Parameter(Mandatory)][string] $Text)

    Write-Host
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Confirm-Yes {
    param([Parameter(Mandatory)][string] $Prompt)

    $answer = (Read-Host "$Prompt [y/yes]").Trim()

    return ($answer -match '^(?i:y|yes)$')
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (
            [BitConverter]::ToString($sha.ComputeHash($Bytes))
        ).Replace('-', '').ToUpperInvariant()
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

function Convert-GuidToEfiBytes {
    param([Parameter(Mandatory)][string] $Guid)

    return ([Guid]$Guid).ToByteArray()
}

function Get-DerObjectLength {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    if ($Bytes.Length -lt 2 -or $Bytes[0] -ne 0x30) {
        throw 'Entry does not start with a DER ASN.1 SEQUENCE.'
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
            $contentLength =
                ($contentLength -shl 8) -bor
                [int]$Bytes[2 + $i]
        }
    }

    $totalLength = $headerLength + $contentLength

    if ($totalLength -gt $Bytes.Length) {
        throw (
            "DER object claims $totalLength bytes, but entry has " +
            "$($Bytes.Length)."
        )
    }

    return $totalLength
}

function ConvertFrom-EfiSignatureList {
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][string] $Label
    )

    if ($Bytes.Length -lt 28) {
        throw "$Label is too small to contain an EFI_SIGNATURE_LIST."
    }

    $offset = 0
    $listIndex = 0
    $globalEntryIndex = 0
    $entries = @()

    while ($offset -lt $Bytes.Length) {
        if (($Bytes.Length - $offset) -lt 28) {
            throw "$Label has a truncated list header at offset $offset."
        }

        $signatureType =
            Convert-EfiGuidBytesToGuid -Bytes $Bytes -Offset $offset

        $listSize =
            Get-U32LE -Bytes $Bytes -Offset ($offset + 16)

        $headerSize =
            Get-U32LE -Bytes $Bytes -Offset ($offset + 20)

        $signatureSize =
            Get-U32LE -Bytes $Bytes -Offset ($offset + 24)

        if ($listSize -lt 28) {
            throw "$Label list $listIndex has invalid size $listSize."
        }

        if (($offset + $listSize) -gt $Bytes.Length) {
            throw "$Label list $listIndex extends beyond the payload."
        }

        if ($signatureSize -lt 16) {
            throw (
                "$Label list $listIndex has invalid SignatureSize " +
                "$signatureSize."
            )
        }

        $entryAreaSize =
            [int64]$listSize - 28 - [int64]$headerSize

        if ($entryAreaSize -lt 0 -or
            ($entryAreaSize % $signatureSize) -ne 0) {

            throw "$Label list $listIndex has inconsistent size fields."
        }

        $headerBytes = New-Object byte[] $headerSize
        if ($headerSize -gt 0) {
            [Array]::Copy(
                $Bytes,
                $offset + 28,
                $headerBytes,
                0,
                $headerSize
            )
        }

        $entryCount = [int]($entryAreaSize / $signatureSize)
        $entryOffset = $offset + 28 + $headerSize

        for ($entryIndex = 0;
             $entryIndex -lt $entryCount;
             $entryIndex++) {

            $ownerGuid =
                Convert-EfiGuidBytesToGuid `
                    -Bytes $Bytes `
                    -Offset $entryOffset

            $signatureBytes = New-Object byte[] $signatureSize
            [Array]::Copy(
                $Bytes,
                $entryOffset,
                $signatureBytes,
                0,
                $signatureSize
            )

            $dataLength = [int]$signatureSize - 16
            $data = New-Object byte[] $dataLength
            [Array]::Copy(
                $Bytes,
                $entryOffset + 16,
                $data,
                0,
                $dataLength
            )

            $entry = [ordered]@{
                Label              = $Label
                ListIndex          = $listIndex
                EntryIndex         = $entryIndex
                GlobalEntryIndex   = $globalEntryIndex
                SignatureTypeGuid  = $signatureType
                SignatureOwner     = $ownerGuid
                SignatureSize      = [int]$signatureSize
                HeaderBytes        = $headerBytes
                SignatureBytes     = $signatureBytes
                EntryData          = $data
                EntryDataSHA256    = Get-Sha256Hex -Bytes $data
                Kind               = 'Binary'
                Subject            = $null
                Issuer             = $null
                SerialNumber       = $null
                NotBeforeUTC       = $null
                NotAfterUTC        = $null
                CertificateSHA256  = $null
                HashValue          = $null
                ParseError         = $null
            }

            if ($signatureType -ieq $EfiCertX509Guid) {
                $entry.Kind = 'X509'

                try {
                    $derLength = Get-DerObjectLength -Bytes $data
                    $certBytes = New-Object byte[] $derLength
                    [Array]::Copy(
                        $data,
                        0,
                        $certBytes,
                        0,
                        $derLength
                    )

                    $cert = New-Object `
                        System.Security.Cryptography.X509Certificates.X509Certificate2 `
                        -ArgumentList @(,$certBytes)

                    $entry.Subject = $cert.Subject
                    $entry.Issuer = $cert.Issuer
                    $entry.SerialNumber = $cert.SerialNumber
                    $entry.NotBeforeUTC =
                        $cert.NotBefore.ToUniversalTime().ToString('o')
                    $entry.NotAfterUTC =
                        $cert.NotAfter.ToUniversalTime().ToString('o')
                    $entry.CertificateSHA256 =
                        Get-Sha256Hex -Bytes $cert.RawData
                }
                catch {
                    $entry.ParseError = $_.Exception.Message
                }
            }
            elseif ($signatureType -ieq $EfiCertSha256Guid -and
                    $data.Length -eq 32) {

                $entry.Kind = 'SHA256'
                $entry.HashValue =
                    ([BitConverter]::ToString($data)).Replace('-', '')
            }

            $entries += [pscustomobject]$entry
            $globalEntryIndex++
            $entryOffset += $signatureSize
        }

        $listIndex++
        $offset += $listSize
    }

    return ,$entries
}

function ConvertTo-EfiSignatureList {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Entries
    )

    if (@($Entries).Count -eq 0) {
        return ,([byte[]]@())
    }

    $stream = New-Object IO.MemoryStream

    try {
        foreach ($entry in @($Entries)) {
            $signatureTypeBytes =
                Convert-GuidToEfiBytes -Guid $entry.SignatureTypeGuid

            $headerBytes = [byte[]]@($entry.HeaderBytes)
            $signatureBytes = [byte[]]@($entry.SignatureBytes)

            if ($signatureBytes.Length -ne [int]$entry.SignatureSize) {
                throw 'Signature entry size changed during reconstruction.'
            }

            # Create one EFI_SIGNATURE_LIST per entry. This is valid for all
            # supported entry types and avoids size compatibility assumptions.
            $listSize =
                [uint32](28 + $headerBytes.Length + $signatureBytes.Length)

            $stream.Write($signatureTypeBytes, 0, 16)

            $u32 = [BitConverter]::GetBytes($listSize)
            $stream.Write($u32, 0, 4)

            $u32 =
                [BitConverter]::GetBytes([uint32]$headerBytes.Length)
            $stream.Write($u32, 0, 4)

            $u32 =
                [BitConverter]::GetBytes(
                    [uint32]$signatureBytes.Length
                )
            $stream.Write($u32, 0, 4)

            if ($headerBytes.Length -gt 0) {
                $stream.Write(
                    $headerBytes,
                    0,
                    $headerBytes.Length
                )
            }

            $stream.Write(
                $signatureBytes,
                0,
                $signatureBytes.Length
            )
        }

        return ,$stream.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-UniqueEntries {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Entries
    )

    $seen = @{}
    $unique = @()

    foreach ($entry in @($Entries)) {
        # Authority is determined by signature data. Ignore owner GUID when
        # deduplicating the same certificate/hash from different sources.
        $key =
            "$($entry.SignatureTypeGuid)|$($entry.EntryDataSHA256)"

        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $unique += $entry
        }
    }

    return ,$unique
}

function Format-EntryIdentity {
    param([Parameter(Mandatory)] $Entry)

    if ($Entry.Kind -eq 'X509') {
        return (
            "$($Entry.Subject) " +
            "[SHA256 $($Entry.CertificateSHA256)]"
        )
    }

    if ($Entry.Kind -eq 'SHA256') {
        return "SHA256 hash $($Entry.HashValue)"
    }

    return (
        "$($Entry.Kind) entry " +
        "[data SHA256 $($Entry.EntryDataSHA256)]"
    )
}

function Show-EntrySummary {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][object[]] $Entries
    )

    Write-Host
    Write-Host "$Name entries: $(@($Entries).Count)"

    foreach ($entry in @($Entries)) {
        if ($entry.Kind -eq 'SHA256' -and -not $ShowAllEntries) {
            continue
        }

        Write-Host "  $(Format-EntryIdentity -Entry $entry)"
    }

    $hiddenHashes = @(
        $Entries |
            Where-Object Kind -eq 'SHA256'
    ).Count

    if ($hiddenHashes -gt 0 -and -not $ShowAllEntries) {
        Write-Host (
            "  $hiddenHashes SHA-256 entries omitted; " +
            'use -ShowAllEntries to display them.'
        )
    }
}

function Get-SecureBootBytes {
    param([Parameter(Mandatory)][string] $Name)

    try {
        return ,([byte[]]@(
            (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).Bytes
        ))
    }
    catch {
        return $null
    }
}

function Get-SecureBootByte {
    param([Parameter(Mandatory)][string] $Name)

    $bytes = Get-SecureBootBytes -Name $Name

    if ($null -eq $bytes -or @($bytes).Count -lt 1) {
        throw "UEFI variable '$Name' is unavailable."
    }

    return [int]([byte[]]$bytes)[0]
}

function Get-GitHubUnsignedRelease {
    param([string] $Tag)

    $headers = @{
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'SecureBoot-Merge'
    }

    $base =
        'https://api.github.com/repos/microsoft/secureboot_objects'

    if ($Tag) {
        if ($Tag -match '-signed$') {
            throw (
                "Tag '$Tag' is a signed runtime release. " +
                'Use the unsigned firmware release.'
            )
        }

        $release =
            Invoke-RestMethod `
                -Uri "$base/releases/tags/$Tag" `
                -Headers $headers
    }
    else {
        # Force the REST response into a PowerShell array before
        # filtering. Without @(...), Windows PowerShell can treat the entire
        # JSON release collection as one pipeline object.
        $releases = @(
            Invoke-RestMethod `
                -Uri "$base/releases?per_page=100" `
                -Headers $headers
        )

        $release =
            $releases |
            Where-Object {
                -not $_.draft -and
                -not $_.prerelease -and
                $_.tag_name -notmatch '-signed$'
            } |
            Sort-Object {
                [datetime]$_.published_at
            } -Descending |
            Select-Object -First 1
    }

    if (-not $release) {
        throw 'No unsigned Microsoft Secure Boot release was found.'
    }

    if ($release.tag_name -match '-signed$') {
        throw 'Refusing a signed runtime release.'
    }

    return $release
}

function Download-And-VerifyRelease {
    param(
        [string] $Tag,
        [string] $Destination,
        [string] $Architecture
    )

    Write-Stage 'Selecting Microsoft unsigned firmware release'

    $release = Get-GitHubUnsignedRelease -Tag $Tag

    Write-Host "Release:      $($release.tag_name)"
    Write-Host "Published:    $($release.published_at)"
    Write-Host "Architecture: $Architecture"

    $expectedAssetName =
        "edk2-$Architecture-secureboot-binaries.zip"

    $assets = @(
        $release.assets |
            Where-Object Name -eq $expectedAssetName
    )

    if ($assets.Count -ne 1) {
        Write-Host 'Release assets:'
        $release.assets |
            ForEach-Object {
                Write-Host "  $($_.name)"
            }

        throw (
            "Expected exactly one '$expectedAssetName' asset; " +
            "found $($assets.Count)."
        )
    }

    $asset = $assets[0]
    $releaseDirectory =
        Join-Path $Destination $release.tag_name
    $archivePath =
        Join-Path $Destination $asset.name

    New-Item `
        -ItemType Directory `
        -Path $Destination `
        -Force |
        Out-Null

    Write-Stage 'Downloading and verifying release asset'
    Write-Host "Asset: $($asset.name)"

    Invoke-WebRequest `
        -Uri $asset.browser_download_url `
        -OutFile $archivePath `
        -UseBasicParsing `
        -Headers @{
            'User-Agent' = 'SecureBoot-Merge'
        }

    $actualHash =
        (Get-FileHash `
            -LiteralPath $archivePath `
            -Algorithm SHA256).Hash.ToUpperInvariant()

    Write-Host "Downloaded SHA256: $actualHash"

    $digestVerified = $false

    if ($asset.PSObject.Properties.Name -contains 'digest' -and
        $asset.digest) {

        if ($asset.digest -notmatch
            '^sha256:([0-9a-fA-F]{64})$') {

            throw (
                "Unsupported GitHub asset digest " +
                "'$($asset.digest)'."
            )
        }

        $expectedHash = $Matches[1].ToUpperInvariant()

        if ($expectedHash -ne $actualHash) {
            throw (
                'Asset digest mismatch. ' +
                "Expected=$expectedHash Actual=$actualHash"
            )
        }

        $digestVerified = $true
        Write-Host (
            'GitHub-published asset SHA-256 verified.'
        ) -ForegroundColor Green
    }
    elseif (-not $ForceUnverifiedAssetDigest) {
        throw (
            'GitHub did not publish an asset digest. ' +
            'Use -ForceUnverifiedAssetDigest only after ' +
            'independently checking the archive hash.'
        )
    }
    else {
        Write-Warning 'Asset digest was not independently verified.'
    }

    if (Test-Path -LiteralPath $releaseDirectory) {
        Remove-Item `
            -LiteralPath $releaseDirectory `
            -Recurse `
            -Force
    }

    New-Item `
        -ItemType Directory `
        -Path $releaseDirectory `
        -Force |
        Out-Null

    Expand-Archive `
        -LiteralPath $archivePath `
        -DestinationPath $releaseDirectory `
        -Force

    return [pscustomobject]@{
        ReleaseTag      = $release.tag_name
        Published       = $release.published_at
        AssetName       = $asset.name
        AssetSHA256     = $actualHash
        DigestVerified  = $digestVerified
        ExtractPath     = $releaseDirectory
    }
}

function Find-MicrosoftPayloadSet {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Policy,
        [Parameter(Mandatory)][string] $PayloadClass
    )

    $payloadPath =
        Join-Path `
            (Join-Path $Root $Policy) `
            $PayloadClass

    if (-not (Test-Path `
        -LiteralPath $payloadPath `
        -PathType Container)) {

        throw "Microsoft payload path does not exist: $payloadPath"
    }

    function Find-OneFile {
        param([Parameter(Mandatory)][string] $BaseName)

        $matches = @(
            Get-ChildItem `
                -LiteralPath $payloadPath `
                -File |
            Where-Object {
                $_.BaseName -ieq $BaseName -and
                $_.Extension -match '^\.(bin|esl)$'
            }
        )

        if ($matches.Count -ne 1) {
            Write-Host "Candidates for ${BaseName}:"
            $matches |
                ForEach-Object {
                    Write-Host "  $($_.FullName)"
                }

            throw (
                "Expected exactly one raw $BaseName payload; " +
                "found $($matches.Count)."
            )
        }

        return $matches[0]
    }

    Write-Host "Policy:       $Policy"
    Write-Host "Payload type: $PayloadClass"
    Write-Host "Payload path: $payloadPath"

    return [pscustomobject]@{
        dbx = Find-OneFile -BaseName 'DBX'
        db  = Find-OneFile -BaseName 'DB'
        KEK = Find-OneFile -BaseName 'KEK'
    }
}

function Read-MicrosoftPayloadSet {
    param([Parameter(Mandatory)] $Set)

    $result = [ordered]@{}

    foreach ($name in @('dbx', 'db', 'KEK')) {
        $file = $Set.$name
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        $entries =
            ConvertFrom-EfiSignatureList `
                -Bytes $bytes `
                -Label "Microsoft-$name"

        $result[$name] = [pscustomobject]@{
            File       = $file.FullName
            Bytes      = $bytes
            SHA256     = Get-Sha256Hex -Bytes $bytes
            Entries    = @($entries)
        }

        Write-Host (
            '{0,-4} {1,9:N0} bytes  {2,4} entries  SHA256={3}' -f
            $name,
            $bytes.Length,
            @($entries).Count,
            $result[$name].SHA256
        )

        if ($name -ne 'dbx' -or $ShowAllEntries) {
            Show-EntrySummary `
                -Name "Microsoft $name" `
                -Entries @($entries)
        }
    }

    return [pscustomobject]$result
}

function Write-KeyPackage {
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][object[]] $OemKekEntries,
        [Parameter(Mandatory)][object[]] $OemDbEntries,
        [Parameter(Mandatory)][byte[]] $OriginalPkBytes,
        [Parameter(Mandatory)][string] $OriginalPkSource,
        [Parameter(Mandatory)] $Download,
        [Parameter(Mandatory)] $MicrosoftPayloads
    )

    New-Item `
        -ItemType Directory `
        -Path $Directory `
        -Force |
        Out-Null

    $resolved =
        (Resolve-Path -LiteralPath $Directory).ProviderPath

    $oemKekBytes =
        ConvertTo-EfiSignatureList `
            -Entries @($OemKekEntries)

    $oemDbBytes =
        ConvertTo-EfiSignatureList `
            -Entries @($OemDbEntries)

    $pkPath = Join-Path $resolved 'Original-PK.esl'
    $kekPath = Join-Path $resolved 'OEM-KEK.esl'
    $dbPath = Join-Path $resolved 'OEM-db.esl'

    [IO.File]::WriteAllBytes($pkPath, $OriginalPkBytes)
    [IO.File]::WriteAllBytes($kekPath, $oemKekBytes)
    [IO.File]::WriteAllBytes($dbPath, $oemDbBytes)

    $manifest = [ordered]@{
        SchemaVersion = 1
        CreatedUTC =
            (Get-Date).ToUniversalTime().ToString('o')
        ComputerName = $env:COMPUTERNAME
        Firmware = [ordered]@{
            Manufacturer =
                (Get-CimInstance Win32_ComputerSystem).Manufacturer
            Model =
                (Get-CimInstance Win32_ComputerSystem).Model
            BiosSerial =
                (Get-CimInstance Win32_BIOS).SerialNumber
            BiosVersion =
                (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
        }
        MicrosoftBaseline = [ordered]@{
            ReleaseTag = $Download.ReleaseTag
            AssetName = $Download.AssetName
            AssetSHA256 = $Download.AssetSHA256
            Policy = $Policy
            PayloadClass = $PayloadClass
            Architecture = $Architecture
            KEKSHA256 = $MicrosoftPayloads.KEK.SHA256
            dbSHA256 = $MicrosoftPayloads.db.SHA256
            dbxSHA256 = $MicrosoftPayloads.dbx.SHA256
        }
        OriginalPlatformKey = [ordered]@{
            Source = $OriginalPkSource
            File = $pkPath
            Bytes = $OriginalPkBytes.Length
            SHA256 = Get-Sha256Hex -Bytes $OriginalPkBytes
        }
        Extracted = [ordered]@{
            OemKekEntries = @($OemKekEntries).Count
            OemDbEntries = @($OemDbEntries).Count
            OemKekFile = $kekPath
            OemDbFile = $dbPath
            OemKekSHA256 = Get-Sha256Hex -Bytes $oemKekBytes
            OemDbSHA256 = Get-Sha256Hex -Bytes $oemDbBytes
            KEK = @(
                foreach ($entry in @($OemKekEntries)) {
                    [ordered]@{
                        Kind = $entry.Kind
                        Subject = $entry.Subject
                        Issuer = $entry.Issuer
                        SignatureTypeGuid =
                            $entry.SignatureTypeGuid
                        SignatureOwner =
                            $entry.SignatureOwner
                        EntryDataSHA256 =
                            $entry.EntryDataSHA256
                    }
                }
            )
            db = @(
                foreach ($entry in @($OemDbEntries)) {
                    [ordered]@{
                        Kind = $entry.Kind
                        Subject = $entry.Subject
                        Issuer = $entry.Issuer
                        SignatureTypeGuid =
                            $entry.SignatureTypeGuid
                        SignatureOwner =
                            $entry.SignatureOwner
                        EntryDataSHA256 =
                            $entry.EntryDataSHA256
                    }
                }
            )
        }
    }

    $manifestPath =
        Join-Path $resolved 'extracted-keys-manifest.json'

    $manifest |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $manifestPath `
            -Encoding UTF8

    $reportLines = New-Object Collections.Generic.List[string]
    $reportLines.Add(
        "Machine: $($manifest.Firmware.Manufacturer) " +
        "$($manifest.Firmware.Model)"
    )
    $reportLines.Add(
        "BIOS serial: $($manifest.Firmware.BiosSerial)"
    )
    $reportLines.Add(
        "Microsoft baseline: $($Download.ReleaseTag), " +
        "$Policy/$PayloadClass/$Architecture"
    )
    $reportLines.Add('')
    $reportLines.Add("Original PK source: $OriginalPkSource")
    $reportLines.Add(
        "Original PK SHA256: $(Get-Sha256Hex -Bytes $OriginalPkBytes)"
    )
    $reportLines.Add('')
    $reportLines.Add(
        "Extracted KEK entries: $(@($OemKekEntries).Count)"
    )

    foreach ($entry in @($OemKekEntries)) {
        $reportLines.Add(
            "  $(Format-EntryIdentity -Entry $entry)"
        )
    }

    $reportLines.Add('')
    $reportLines.Add(
        "Extracted db entries: $(@($OemDbEntries).Count)"
    )

    foreach ($entry in @($OemDbEntries)) {
        $reportLines.Add(
            "  $(Format-EntryIdentity -Entry $entry)"
        )
    }

    $reportPath =
        Join-Path $resolved 'extracted-keys-report.txt'

    $reportLines |
        Set-Content `
            -LiteralPath $reportPath `
            -Encoding UTF8

    return [pscustomobject]@{
        Directory = $resolved
        PkPath = $pkPath
        KekPath = $kekPath
        DbPath = $dbPath
        ManifestPath = $manifestPath
        ReportPath = $reportPath
    }
}

function Read-KeyPackage {
    param([Parameter(Mandatory)][string] $Directory)

    if (-not (Test-Path `
        -LiteralPath $Directory `
        -PathType Container)) {

        return $null
    }

    $pkPath = Join-Path $Directory 'Original-PK.esl'
    $kekPath = Join-Path $Directory 'OEM-KEK.esl'
    $dbPath = Join-Path $Directory 'OEM-db.esl'
    $manifestPath =
        Join-Path $Directory 'extracted-keys-manifest.json'

    if (-not (Test-Path -LiteralPath $pkPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $kekPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dbPath -PathType Leaf) -or
        -not (Test-Path `
            -LiteralPath $manifestPath `
            -PathType Leaf)) {

        return $null
    }

    $pkBytes = [IO.File]::ReadAllBytes($pkPath)
    $kekBytes = [IO.File]::ReadAllBytes($kekPath)
    $dbBytes = [IO.File]::ReadAllBytes($dbPath)

    $kekEntries = @()
    if ($kekBytes.Length -gt 0) {
        $kekEntries =
            ConvertFrom-EfiSignatureList `
                -Bytes $kekBytes `
                -Label 'Extracted-OEM-KEK'
    }

    $dbEntries = @()
    if ($dbBytes.Length -gt 0) {
        $dbEntries =
            ConvertFrom-EfiSignatureList `
                -Bytes $dbBytes `
                -Label 'Extracted-OEM-db'
    }

    $manifest =
        Get-Content `
            -LiteralPath $manifestPath `
            -Raw |
        ConvertFrom-Json

    return [pscustomobject]@{
        Directory = (Resolve-Path $Directory).ProviderPath
        PkBytes = $pkBytes
        KekBytes = $kekBytes
        DbBytes = $dbBytes
        KekEntries = @($kekEntries)
        DbEntries = @($dbEntries)
        Manifest = $manifest
    }
}

function Compare-Against-MicrosoftBaseline {
    param(
        [Parameter(Mandatory)][object[]] $InstalledEntries,
        [Parameter(Mandatory)][object[]] $MicrosoftEntries
    )

    $microsoftKeys = @{}

    foreach ($entry in @($MicrosoftEntries)) {
        $key =
            "$($entry.SignatureTypeGuid)|$($entry.EntryDataSHA256)"
        $microsoftKeys[$key] = $true
    }

    $platformEntries = @()

    foreach ($entry in @($InstalledEntries)) {
        $key =
            "$($entry.SignatureTypeGuid)|$($entry.EntryDataSHA256)"

        if (-not $microsoftKeys.ContainsKey($key)) {
            $platformEntries += $entry
        }
    }

    return ,(Get-UniqueEntries -Entries $platformEntries)
}

function Test-FinalPolicy {
    param(
        [Parameter(Mandatory)][object[]] $KekEntries,
        [Parameter(Mandatory)][object[]] $DbEntries
    )

    $kekSubjects =
        @(
            $KekEntries |
                Where-Object Kind -eq 'X509' |
                ForEach-Object Subject
        ) -join "`n"

    $dbSubjects =
        @(
            $DbEntries |
                Where-Object Kind -eq 'X509' |
                ForEach-Object Subject
        ) -join "`n"

    if ($kekSubjects -notmatch
        'Microsoft Corporation KEK 2K CA 2023') {

        throw (
            'Final KEK does not contain ' +
            'Microsoft Corporation KEK 2K CA 2023.'
        )
    }

    if ($dbSubjects -notmatch 'Windows UEFI CA 2023') {
        throw (
            'Final db does not contain Windows UEFI CA 2023.'
        )
    }

    if ($Policy -eq 'MicrosoftAndThirdParty' -and
        $dbSubjects -notmatch 'Microsoft UEFI CA 2023') {

        throw (
            'Final db does not contain Microsoft UEFI CA 2023.'
        )
    }

    Write-Host (
        'Final merged KEK/db policy contains the required ' +
        'Microsoft 2023 certificates.'
    ) -ForegroundColor Green
}

function Backup-CurrentVariables {
    param([Parameter(Mandatory)][string] $Directory)

    New-Item `
        -ItemType Directory `
        -Path $Directory `
        -Force |
        Out-Null

    foreach ($name in @('PK', 'KEK', 'db', 'dbx')) {
        $bytes = Get-SecureBootBytes -Name $name

        if ($null -ne $bytes -and @($bytes).Count -gt 0) {
            $path = Join-Path $Directory "$name-before.bin"
            [IO.File]::WriteAllBytes($path, [byte[]]$bytes)

            Write-Host (
                "$name backed up: " +
                "SHA256=$(Get-Sha256Hex -Bytes ([byte[]]$bytes))"
            )
        }
        else {
            Write-Host "${name}: not present"
        }
    }
}

function Write-SecureBootVariable {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('dbx', 'db', 'KEK')]
        [string] $Name,

        [Parameter(Mandatory)]
        [byte[]] $Content
    )

    if ((Get-SecureBootByte -Name 'SetupMode') -ne 1) {
        throw "SetupMode changed before writing $Name."
    }

    $timestamp =
        (Get-Date).ToUniversalTime().AddMinutes(-2).
            ToString('yyyy-MM-ddTHH:mm:ssZ')

    Write-Host (
        "Writing $Name with authenticated-variable envelope..."
    ) -ForegroundColor Yellow

    try {
        $null =
            Set-SecureBootUEFI `
                -Name $Name `
                -Time $timestamp `
                -Content $Content `
                -ErrorAction Stop
    }
    catch {
        throw (
            "Set-SecureBootUEFI rejected ${Name}: " +
            $_.Exception.Message
        )
    }

    Start-Sleep -Milliseconds 750

    $readBack = Get-SecureBootBytes -Name $Name

    if ($null -eq $readBack -or @($readBack).Count -eq 0) {
        throw "$Name could not be read back."
    }

    $expectedHash = Get-Sha256Hex -Bytes $Content
    $actualHash =
        Get-Sha256Hex -Bytes ([byte[]]$readBack)

    if ($expectedHash -ne $actualHash) {
        throw (
            "$Name read-back mismatch. " +
            "Expected=$expectedHash Actual=$actualHash"
        )
    }

    Write-Host "$Name verified: $actualHash" -ForegroundColor Green
}

function Invoke-ExtractKeys {
    param(
        [Parameter(Mandatory)] $Download,
        [Parameter(Mandatory)] $MicrosoftPayloads
    )

    Write-Stage 'Reading installed PK, KEK and db'

    $activePkBytes = Get-SecureBootBytes -Name 'PK'
    $defaultPkBytes = Get-SecureBootBytes -Name 'PKDefault'

    if ($null -ne $activePkBytes -and @($activePkBytes).Count -gt 0) {
        $originalPkBytes = [byte[]]$activePkBytes
        $originalPkSource = 'PK'
    }
    elseif ($null -ne $defaultPkBytes -and @($defaultPkBytes).Count -gt 0) {
        $originalPkBytes = [byte[]]$defaultPkBytes
        $originalPkSource = 'PKDefault'
    }
    else {
        throw 'Neither active PK nor PKDefault is available for extraction.'
    }

    Write-Host (
        "Original Platform Key source: $originalPkSource, " +
        "SHA256=$(Get-Sha256Hex -Bytes $originalPkBytes)"
    )

    $installedKekBytes = Get-SecureBootBytes -Name 'KEK'
    $installedDbBytes = Get-SecureBootBytes -Name 'db'

    if ($null -eq $installedKekBytes -or
        @($installedKekBytes).Count -eq 0) {

        throw 'Installed KEK is absent or unreadable.'
    }

    if ($null -eq $installedDbBytes -or
        @($installedDbBytes).Count -eq 0) {

        throw 'Installed db is absent or unreadable.'
    }

    $installedKekEntries =
        ConvertFrom-EfiSignatureList `
            -Bytes ([byte[]]$installedKekBytes) `
            -Label 'Installed-KEK'

    $installedDbEntries =
        ConvertFrom-EfiSignatureList `
            -Bytes ([byte[]]$installedDbBytes) `
            -Label 'Installed-db'

    Show-EntrySummary `
        -Name 'Installed KEK' `
        -Entries @($installedKekEntries)

    Show-EntrySummary `
        -Name 'Installed db' `
        -Entries @($installedDbEntries)

    Write-Stage 'Extracting platform-specific entries'

    $oemKekEntries =
        Compare-Against-MicrosoftBaseline `
            -InstalledEntries @($installedKekEntries) `
            -MicrosoftEntries @($MicrosoftPayloads.KEK.Entries)

    $oemDbEntries =
        Compare-Against-MicrosoftBaseline `
            -InstalledEntries @($installedDbEntries) `
            -MicrosoftEntries @($MicrosoftPayloads.db.Entries)

    Show-EntrySummary `
        -Name 'Extracted OEM/platform KEK' `
        -Entries @($oemKekEntries)

    Show-EntrySummary `
        -Name 'Extracted OEM/platform db' `
        -Entries @($oemDbEntries)

    $package =
        Write-KeyPackage `
            -Directory $KeyPackageDirectory `
            -OemKekEntries @($oemKekEntries) `
            -OemDbEntries @($oemDbEntries) `
            -OriginalPkBytes $originalPkBytes `
            -OriginalPkSource $originalPkSource `
            -Download $Download `
            -MicrosoftPayloads $MicrosoftPayloads

    Write-Stage 'Extraction complete'

    Write-Host (
        "Machine-specific package: $($package.Directory)"
    ) -ForegroundColor Green

    Write-Host "  $($package.PkPath)"
    Write-Host "  $($package.KekPath)"
    Write-Host "  $($package.DbPath)"
    Write-Host "  $($package.ManifestPath)"
    Write-Host "  $($package.ReportPath)"
}


function Invoke-Provision {
    param(
        [Parameter(Mandatory)] $MicrosoftPayloads
    )

    Write-Stage 'Checking firmware state'

    $setupMode = Get-SecureBootByte -Name 'SetupMode'
    $secureBoot = Get-SecureBootByte -Name 'SecureBoot'
    $pkBytes = Get-SecureBootBytes -Name 'PK'

    $pkPresent =
        ($null -ne $pkBytes -and @($pkBytes).Count -gt 0)

    Write-Host "SetupMode:  $setupMode"
    Write-Host "SecureBoot: $secureBoot"
    Write-Host "PK present: $pkPresent"

    if ($setupMode -ne 1) {
        throw (
            'Refusing: firmware is not in Secure Boot Setup Mode.'
        )
    }

    if ($secureBoot -ne 0) {
        throw (
            'Refusing: SecureBoot unexpectedly reports active.'
        )
    }

    if ($pkPresent) {
        throw 'Refusing: PK is present.'
    }

    Write-Stage 'Loading extracted original and machine-specific keys'

    $package =
        Read-KeyPackage -Directory $KeyPackageDirectory

    $oemKekEntries = @()
    $oemDbEntries = @()

    if ($null -ne $package) {
        $oemKekEntries = @($package.KekEntries)
        $oemDbEntries = @($package.DbEntries)

        Write-Host (
            "Using extracted package: $($package.Directory)"
        ) -ForegroundColor Green

        if ($package.Manifest.Firmware.Manufacturer) {
            Write-Host (
                'Package machine: ' +
                "$($package.Manifest.Firmware.Manufacturer) " +
                "$($package.Manifest.Firmware.Model)"
            )
        }

        Show-EntrySummary `
            -Name 'OEM/platform KEK to merge' `
            -Entries $oemKekEntries

        Show-EntrySummary `
            -Name 'OEM/platform db to merge' `
            -Entries $oemDbEntries
    }
    else {
        throw (
            'No valid extracted-key package was found at: ' +
            $KeyPackageDirectory +
            '. Run this tool with -Extract first.'
        )
    }

    Write-Stage 'Building merged policy'

    $mergedKekEntries =
        Get-UniqueEntries -Entries @(
            @($MicrosoftPayloads.KEK.Entries) +
            @($oemKekEntries)
        )

    $mergedDbEntries =
        Get-UniqueEntries -Entries @(
            @($MicrosoftPayloads.db.Entries) +
            @($oemDbEntries)
        )

    $mergedKekBytes =
        ConvertTo-EfiSignatureList `
            -Entries @($mergedKekEntries)

    $mergedDbBytes =
        ConvertTo-EfiSignatureList `
            -Entries @($mergedDbEntries)

    # dbx is intentionally not merged.
    $microsoftDbxBytes =
        [byte[]]$MicrosoftPayloads.dbx.Bytes

    Test-FinalPolicy `
        -KekEntries @($mergedKekEntries) `
        -DbEntries @($mergedDbEntries)

    Show-EntrySummary `
        -Name 'Final merged KEK' `
        -Entries @($mergedKekEntries)

    Show-EntrySummary `
        -Name 'Final merged db' `
        -Entries @($mergedDbEntries)

    Write-Host
    Write-Host (
        'Final dbx: Microsoft payload only, ' +
        "$($microsoftDbxBytes.Length) bytes, " +
        "SHA256=$(Get-Sha256Hex -Bytes $microsoftDbxBytes)"
    )

    Write-Stage 'Backing up current variables'
    Backup-CurrentVariables -Directory $BackupDirectory

    $previewDirectory =
        Join-Path $BackupDirectory 'prepared-payloads'

    New-Item `
        -ItemType Directory `
        -Path $previewDirectory `
        -Force |
        Out-Null

    [IO.File]::WriteAllBytes(
        (Join-Path $previewDirectory 'DBX-Microsoft.bin'),
        $microsoftDbxBytes
    )

    [IO.File]::WriteAllBytes(
        (Join-Path $previewDirectory 'DB-merged.esl'),
        $mergedDbBytes
    )

    [IO.File]::WriteAllBytes(
        (Join-Path $previewDirectory 'KEK-merged.esl'),
        $mergedKekBytes
    )

    $previewManifest = [ordered]@{
        CreatedUTC =
            (Get-Date).ToUniversalTime().ToString('o')
        MicrosoftDbxSHA256 =
            Get-Sha256Hex -Bytes $microsoftDbxBytes
        MergedDbSHA256 =
            Get-Sha256Hex -Bytes $mergedDbBytes
        MergedKekSHA256 =
            Get-Sha256Hex -Bytes $mergedKekBytes
        MicrosoftDbxEntries =
            @($MicrosoftPayloads.dbx.Entries).Count
        MergedDbEntries = @($mergedDbEntries).Count
        MergedKekEntries = @($mergedKekEntries).Count
    }

    $previewManifest |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -LiteralPath (
                Join-Path $previewDirectory 'prepared-manifest.json'
            ) `
            -Encoding UTF8

    Write-Host
    Write-Host (
        "Prepared payloads: $previewDirectory"
    ) -ForegroundColor Green

    Write-Host
    Write-Host (
        'This will REPLACE dbx with Microsoft dbx, replace db/KEK ' +
        'with merged values, and restore the extracted original PK.'
    ) -ForegroundColor Red

    if (-not (Confirm-Yes -Prompt 'Apply this Secure Boot policy?')) {
        throw 'Confirmation declined; no firmware variables changed.'
    }

    Import-Module SecureBoot -ErrorAction Stop

    Write-Stage 'Installing dbx, db and KEK'

    Write-SecureBootVariable `
        -Name dbx `
        -Content $microsoftDbxBytes

    Write-SecureBootVariable `
        -Name db `
        -Content $mergedDbBytes

    Write-SecureBootVariable `
        -Name KEK `
        -Content $mergedKekBytes

    Write-Stage 'Restoring original Platform Key'

    $pkBytes = [byte[]]$package.PkBytes

    if ($pkBytes.Length -eq 0) {
        throw 'Extracted Platform Key payload is empty.'
    }

    $timestamp =
        (Get-Date).ToUniversalTime().
            ToString('yyyy-MM-ddTHH:mm:ssZ')

    try {
        $null =
            Set-SecureBootUEFI `
                -Name PK `
                -Time $timestamp `
                -Content $pkBytes `
                -ErrorAction Stop
    }
    catch {
        throw (
            'Set-SecureBootUEFI rejected PK: ' +
            $_.Exception.Message
        )
    }

    Start-Sleep -Milliseconds 750

    $finalPk = Get-SecureBootBytes -Name 'PK'
    if ($null -eq $finalPk -or @($finalPk).Count -eq 0) {
        throw 'PK was not readable after restoration.'
    }

    $expectedPkHash = Get-Sha256Hex -Bytes $pkBytes
    $actualPkHash =
        Get-Sha256Hex -Bytes ([byte[]]$finalPk)

    if ($expectedPkHash -ne $actualPkHash) {
        throw (
            'PK read-back mismatch. ' +
            "Expected=$expectedPkHash Actual=$actualPkHash"
        )
    }

    $finalSetupMode = Get-SecureBootByte -Name 'SetupMode'

    if ($finalSetupMode -ne 0) {
        Write-Warning (
            "PK is installed, but SetupMode still reports $finalSetupMode. " +
            'Reboot before judging the firmware mode transition.'
        )
    }
    else {
        Write-Host 'PK restored; SetupMode is now 0.' -ForegroundColor Green
    }

    Write-Stage 'Provision complete'

    Write-Host (
        'Microsoft dbx, merged db/KEK, and the original extracted PK ' +
        'were installed and verified. Reboot now.'
    ) -ForegroundColor Green
}

Write-Stage 'Starting'

$selectedAction = if ($Extract) { 'Extract' } else { 'Provision' }
Write-Host "Action:        $selectedAction"
Write-Host "Architecture:  $Architecture"
Write-Host "Policy:        $Policy"
Write-Host "Payload class: $PayloadClass"

if (-not (Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)) {
    throw (
        'Get-SecureBootUEFI is unavailable. Run elevated ' +
        '64-bit Windows PowerShell on a UEFI system.'
    )
}

if ([Environment]::Is64BitOperatingSystem -and
    -not [Environment]::Is64BitProcess) {

    throw 'Run 64-bit Windows PowerShell.'
}

# Extraction explicitly selects the Microsoft baseline. Provision
# reuses the baseline recorded in the extracted package, so the operator
# does not need to supply the release a second time.
$effectiveReleaseTag = $null
$effectivePolicy = $Policy
$effectivePayloadClass = $PayloadClass
$effectiveArchitecture = $Architecture

if ($Extract) {
    $effectiveReleaseTag = $ReleaseTag
}
else {
    $existingPackage = Read-KeyPackage -Directory $KeyPackageDirectory

    if ($null -ne $existingPackage -and
        $null -ne $existingPackage.Manifest.MicrosoftBaseline) {

        $baseline = $existingPackage.Manifest.MicrosoftBaseline
        $effectiveReleaseTag = [string]$baseline.ReleaseTag

        if ($baseline.Policy) {
            $effectivePolicy = [string]$baseline.Policy
        }

        if ($baseline.PayloadClass) {
            $effectivePayloadClass = [string]$baseline.PayloadClass
        }

        if ($baseline.Architecture) {
            $effectiveArchitecture = [string]$baseline.Architecture
        }

        Write-Host (
            'Provisioning baseline from extracted package: ' +
            "$effectiveReleaseTag, " +
            "$effectivePolicy/$effectivePayloadClass/" +
            $effectiveArchitecture
        ) -ForegroundColor Green
    }
    else {
        throw (
            'No valid extracted-key package is available at: ' +
            $KeyPackageDirectory +
            '. Run -Extract with an explicit -ReleaseTag before provisioning.'
        )
    }
}

$download =
    Download-And-VerifyRelease `
        -Tag $effectiveReleaseTag `
        -Destination $DownloadDirectory `
        -Architecture $effectiveArchitecture

$payloadSet =
    Find-MicrosoftPayloadSet `
        -Root $download.ExtractPath `
        -Policy $effectivePolicy `
        -PayloadClass $effectivePayloadClass

$microsoftPayloads =
    Read-MicrosoftPayloadSet -Set $payloadSet

if ($Extract) {
    Invoke-ExtractKeys `
        -Download $download `
        -MicrosoftPayloads $microsoftPayloads
}
else {
    # Use the resolved baseline values for policy validation/reporting.
    $Policy = $effectivePolicy
    $PayloadClass = $effectivePayloadClass
    $Architecture = $effectiveArchitecture

    Invoke-Provision `
        -MicrosoftPayloads $microsoftPayloads
}
