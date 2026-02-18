<#
.SYNOPSIS
    FAT12/16 Ultimate Forensics Tool (v9 - The "Restore Everything" Version)
.DESCRIPTION
    - Full BPB Table (Clean Hex).
    - Detailed Math Formulas.
    - Memory Layout.
    - Recursive File Extraction.
    - Metadata: Entry Offsets, Data Offsets, Created/Modified Timestamps.
    - Long Cluster Chains (up to 50).
    - Complete Forensic Statistics (Slack, Fragmentation, Deleted, etc.).
.PARAMETER Dump
    Path to the disk image (.vhd, .img, .bin).
.PARAMETER Boot
    Boot sector offset (Hex String). Default 0x10000.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Dump,

    [string]$Boot = "0x10000"
)

$ErrorActionPreference = "Stop"

# --- 0. Setup ---
$DiskName = [System.IO.Path]::GetFileNameWithoutExtension($Dump)
$ExtractRoot = "$($DiskName)_result"

if (Test-Path $ExtractRoot) { Remove-Item $ExtractRoot -Recurse -Force }
New-Item -ItemType Directory -Path $ExtractRoot | Out-Null
$LogFile = Join-Path $ExtractRoot "$($DiskName)_res.txt"

# --- Global Statistics ---
$Global:Stats = @{
    SubDirectories    = 0
    TotalBytes        = [long]0
    TotalUsedClusters = 0
    SlackSpace        = [long]0 
    FragmentedFiles   = 0       
    DeletedEntries    = 0       
    HiddenFiles       = 0       
}

function Log-Output {
    param([string]$Message, [string]$Color="White", [switch]$NoNewLine)
    if ($NoNewLine) { Write-Host $Message -NoNewline -ForegroundColor $Color }
    else { Write-Host $Message -ForegroundColor $Color }
    $Message | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Clean-String {
    param([string]$InputStr)
    if ([string]::IsNullOrEmpty($InputStr)) { return "UNKNOWN" }
    $Cleaned = $InputStr.Trim([char]0x00, [char]0x20, [char]0xFF, [char]0xFFFF)
    $Invalid = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($Char in $Invalid) { $Cleaned = $Cleaned.Replace($Char, "_") }
    $Cleaned = $Cleaned.Replace([string][char]0xFFFF, "")
    if ([string]::IsNullOrWhiteSpace($Cleaned)) { return "UNNAMED" }
    return $Cleaned
}

Log-Output "=== ULTIMATE DISK ANALYSIS: $DiskName ===" "Cyan"
Log-Output "Image: $Dump"
Log-Output "Boot Offset: $Boot"

# --- 1. Read Boot Sector ---
try {
    $BootOffset = [Convert]::ToInt32($Boot, 16)
    $fs = [System.IO.File]::OpenRead($Dump)
    $br = [System.IO.BinaryReader]::new($fs)
} catch {
    Log-Output "Error: Could not open file." "Red"
    exit
}

# Reader helper that keeps values raw (Int) so we can format them cleanly later
function Read-BpbVal {
    param($Name, $RelOffset, $Size, $Type="Int")
    
    $AbsOffset = $BootOffset + $RelOffset
    $fs.Seek($AbsOffset, 0) | Out-Null
    $Raw = $br.ReadBytes($Size)
    
    $DecVal = 0
    $Desc = ""
    $HexRaw = ($Raw | ForEach-Object { "{0:X2}" -f $_ }) -join " "

    if ($Type -eq "ASCII") {
        $DecVal = [System.Text.Encoding]::ASCII.GetString($Raw)
        $Desc = $DecVal
        # For ASCII, the Hex Value is just the raw bytes
        $HexVal = $HexRaw
    } else {
        if ($Size -eq 1) { $DecVal = $Raw[0] }
        elseif ($Size -eq 2) { $DecVal = [BitConverter]::ToUInt16($Raw, 0) }
        elseif ($Size -eq 4) { $DecVal = [BitConverter]::ToUInt32($Raw, 0) }
        # Keep HexVal empty here, we format in the table
    }

    if ($Name -eq "BPB_Media") {
        if ($DecVal -eq 0xF8) { $Desc = "Fixed Disk (HDD)" }
        elseif ($DecVal -eq 0xF0) { $Desc = "Floppy" }
    }

    return [PSCustomObject]@{
        Characteristic = $Name; Offset = $RelOffset; Size = $Size; 
        RawHex = $HexRaw; Dec = $DecVal; Description = $Desc; Type = $Type
    }
}

# --- 2. BPB Table Output ---

$Params = @()
$Params += Read-BpbVal "BS_OEMName"     0x03 8 "ASCII"
$Params += Read-BpbVal "BPB_BytsPerSec" 0x0B 2 "Int"
$Params += Read-BpbVal "BPB_SecPerClus" 0x0D 1 "Int"
$Params += Read-BpbVal "BPB_RsvdSecCnt" 0x0E 2 "Int"
$Params += Read-BpbVal "BPB_NumFATs"    0x10 1 "Int"
$Params += Read-BpbVal "BPB_RootEntCnt" 0x11 2 "Int"
$Params += Read-BpbVal "BPB_TotSec16"   0x13 2 "Int"
$Params += Read-BpbVal "BPB_Media"      0x15 1 "Int"
$Params += Read-BpbVal "BPB_FATSz16"    0x16 2 "Int"
$Params += Read-BpbVal "BS_VolID"       0x27 4 "Int"
$Params += Read-BpbVal "BS_VolLab"      0x2B 11 "ASCII"

Log-Output "`n=== Table 1. BPB Parameters ===" "Yellow"

# Custom Table Formatting to fix 0x0x issue
$TableStr = $Params | Select-Object Characteristic, 
    @{N='Offset'; E={"{0:X2}" -f $_.Offset}}, 
    Size, 
    @{N='Value (Hex)'; E={
        if ($_.Type -eq "ASCII") { $_.RawHex } 
        elseif ($_.Size -eq 1) { "0x{0:X2}" -f $_.Dec }
        elseif ($_.Size -eq 2) { "0x{0:X4}" -f $_.Dec }
        elseif ($_.Size -eq 4) { "0x{0:X8}" -f $_.Dec }
    }}, 
    Dec, 
    Description | Format-Table -AutoSize | Out-String

Log-Output $TableStr

# --- 3. Mathematical Calculations ---

$BytsPerSec = ($Params | ? Characteristic -eq "BPB_BytsPerSec").Dec
$SecPerClus = ($Params | ? Characteristic -eq "BPB_SecPerClus").Dec
$RsvdSecCnt = ($Params | ? Characteristic -eq "BPB_RsvdSecCnt").Dec
$NumFATs    = ($Params | ? Characteristic -eq "BPB_NumFATs").Dec
$RootEntCnt = ($Params | ? Characteristic -eq "BPB_RootEntCnt").Dec
$TotSec16   = ($Params | ? Characteristic -eq "BPB_TotSec16").Dec
$FATSz16    = ($Params | ? Characteristic -eq "BPB_FATSz16").Dec

Log-Output "=== File System Calculations ===" "Cyan"

# 1. RootDirSectors
$RootDirSectors = [int][math]::Ceiling(($RootEntCnt * 32) / $BytsPerSec)
Log-Output "1) RootDirSectors = ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec"
Log-Output "   = (($RootEntCnt * 32) + ($BytsPerSec - 1)) / $BytsPerSec = $RootDirSectors" "Green"

# 2. DataSectors
$DataSectors = $TotSec16 - ($RsvdSecCnt + ($NumFATs * $FATSz16) + $RootDirSectors)
Log-Output "`n2) DataSectors = BPB_TotSec16 - (BPB_RsvdSecCnt + (BPB_NumFATs * BPB_FATSz16) + RootDirSectors)"
Log-Output "   = $TotSec16 - ($RsvdSecCnt + ($NumFATs * $FATSz16) + $RootDirSectors) = $DataSectors" "Green"

# 3. CountOfClusters
$CountOfClusters = [math]::Floor($DataSectors / $SecPerClus)
Log-Output "`n3) CountOfClusters = DataSectors / BPB_SecPerClus"
Log-Output "   = $DataSectors / $SecPerClus = $CountOfClusters" "Green"

# 4. FAT Type
Log-Output "`n=== File System Type Determination ===" "Cyan"
Log-Output "CountOfClusters < 4085 => FAT12"
Log-Output "4085 <= CountOfClusters < 65525 => FAT16"
Log-Output "Result: Cluster Count = $CountOfClusters"
$FATType = if ($CountOfClusters -lt 4085) { "FAT12" } else { "FAT16" }
Log-Output "File System: $FATType" "Yellow"

# --- 4. Memory Layout ---

$BytesPerCluster = [int]($BytsPerSec * $SecPerClus)

$Reserved_Start = $BootOffset
$Reserved_End   = $BootOffset + ($RsvdSecCnt * $BytsPerSec) - 1

$FAT1_Start     = $Reserved_End + 1
$FAT_Size_Bytes = $FATSz16 * $BytsPerSec
$FAT1_End       = $FAT1_Start + $FAT_Size_Bytes - 1

$FAT2_Start     = $FAT1_End + 1
$FAT2_End       = $FAT2_Start + $FAT_Size_Bytes - 1

if ($NumFATs -eq 2) { $RootDir_Start = $FAT2_End + 1 } else { $RootDir_Start = $FAT1_End + 1 }
$RootDir_End    = $RootDir_Start + ($RootDirSectors * $BytsPerSec) - 1

$Data_Start     = $RootDir_End + 1
$Data_End       = $BootOffset + ($TotSec16 * $BytsPerSec) - 1

Log-Output "`n=== Memory Layout (Hex) ===" "Yellow"
Log-Output " Reserved (Boot):  0x$("{0:X}" -f $Reserved_Start) - 0x$("{0:X}" -f $Reserved_End)"
Log-Output " FAT1 Table:       0x$("{0:X}" -f $FAT1_Start) - 0x$("{0:X}" -f $FAT1_End)"
if ($NumFATs -gt 1) {
    Log-Output " FAT2 Table:       0x$("{0:X}" -f $FAT2_Start) - 0x$("{0:X}" -f $FAT2_End)"
}
Log-Output " Root Directory:   0x$("{0:X}" -f $RootDir_Start) - 0x$("{0:X}" -f $RootDir_End)"
Log-Output " Data Region:      0x$("{0:X}" -f $Data_Start) - 0x$("{0:X}" -f $Data_End)"

# --- 5. FAT Analysis ---

Log-Output "`n=== Analyzing FAT Table... ===" "Gray"
$fs.Seek($FAT1_Start, 0) | Out-Null
$FATBytes = $br.ReadBytes($FAT_Size_Bytes)

$FatEntriesTotal = if ($FATType -eq "FAT16") { [math]::Floor($FATBytes.Length / 2) } else { [math]::Floor(($FATBytes.Length * 2) / 3) }
$FatEntriesUsed  = 0

function Get-NextCluster($CurrentCluster) {
    if ($CurrentCluster -lt 2) { return 0xFFF8 }
    if ($FATType -eq "FAT16") {
        $Offset = $CurrentCluster * 2
        if ($Offset -ge ($FATBytes.Length - 1)) { return 0xFFF8 }
        return [BitConverter]::ToUInt16($FATBytes, $Offset)
    } else { 
        $Offset = [int][math]::Floor($CurrentCluster + ($CurrentCluster / 2))
        if ($Offset -ge ($FATBytes.Length - 1)) { return 0xFF8 }
        $Val16 = [BitConverter]::ToUInt16($FATBytes, $Offset)
        if ($CurrentCluster % 2 -eq 0) { return ($Val16 -band 0x0FFF) }
        else { return ($Val16 -shr 4) }
    }
}

for ($i = 2; $i -lt ($CountOfClusters + 2); $i++) {
    $Val = Get-NextCluster $i
    if ($Val -ne 0 -and $Val -ne 0xFFFF -and $Val -ne 0xFFF7 -and $Val -ne 0xFF8) { 
        $FatEntriesUsed++ 
    }
}

Log-Output " Total FAT Entries: $FatEntriesTotal"
Log-Output " Used FAT Entries:  $FatEntriesUsed"

function Get-ClusterChain($StartCluster) {
    $Chain = @(); $Curr = $StartCluster
    $EOF = if ($FATType -eq "FAT16") { 0xFFF8 } else { 0xFF8 }
    $Limit = 50 # Increased chain limit per request
    while ($Curr -ge 2 -and $Curr -lt $EOF) {
        $Chain += $Curr; 
        if ($Curr -ge $FatEntriesTotal) { break }
        $Next = Get-NextCluster $Curr
        if ($Chain.Count -gt $Limit) { break }
        if ($Chain -contains $Next) { break }
        $Curr = $Next
    }
    return $Chain
}

# --- 6. File Walker ---

function Decode-DosDate($Value) {
    if ($Value -eq 0) { return "N/A" }
    $Year  = (($Value -shr 9) -band 0x7F) + 1980
    $Month = ($Value -shr 5) -band 0x0F
    $Day   = $Value -band 0x1F
    return "$Year-$("{0:D2}" -f $Month)-$("{0:D2}" -f $Day)"
}

function Decode-DosTime($Value) {
    $Hour = ($Value -shr 11) -band 0x1F
    $Min  = ($Value -shr 5) -band 0x3F
    $Sec  = ($Value -band 0x1F) * 2
    return "$("{0:D2}" -f $Hour):$("{0:D2}" -f $Min):$("{0:D2}" -f $Sec)"
}

function Extract-FileData($StartCluster, $FileSize, $DestinationPath) {
    $Chain = Get-ClusterChain $StartCluster
    try {
        $FileStream = [System.IO.File]::Create($DestinationPath)
        $Writer = [System.IO.BinaryWriter]::new($FileStream)
        $RemainingBytes = $FileSize
        foreach ($Cluster in $Chain) {
            if ($RemainingBytes -le 0) { break }
            $ClusterOffset = $Data_Start + (($Cluster - 2) * $BytesPerCluster)
            $fs.Seek($ClusterOffset, 0) | Out-Null
            $ToRead = [math]::Min($BytesPerCluster, $RemainingBytes)
            $Writer.Write($br.ReadBytes($ToRead))
            $RemainingBytes -= $ToRead
        }
    } catch { } 
    finally { if ($Writer) { $Writer.Close() }; if ($FileStream) { $FileStream.Close() } }
}

$Global:VolumeLabel = "NO_NAME"

function Parse-Directory($DirOffset, $IsRoot, $Indent, $CurrentPath) {
    $MaxEntries = if ($IsRoot) { $RootEntCnt } else { 65535 }
    $LFN_Buffer = @{} 
    
    for ($i = 0; $i -lt $MaxEntries; $i++) {
        $CurrentEntryOffset = $DirOffset + ($i * 32)
        $fs.Seek($CurrentEntryOffset, 0) | Out-Null
        $RawEntry = $br.ReadBytes(32)
        
        if ($RawEntry[0] -eq 0x00) { break } 
        if ($RawEntry[0] -eq 0xE5) { 
            $Global:Stats.DeletedEntries++
            continue 
        } 
        if ($RawEntry[0] -eq 0x2E) { continue } 
        
        $Attr = $RawEntry[11]
        
        if ($Attr -eq 0x0F) {
            $Seq = $RawEntry[0] -band 0x1F
            $NameParts = @()
            $NameParts += [System.Text.Encoding]::Unicode.GetString($RawEntry, 1, 10)
            $NameParts += [System.Text.Encoding]::Unicode.GetString($RawEntry, 14, 12)
            $NameParts += [System.Text.Encoding]::Unicode.GetString($RawEntry, 28, 4)
            $LFN_Part = ($NameParts -join "").Trim([char]0, [char]0xFFFF, [char]0xFF)
            $LFN_Buffer[$Seq] = $LFN_Part
            continue 
        }
        
        # Meta
        $CrtDate = Decode-DosDate ([BitConverter]::ToUInt16($RawEntry, 16))
        $CrtTime = Decode-DosTime ([BitConverter]::ToUInt16($RawEntry, 14))
        $ModDate = Decode-DosDate ([BitConverter]::ToUInt16($RawEntry, 24))
        $ModTime = Decode-DosTime ([BitConverter]::ToUInt16($RawEntry, 22))
        $FileSize = [BitConverter]::ToUInt32($RawEntry, 28)
        
        $FstClusHi = [BitConverter]::ToUInt16($RawEntry, 20)
        $FstClusLo = [BitConverter]::ToUInt16($RawEntry, 26)
        $StartCluster = ($FstClusHi -shl 16) -bor $FstClusLo
        
        if (($Attr -band 0x08) -and -not ($Attr -band 0x10)) {
            $VolRaw = [System.Text.Encoding]::ASCII.GetString($RawEntry, 0, 11)
            $Global:VolumeLabel = Clean-String $VolRaw
            Log-Output " Found Volume Label: $Global:VolumeLabel (Offset: 0x$("{0:X}" -f $CurrentEntryOffset))" "Cyan"
            continue
        }

        # Name
        $Name = ""
        if ($LFN_Buffer.Count -gt 0) {
            for ($k = 1; $k -le $LFN_Buffer.Count; $k++) { $Name += $LFN_Buffer[$k] }
            $LFN_Buffer.Clear()
        } else {
            $Base = [System.Text.Encoding]::ASCII.GetString($RawEntry, 0, 8)
            $Ext  = [System.Text.Encoding]::ASCII.GetString($RawEntry, 8, 3)
            $Base = Clean-String $Base
            $Ext  = Clean-String $Ext
            if ($Ext -ne "UNKNOWN") { $Name = "$Base.$Ext" } else { $Name = $Base }
        }
        $Name = Clean-String $Name
        $EntryHex = "0x$("{0:X}" -f $CurrentEntryOffset)"

        if ($Attr -band 0x10) {
            $Global:Stats.SubDirectories++
            Log-Output "$Indent[$Name] (DIR)" "Green"
            Log-Output "$Indent  Entry Offset: $EntryHex | Start Cluster: $StartCluster" "Gray"
            # RESTORED: Directory Metadata
            Log-Output "$Indent  Created: $CrtDate $CrtTime | Modified: $ModDate $ModTime" "Gray"
            
            $NewPath = Join-Path $CurrentPath $Name
            if (-not (Test-Path $NewPath)) { New-Item -ItemType Directory -Path $NewPath | Out-Null }
            $SubDirOffset = $Data_Start + (($StartCluster - 2) * $BytesPerCluster)
            Parse-Directory $SubDirOffset $false "$Indent  " $NewPath
        }
        else {
            $Chain = Get-ClusterChain $StartCluster
            
            # --- Advanced Stats ---
            $Global:Stats.TotalBytes += $FileSize
            $Global:Stats.TotalUsedClusters += $Chain.Count
            
            $PhysicalSize = $Chain.Count * $BytesPerCluster
            $Slack = $PhysicalSize - $FileSize
            if ($Slack -gt 0) { $Global:Stats.SlackSpace += $Slack }
            
            $IsFragmented = $false
            for($c=0; $c -lt ($Chain.Count - 1); $c++) {
                if ($Chain[$c+1] -ne ($Chain[$c] + 1)) { $IsFragmented = $true; break }
            }
            if ($IsFragmented) { $Global:Stats.FragmentedFiles++ }
            
            if ($Attr -band 0x02) { $Global:Stats.HiddenFiles++ }
            
            # RESTORED: Chain Limit 50
            $ChainStr = if ($Chain.Count -gt 50) { ($Chain[0..49] -join ",") + "..." } else { $Chain -join "," }
            $DataHex = "N/A"
            if ($StartCluster -ge 2) {
                 $PhysOff = $Data_Start + (($StartCluster - 2) * $BytesPerCluster)
                 $DataHex = "0x$("{0:X}" -f $PhysOff)"
            }

            Log-Output "$Indent$Name" "White"
            Log-Output "$Indent  Entry Offset: $EntryHex | Data Offset: $DataHex" "Gray"
            Log-Output "$Indent  Size: $FileSize | Clusters: $($Chain.Count) | Chain: $ChainStr" "DarkGray"
            # RESTORED: File Metadata
            Log-Output "$Indent  Created: $CrtDate $CrtTime | Modified: $ModDate $ModTime" "Gray"
            
            $DestFile = Join-Path $CurrentPath $Name
            Extract-FileData $StartCluster $FileSize $DestFile
        }
    }
}

Log-Output "`n=== Scanning File System... ===" "Yellow"
$TempVolPath = Join-Path $ExtractRoot "DETECTING_VOL"
New-Item -ItemType Directory -Path $TempVolPath | Out-Null
Parse-Directory $RootDir_Start $true "" $TempVolPath

$br.Close()
$fs.Close()

try {
    $FinalVolPath = Join-Path $ExtractRoot $Global:VolumeLabel
    if (Test-Path $FinalVolPath) { Remove-Item $FinalVolPath -Recurse -Force }
    Rename-Item -Path $TempVolPath -NewName $Global:VolumeLabel -ErrorAction SilentlyContinue
} catch { }

# --- 7. Final Report ---

Log-Output "`n==========================================" "Cyan"
Log-Output "       FINAL STATISTICS (ANSWERS)         " "Cyan"
Log-Output "==========================================" "Cyan"

Log-Output "1. Total Subdirectories (excluding root):"
Log-Output "   ANSWER: $($Global:Stats.SubDirectories)" "Green"

Log-Output "`n2. Total FAT Entries (Capacity):"
Log-Output "   ANSWER: $FatEntriesTotal" "Green"

Log-Output "`n3. Used FAT Entries (Files + Dirs):"
Log-Output "   ANSWER: $FatEntriesUsed" "Green"

Log-Output "`n4. Total Logical Size of Files:"
Log-Output "   ANSWER: $($Global:Stats.TotalBytes) bytes" "Green"

Log-Output "`n5. Total Clusters Occupied (Physical Size):"
Log-Output "   ANSWER: $($Global:Stats.TotalUsedClusters) clusters" "Green"

Log-Output "`n6. Slack Space (Wasted Bytes):"
Log-Output "   ANSWER: $($Global:Stats.SlackSpace) bytes" "Red"

Log-Output "`n7. Fragmented Files:"
Log-Output "   ANSWER: $($Global:Stats.FragmentedFiles)" "Red"

Log-Output "`n8. Deleted File Entries (Found 0xE5):"
Log-Output "   ANSWER: $($Global:Stats.DeletedEntries)" "Red"

Log-Output "`n9. Total Addressable Clusters:"
Log-Output "   ANSWER: $CountOfClusters" "Green"

Log-Output "`n10. Total Reserved Sectors:"
Log-Output "    ANSWER: $RsvdSecCnt" "Green"

Log-Output "`n[Analysis Complete]" "Green"
Log-Output "Log saved to: $LogFile"
