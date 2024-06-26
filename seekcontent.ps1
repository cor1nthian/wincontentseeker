<#

    .SYNOPSIS
    Script to search files by a content match.
    Intended to be used as an explorer context manu option.
    Calculates hashes for found files.

    .DESCRIPTION
    Script to search files by a content match.
    Intended to be used as local manu option.
    Calculates hashes for found files.

    .INPUTS
    Mandatory - folder path and expression to search

    .OUTPUTS
    Table consisting of matching files' paths, hashing algorithms used, matchinf file sizes and matching files' hashes.
    If no files found, outputs "---"

    .PARAMETER FolderPath
    Mandatory. 0 position. Folder path to check.

    .PARAMETER SearchExpr
    Mandatory. 1 position. Expression to search.

    .PARAMETER MaxFileSz
    Optional. 2 position. Default -  100mb. Files more than MaxFileSz are ignored.

    .PARAMETER MD5Thresh
    Optional. 3 position. Default - 50mb. Files less than MD5Thresh (or equal to) get MD5 hash, others get SHA256 hash

    .PARAMETER SHA256Always
    Optional. 4 position. Default - false. Get SHA256 always for all matching files.

    .PARAMETER DoCls
    Optional. 5 position. Default - true. If true, clear screen before result output,

    .PARAMETER FileSzMod
    Optional. 6 position. Default - 1KB. Divide file size by this value.
    Set of available vals consists of (1KB, 1MB, 1GB)

    .PARAMETER FractPartSigns
    Optional. 7 position. Default - 2. Round up file size division result to this max number of fract signs.
    Set of available vals consists of (2, 3, 4)

    .PARAMETER CompareMethod
    Optional. 8 position. One of the values from set: { "equal", "equalignorecase", "partialmatch", "partialmatchignorecase" }
    Default - partialmatchignorecase.
    Compare method used to pick files.

#>

Param ( [Parameter(Position = 0, Mandatory = $true)]  [System.String]  $FolderPath,
        [Parameter(Position = 1, Mandatory = $true)]  [System.String]  $SearchExpr,
        [Parameter(Position = 2, Mandatory = $false)] [System.Int64]   $MaxFileSz = 100mb,
        [Parameter(Position = 3, Mandatory = $false)] [System.Int64]   $MD5Thresh = 50mb,
        [Parameter(Position = 4, Mandatory = $false)] [System.Boolean] $SHA256Always = $false,
        [Parameter(Position = 5, Mandatory = $false)] [System.Boolean] $DoCls = $true,
        [Parameter(Position = 6, Mandatory = $false)]
            [ValidateSet(1KB, 1MB, 1GB)]
                [System.Int64] $FileSzMod = 1KB,
        [Parameter(Position = 7, Mandatory = $false)]
            [ValidateSet(2, 3, 4)]
                [System.Int16] $FractPartSigns = 2,
        [Parameter(Position = 8, Mandatory = $false)]
            [ValidateSet("equal", "equalignorecase", "partialmatch", "partialmatchignorecase")]
                [System.String] $CompareMethod = "partialmatchignorecase" )

function GetHash {
     
    Param ( [Parameter(Mandatory = $true, ParameterSetName = 'Object')] $InputObject,
            [Parameter(Mandatory = $true, ParameterSetName = 'File')]  [System.String][ValidateNotNullOrEmpty()] $FilePath,
            [Parameter(Mandatory = $true, ParameterSetName = 'Text')]  [System.String][ValidateNotNullOrEmpty()] $Text,
            [Parameter(Mandatory = $false, ParameterSetName = 'Text')] [System.String][ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')] $Encoding = 'Unicode',
            [Parameter(Mandatory = $false)] [System.String][ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")] $Algorithm = "SHA256" )
 
    switch($PSCmdlet.ParameterSetName) {
        File {
            try {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                GetHash -InputObject $InputObject -Algorithm $Algorithm
            } catch {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            GetHash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream]) {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
 
                # Compute file-hash using the crypto object
                [System.Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [System.String] $hash = [BitConverter]::ToString($computedHash) -replace '-',''
 
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }
 
                $retVal
            }
        }
    }
}

function BuildReportLine {

    Param ( [Parameter(Position = 0, Mandatory = $true)]  [System.String] $filePath )

    [System.String] $Algo = "MD5"
    [System.String] $hash = ""
    if($script:SHA256Always) {
        $hash = (GetHash -FilePath $filePath -Algorithm SHA256 | Select Hash).Hash
        $Algo = "SHA256"
    } else {
        if((GetFileSize $filePath) -le $script:MD5Thresh) {
            $hash = (GetHash -FilePath $filePath -Algorithm MD5 | Select Hash).Hash
            $Algo = "MD5"
        } else {
            $hash = (GetHash -FilePath $filePath -Algorithm SHA256 | Select Hash).Hash
            $Algo = "SHA256"
        }
    }
    [System.String] $fileSzColName;
    if($script:FileSzMod -eq 1KB) {
        $fileSzColName = "Size, KB";
    } elseif($script:FileSzMod -eq 1MB) {
        $fileSzColName = "Size, MB";
    } elseif($script:FileSzMod -eq 1GB) {
        $fileSzColName = "Size, GB";
    }
    return [PSCustomObject] @{ Path = $filePath; $fileSzColName = ([Math]::Round((GetFileSize $filePath) / $script:FileSzMod, $script:FractPartSigns)); Algo = $Algo; Hash = $hash }
}

function GetFileSize {

    Param ( [Parameter(Position = 0, Mandatory = $true)]  [System.String] $filePath )

    [System.UInt64] $fileSz = (Get-ChildItem $filePath -ErrorAction SilentlyContinue | Select Length).Length
    if(!($fileSz -eq $null)) {
        return $fileSz
    } else {
        return 0
    }
}

############### SCRIPT ###############
$host.UI.RawUI.WindowTitle = “Searching content”
if(!$searchExpr.Length -or !$folderPath.Length) {
    Write-Host -ForegroundColor Red "EMPTY PARAMETERS"
    Exit 1
}
$fileList = Get-ChildItem $folderPath -Force -Recurse -ErrorAction SilentlyContinue | Where { !$_.PSIsContainer } | % { $_.FullName }
if(!$fileList.Count) {
    Write-Host -ForegroundColor Red "COULDNT PICK ANY FILES"
    Exit 1
}
if($DoCls) { Cls }
$out = @()
[System.Int64] $i = 0
[System.Boolean] $exitCycle = $false
[System.String[]] $content = @()
foreach($rec in $fileList) {
    Write-Progress -Status "Checking files" -Activity "Checking files" -CurrentOperation $rec -PercentComplete (($i / $fileList.Count) * 100)
    if((GetFileSize $rec) -le $MaxFileSz) {
        $content = Get-Content -Force -ErrorAction SilentlyContinue -Path $rec
        $exitCycle = $false
        foreach($line in $content) {
            if($exitCycle) {
                break
            }
            if($CompareMethod -eq "equal") {
                if(!($line -eq $null)) {
                    if($line -ceq $searchExpr) {
                        $out += (BuildReportLine $rec)
                        $exitCycle = $true
                        continue
                    }
                } else {
                    continue
                }
            } elseif($CompareMethod -eq "equalignorecase") {
                if(!($line -eq $null)) {
                    if($line.ToLower() -eq $searchExpr.ToLower()) {
                        $out += (BuildReportLine $rec)
                        $exitCycle = $true
                        continue
                    }
                } else {
                    continue
                }
            } elseif($CompareMethod -eq "partialmatch") {
                if(!($line -eq $null)) {
                    if($line -cmatch $searchExpr) {
                        $out += (BuildReportLine $rec)
                        $exitCycle = $true
                        continue
                    }
                } else {
                    continue
                }
            } elseif($CompareMethod -eq "partialmatchignorecase") {
                if(!($line -eq $null)) {
                    if($line.ToLower() -match $searchExpr.ToLower()) {
                        $out += (BuildReportLine $rec)
                        $exitCycle = $true
                        continue
                    }
                } else {
                    continue
                }
            }
        }
    }
    ++$i
}
Write-Progress -Status "Checking files" -Activity "Checking files" -Completed
Write-Host -ForegroundColor Green "RESULTS:"
if($out.Count) {
    [System.ConsoleColor] $color = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = "Green"
    $out | Format-Table -AutoSize
    $Host.UI.RawUI.ForegroundColor = $color
} else {
    Write-Host -ForegroundColor Green  "---"
}
Write-Host "`nPRESS ANY KEY TO CONTINUE"
[System.Void][System.Console]::ReadKey($true)
