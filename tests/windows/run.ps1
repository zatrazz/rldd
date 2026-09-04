#requires -Version 7.0

<#
.SYNOPSIS
    Check the rldd PE backend against 'dumpbin /dependents'.

.DESCRIPTION
    The dependency names an object records can only be checked against a real
    installation, so this runs rldd over the binaries of a system directory and
    compares the import and the delay load import lists with the ones dumpbin
    reports, in the directory order and with the recorded spelling.

    The exit status is non-zero when any check fails.

.EXAMPLE
    tests/windows/run.ps1
    tests/windows/run.ps1 -Sample 0
    tests/windows/run.ps1 -Root C:\Windows\SysWOW64
    tests/windows/run.ps1 -Root C:\ -Recurse -Sample 0
#>

[CmdletBinding()]
param(
    # The directories to sweep, or single files.
    [string[]]$Root = @("$env:SystemRoot\System32"),
    # Walk the directories, instead of taking only the objects directly below
    # them.
    [switch]$Recurse,
    # Sweep a random sample of this many objects, 0 meaning all of them.
    [int]$Sample = 200,
    # Parallel workers.  The sweep saturates at one per processor, since every
    # object costs two process starts.
    [int]$Throttle = [Environment]::ProcessorCount
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

# The report.

$UseColor = -not [Console]::IsOutputRedirected -and -not $env:NO_COLOR
$Red = if ($UseColor) { "$([char]27)[31m" } else { '' }
$Green = if ($UseColor) { "$([char]27)[32m" } else { '' }
$Off = if ($UseColor) { "$([char]27)[0m" } else { '' }
$Failed = 0

function Write-Pass([string]$Message) { Write-Host "  ${Green}PASS${Off}  $Message" }
function Write-Fail([string]$Message) { $script:Failed++; Write-Host "  ${Red}FAIL${Off}  $Message" }
function Write-Detail([string]$Message) { Write-Host "        $Message" }
function Write-Die([string]$Message) { Write-Host "${Red}error:${Off} $Message"; exit 2 }

# The reference tool.  dumpbin needs the Visual C++ runtime next to it, so it
# is always run through its full path instead of being copied anywhere.

function Find-Dumpbin {
    $command = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $null }

    # The host tools of the highest toolset, so a 32 bit dumpbin is not picked
    # on a 64 bit host.
    foreach ($root in (& $vswhere -products * -property installationPath 2>$null)) {
        $found = Get-ChildItem -LiteralPath $root -Filter dumpbin.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\HostX64\\x64\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

# The parsers.

# The two 'Image has the following ... dependencies' lists, in the import
# directory order.  A file dumpbin cannot read is a fatal error, one that is
# not a PE object at all an invalid format warning.
function ConvertFrom-Dumpbin([string]$Text) {
    $imports = [System.Collections.Generic.List[string]]::new()
    $delay = [System.Collections.Generic.List[string]]::new()
    $failure = ''
    $section = ''

    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^Image has the following delay load dependencies') { $section = 'delay'; continue }
        if ($trimmed -match '^Image has the following dependencies') { $section = 'import'; continue }
        if ($trimmed -match '^Image has the following') { $section = ''; continue }
        if ($trimmed -eq 'Summary') { $section = ''; continue }
        if ($trimmed -match 'fatal error LNK\d+|warning LNK4048') { $failure = $trimmed; continue }
        if ($line -notmatch '^    \S') { continue }
        if ($section -eq 'import') { $imports.Add($trimmed) }
        elseif ($section -eq 'delay') { $delay.Add($trimmed) }
    }
    [pscustomobject]@{ Imports = $imports.ToArray(); Delay = $delay.ToArray(); Failure = $failure }
}

# One level of the 'rldd -a -p' tree, whose entries are
#   '\_ PATH [attrs] [mode]', '\_ ALIAS -> PATH [attrs] [mode]', or
#   '\_ NAME not found [attrs]' when the module was not resolved.
function ConvertFrom-Rldd([string]$Text) {
    $entries = [System.Collections.Generic.List[object]]::new()
    $failure = ''

    foreach ($line in (($Text -replace "$([char]27)\[[0-9;]*m", '') -split "`r?`n")) {
        if ($line -match '^(error|rldd):|panicked at') { $failure = $line.Trim(); continue }
        if (-not $line.StartsWith('\_ ')) { continue }

        # The trailing bracket groups are the attributes and the resolution
        # mode, taken off from the right so a name keeps every other bracket.
        # The mode is empty on a dependency that resolves back to the object
        # itself, which leaves the line with a trailing space.
        $body = $line.Substring(3).TrimEnd()
        $attrs = @()
        while ($body -match '^(?<head>.*?)\s*\[(?<tag>[^\]]+)\]$') {
            $attrs += $Matches['tag']
            $body = $Matches['head']
        }

        $found = $true
        if ($body -match '^(?<name>.*) not found$') { $found = $false; $body = $Matches['name'] }

        # The recorded name, when the module it resolves to has another one.
        $alias = ''
        if ($body -match '^(?<alias>\S+) -> (?<name>.+)$') { $alias = $Matches['alias']; $body = $Matches['name'] }

        $entries.Add([pscustomobject]@{
                Recorded = if ($alias) { $alias } elseif ($found) { Split-Path $body -Leaf } else { $body }
                Path     = if ($found) { $body } else { '' }
                Attrs    = $attrs
            })
    }
    [pscustomobject]@{ Entries = $entries.ToArray(); Failure = $failure }
}

# The binary under test, built only when it is not there yet, so a run right
# after 'cargo build --release' tests what was just built.

$Rldd = Join-Path $RepoRoot 'target\release\rldd.exe'
if (-not (Test-Path -LiteralPath $Rldd)) {
    & cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { Write-Die 'cargo build failed' }
}
$Rldd = (Resolve-Path -LiteralPath $Rldd).Path

$Dumpbin = Find-Dumpbin
if (-not $Dumpbin) { Write-Die 'dumpbin was not found (install the Visual C++ build tools)' }

# The objects to test.  A root may also be a single file, so a report can be
# reproduced for one object.

$binaries = @($Root | ForEach-Object {
        if (-not (Test-Path -LiteralPath $_)) { return }
        if (Test-Path -LiteralPath $_ -PathType Container) {
            Get-ChildItem -LiteralPath $_ -File -Force -Recurse:$Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(exe|dll|ocx|cpl|drv|sys|efi|node|pyd|scr|ax|tsp)$' } |
                ForEach-Object { $_.FullName }
        } else {
            (Get-Item -LiteralPath $_ -Force).FullName
        }
    } | Sort-Object -Unique)

if ($Sample -gt 0 -and $binaries.Count -gt $Sample) {
    $binaries = @($binaries | Get-Random -Count $Sample | Sort-Object)
}
if ($binaries.Count -eq 0) { Write-Die "no binary below $($Root -join ', ')" }

# The sweep.

$mismatch = [System.Collections.Generic.List[string]]::new()
$caseonly = [System.Collections.Generic.List[string]]::new()
$panics = [System.Collections.Generic.List[string]]::new()
$missing = [System.Collections.Generic.List[string]]::new()
$notFound = [System.Collections.Generic.List[string]]::new()
$unreadable = 0
$refused = 0
$compared = 0

Write-Host "Sweeping $($binaries.Count) objects with $Dumpbin"
$started = Get-Date

# The workers only start the two tools, so nothing but the two outputs crosses
# back; the comparison is done here as the results arrive, which keeps a sweep
# of the whole system within memory.
$binaries | ForEach-Object -ThrottleLimit $Throttle -Parallel {
    [pscustomobject]@{
        File    = $_
        Dumpbin = (& $using:Dumpbin /nologo /dependents $_ 2>&1 | Out-String)
        Rldd    = (& $using:Rldd -a -p --depth 1 $_ 2>&1 | Out-String)
    }
} | ForEach-Object {
    $output = $_
    $tree = ConvertFrom-Rldd $output.Rldd
    if ($tree.Failure) {
        # An object neither tool reads is not a PE object; a panic never is
        # an acceptable answer.
        if ($tree.Failure -match 'panicked at') { $panics.Add("$($output.File): $($tree.Failure)") }
        else { $unreadable++ }
        return
    }

    # dumpbin refuses some objects rldd reads (a packed executable, an unusual
    # optional header), which leaves them unchecked instead of failing.
    $reference = ConvertFrom-Dumpbin $output.Dumpbin
    if ($reference.Failure) { $refused++; return }
    $compared++

    # A forwarded module is pulled in by a symbol instead of by a directory
    # entry, so dumpbin never lists it.
    $entries = @($tree.Entries | Where-Object { $_.Attrs -notcontains 'forwarded' })
    $lists = @(
        @{ Kind = 'import'; Expected = $reference.Imports; Got = @($entries | Where-Object { $_.Attrs -notcontains 'delay-load' } | ForEach-Object { $_.Recorded }) }
        @{ Kind = 'delay'; Expected = $reference.Delay; Got = @($entries | Where-Object { $_.Attrs -contains 'delay-load' } | ForEach-Object { $_.Recorded }) }
    )

    # Both tools keep the import directory order, so the lists are compared in
    # place and a difference in case alone is told apart.
    foreach ($list in $lists) {
        $expected = ($list.Expected -join "`n")
        $got = ($list.Got -join "`n")
        if ($expected -ieq $got) {
            if ($expected -cne $got) {
                $caseonly.Add("$($output.File): the $($list.Kind) names are printed with another case")
            }
            continue
        }
        $detail = @(
            $list.Expected | Where-Object { $list.Got -notcontains $_ } | ForEach-Object { "only dumpbin lists $_" }
            $list.Got | Where-Object { $list.Expected -notcontains $_ } | ForEach-Object { "only rldd lists $_" }
        )
        if (-not $detail) { $detail = @('the entries are in another order') }
        $mismatch.Add("$($output.File): $($list.Kind): $($detail -join ', ')")
    }

    # A resolved path is built from the directory the module was found on, so
    # it has to name a file that exists.
    foreach ($entry in $entries) {
        if (-not $entry.Path) { $notFound.Add($entry.Recorded); continue }
        if (-not (Test-Path -LiteralPath $entry.Path)) { $missing.Add("$($output.File): $($entry.Path)") }
    }
}

# The verdict.

$elapsed = [int]((Get-Date) - $started).TotalSeconds
Write-Host "$compared compared in ${elapsed}s, $unreadable not a PE object, $refused unreadable by dumpbin"

foreach ($check in @(
        @{ Failures = $mismatch; Pass = "the dependency names match on all $compared objects"; Fail = 'objects have another dependency list' }
        @{ Failures = $caseonly; Pass = 'every name is printed as the import directory records it'; Fail = 'objects print a name with another case' }
        @{ Failures = $panics; Pass = 'no object made rldd panic'; Fail = 'objects made rldd panic' }
        @{ Failures = $missing; Pass = 'every resolved dependency names a file that exists'; Fail = 'objects resolved a dependency to a path that does not exist' }
    )) {
    if ($check.Failures.Count -eq 0) {
        Write-Pass $check.Pass
    } else {
        Write-Fail "$($check.Failures.Count) $($check.Fail)"
        $check.Failures | Select-Object -First 10 | ForEach-Object { Write-Detail $_ }
    }
}

# An unresolved dependency is expected on Windows (the delay load import of an
# optional component, an object of another machine), so they are only listed.
if ($notFound.Count) {
    $names = $notFound | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    Write-Detail "$($notFound.Count) unresolved dependencies, the most common being:"
    foreach ($name in $names) { Write-Detail "    $($name.Count)  $($name.Name)" }
}

exit ([int]($Failed -gt 0))
