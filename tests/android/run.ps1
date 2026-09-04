<#
.SYNOPSIS
Run the Android device tests from PowerShell.

.DESCRIPTION
This wrapper finds the Git Bash shell and runs the suite with it.

Every argument is passed through to run.sh.

.EXAMPLE
tests\android\run.ps1

.EXAMPLE
tests\android\run.ps1 -d emulator-5554 -s
#>

$ErrorActionPreference = 'Stop'

function Find-GitBash {
    # The usual install locations first.
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe')
    )

    # Then the shell shipped next to the git on the PATH, which covers a
    # portable or relocated install.
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) {
        $root = Split-Path (Split-Path $git.Source -Parent) -Parent
        $candidates += (Join-Path $root 'bin\bash.exe')
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $null
}

$bash = Find-GitBash
if (-not $bash) {
    Write-Error @'
Git Bash was not found. Install Git for Windows, or run tests/android/run.sh 
from a Git Bash prompt.
'@
    exit 1
}

$script = Join-Path $PSScriptRoot 'run.sh'

# Git Bash needs the script path in its own form, since $0 is used to locate
# the rest of the suite.
$unix = (& $bash -c "cygpath -u '$script'").Trim()

& $bash $unix @args
exit $LASTEXITCODE
