#requires -Version 7.0

<#
.SYNOPSIS
    Check the rldd PE backend against 'dumpbin /dependents', and optionally
    against the modules the loader maps.

.DESCRIPTION
    The dependency names an object records can only be checked against a real
    installation, so this runs rldd over the binaries of a system directory and
    compares the import and the delay load import lists with the ones dumpbin
    reports, in the directory order and with the recorded spelling.

    With -Paths, every executable of the sweep is also started under the
    debugger up to the initial loader breakpoint, and the modules the loader
    mapped by then are compared with where rldd resolves the static
    dependencies to.

    The exit status is non-zero when any check fails.

.EXAMPLE
    tests/windows/run.ps1
    tests/windows/run.ps1 -Sample 0
    tests/windows/run.ps1 -Root C:\Windows\SysWOW64
    tests/windows/run.ps1 -Root C:\ -Recurse -Sample 0
    tests/windows/run.ps1 -Paths
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
    [int]$Throttle = [Environment]::ProcessorCount,
    # Compare the resolved paths of the executables with the modules the
    # loader maps.
    [switch]$Paths,
    # How long an executable is given to reach the loader breakpoint, in
    # seconds.
    [int]$Timeout = 10
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

# The report.

$UseColor = -not [Console]::IsOutputRedirected -and -not $env:NO_COLOR
$Red = if ($UseColor) { "$([char]27)[31m" } else { '' }
$Green = if ($UseColor) { "$([char]27)[32m" } else { '' }
$Off = if ($UseColor) { "$([char]27)[0m" } else { '' }
$Failed = 0

function Write-Pass([string]$Message) {
    Write-Host "  ${Green}PASS${Off}  $Message"
}

function Write-Fail([string]$Message) {
    $script:Failed++; Write-Host "  ${Red}FAIL${Off}  $Message"
}

function Write-Detail([string]$Message) {
    Write-Host "        $Message"
}

function Write-Die([string]$Message) {
    Write-Host "${Red}error:${Off} $Message";
    exit 2
}

#dumpbin needs the Visual C++ runtime next to it.

function Find-Dumpbin {
    $command = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        return $null
    }

    # The host tools of the highest toolset.
    foreach ($root in (& $vswhere -products * -property installationPath 2>$null)) {
        $found = Get-ChildItem -LiteralPath $root -Filter dumpbin.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\HostX64\\x64\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }
    return $null
}

# The two 'Image has the following ... dependencies' lists, in the import
# directory order.  A file dumpbin cannot read is a fatal error, one that is
# not a PE object at all an invalid format warning, and a 16 bit one an
# MS-DOS executable warning.
function ConvertFrom-Dumpbin([string]$Text) {
    $imports = [System.Collections.Generic.List[string]]::new()
    $delay = [System.Collections.Generic.List[string]]::new()
    $failure = ''
    $section = ''

    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^Image has the following delay load dependencies') {
             $section = 'delay';
             continue
        }
        if ($trimmed -match '^Image has the following dependencies') {
            $section = 'import';
            continue
        }
        if ($trimmed -match '^Image has the following') {
            $section = '';
            continue
        }
        if ($trimmed -eq 'Summary') {
            $section = '';
            continue
        }
        if ($trimmed -match 'fatal error LNK\d+|warning LNK(4048|4094)') {
            $failure = $trimmed;
            continue
         }
        if ($line -notmatch '^    \S') {
            continue
        }
        if ($section -eq 'import') {
            $imports.Add($trimmed)
        }
        elseif ($section -eq 'delay') {
            $delay.Add($trimmed)
        }
    }
    [pscustomobject]@{ Imports = $imports.ToArray(); Delay = $delay.ToArray(); Failure = $failure }
}

# The entries of an 'rldd -a -p' tree, whose lines are:
#   '\_ PATH [attrs] [mode]'
#   '\_ ALIAS -> PATH [attrs] [mode]'
#   '\_ NAME not found [attrs]' (when the module was not resolved)
# indented by three columns for each level below the first.
function ConvertFrom-Rldd([string]$Text) {
    $entries = [System.Collections.Generic.List[object]]::new()
    $failure = ''

    foreach ($line in (($Text -replace "$([char]27)\[[0-9;]*m", '') -split "`r?`n")) {
        if ($line -match '^(error|rldd):|panicked at') {
            $failure = $line.Trim();
            continue
        }
        $at = $line.IndexOf('\_ ')
        if ($at -lt 0 -or $at % 3 -ne 0 -or $line.Substring(0, $at) -notmatch '^[| ]*$') {
            continue
        }

        # The trailing bracket groups are the attributes and the resolution
        # mode, taken off from the right so a name keeps every other bracket.
        # The mode is empty on a dependency that resolves back to the object
        # itself.
        $body = $line.Substring($at + 3).TrimEnd()
        $attrs = @()
        while ($body -match '^(?<head>.*?)\s*\[(?<tag>[^\]]+)\]$') {
            $attrs += $Matches['tag']
            $body = $Matches['head']
        }

        $found = $true
        if ($body -match '^(?<name>.*) not found$') {
            $found = $false; $body = $Matches['name']
        }

        # The recorded name, when the module it resolves to has another one.
        $alias = ''
        if ($body -match '^(?<alias>\S+) -> (?<name>.+)$') {
            $alias = $Matches['alias']; $body = $Matches['name']
        }

        $entries.Add([pscustomobject]@{
                Level    = $at / 3
                Recorded = if ($alias) { $alias } elseif ($found) { Split-Path $body -Leaf } else { $body }
                Path     = if ($found) { $body } else { '' }
                Attrs    = $attrs
            })
    }
    [pscustomobject]@{ Entries = $entries.ToArray(); Failure = $failure }
}

# The modules the loader maps when starting an executable, up to the initial
# loader breakpoint: the static imports along with what they pull in, before
# any of their code runs.  The process is started under the debugger and
# killed there (for a 32 bit one, at the breakpoint of the WOW64 layer, after
# the native one), and the paths come from the file handles of the load
# events, which name the SysWOW64 files as they are.
$OracleSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class RlddLoaderOracle {
    public class Result {
        public List<string> Modules = new List<string>();
        public string Failure = "";
        public bool Wow64;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION information);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WaitForDebugEvent(IntPtr debugEvent, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ContinueDebugEvent(int processId, int threadId, uint status);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DebugActiveProcessStop(int processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process(IntPtr process, out bool wow64);
    [DllImport("kernel32.dll")]
    static extern uint SetErrorMode(uint mode);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint length, uint flags);

    const uint DEBUG_ONLY_THIS_PROCESS = 0x2;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint DBG_CONTINUE = 0x00010002;
    const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    const int EXCEPTION_DEBUG_EVENT = 1;
    const int CREATE_PROCESS_DEBUG_EVENT = 3;
    const int EXIT_PROCESS_DEBUG_EVENT = 5;
    const int LOAD_DLL_DEBUG_EVENT = 6;
    const uint STATUS_BREAKPOINT = 0x80000003;
    const uint STATUS_WX86_BREAKPOINT = 0x4000001F;
    // SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX and SEM_NOOPENFILEERRORBOX,
    // which the process inherits, so a missing module fails the start instead
    // of raising a message box.
    const uint ERROR_MODE = 0x0001 | 0x0002 | 0x8000;

    // The path of a file handle of a debug event, which is closed.
    static string PathOf(IntPtr file) {
        if (file == IntPtr.Zero)
            return null;
        var path = new StringBuilder(1024);
        uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0);
        CloseHandle(file);
        if (length == 0 || length >= path.Capacity)
            return null;
        var name = path.ToString();
        if (name.StartsWith(@"\\?\UNC\"))
            return @"\\" + name.Substring(8);
        return name.StartsWith(@"\\?\") ? name.Substring(4) : name;
    }

    // Handle an event that needs no answer but closing its file handle.
    static void Release(IntPtr debugEvent, int union) {
        int code = Marshal.ReadInt32(debugEvent, 0);
        if (code == CREATE_PROCESS_DEBUG_EVENT || code == LOAD_DLL_DEBUG_EVENT)
            PathOf(Marshal.ReadIntPtr(debugEvent, union));
    }

    public static Result Run(string executable, string directory, int timeout) {
        var result = new Result();
        SetErrorMode(ERROR_MODE);
        var startup = new STARTUPINFO();
        startup.cb = Marshal.SizeOf(startup);
        // STARTF_USESHOWWINDOW, with SW_HIDE.
        startup.dwFlags = 1;
        PROCESS_INFORMATION process;
        var command = new StringBuilder("\"" + executable + "\"");
        if (!CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, false,
                DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, IntPtr.Zero, directory,
                ref startup, out process)) {
            result.Failure = "not started: " + new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return result;
        }

        // The union of DEBUG_EVENT follows the three fields, aligned to the
        // pointer size.
        int union = IntPtr.Size == 8 ? 16 : 12;
        IntPtr debugEvent = Marshal.AllocHGlobal(1024);
        bool pending = false, exited = false;
        int pid = 0, tid = 0;
        try {
            bool wow64;
            IsWow64Process(process.hProcess, out wow64);
            result.Wow64 = wow64;
            var deadline = DateTime.UtcNow.AddMilliseconds(timeout);
            while (true) {
                int left = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0 || !WaitForDebugEvent(debugEvent, (uint)left)) {
                    result.Failure = "timeout";
                    break;
                }
                pending = true;
                int code = Marshal.ReadInt32(debugEvent, 0);
                pid = Marshal.ReadInt32(debugEvent, 4);
                tid = Marshal.ReadInt32(debugEvent, 8);
                uint status = DBG_CONTINUE;
                if (code == LOAD_DLL_DEBUG_EVENT) {
                    string path = PathOf(Marshal.ReadIntPtr(debugEvent, union));
                    if (path != null)
                        result.Modules.Add(path);
                } else if (code == EXCEPTION_DEBUG_EVENT) {
                    uint exception = (uint)Marshal.ReadInt32(debugEvent, union);
                    if (exception == STATUS_WX86_BREAKPOINT || (exception == STATUS_BREAKPOINT && !wow64))
                        break;
                    if (exception != STATUS_BREAKPOINT)
                        status = DBG_EXCEPTION_NOT_HANDLED;
                } else if (code == EXIT_PROCESS_DEBUG_EVENT) {
                    result.Failure = String.Format("exited with 0x{0:X8}", Marshal.ReadInt32(debugEvent, union));
                    exited = true;
                    break;
                } else {
                    Release(debugEvent, union);
                }
                ContinueDebugEvent(pid, tid, status);
                pending = false;
            }
        } finally {
            // Kill the process and let it go through its exit, answering the
            // pending event, so it does not linger stopped.
            if (!exited) {
                TerminateProcess(process.hProcess, 1);
                var deadline = DateTime.UtcNow.AddMilliseconds(5000);
                while (true) {
                    if (pending)
                        ContinueDebugEvent(pid, tid, DBG_CONTINUE);
                    int left = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                    if (left <= 0 || !WaitForDebugEvent(debugEvent, (uint)left))
                        break;
                    pending = true;
                    pid = Marshal.ReadInt32(debugEvent, 4);
                    tid = Marshal.ReadInt32(debugEvent, 8);
                    if (Marshal.ReadInt32(debugEvent, 0) == EXIT_PROCESS_DEBUG_EVENT) {
                        ContinueDebugEvent(pid, tid, DBG_CONTINUE);
                        break;
                    }
                    Release(debugEvent, union);
                }
                DebugActiveProcessStop(process.dwProcessId);
            } else {
                ContinueDebugEvent(pid, tid, DBG_CONTINUE);
            }
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            Marshal.FreeHGlobal(debugEvent);
        }
        return result;
    }
}
'@

# The modules rldd resolves the static dependencies of an executable to: the
# ones the executable reaches without going through a delay load import.  A
# module is only expanded where it first shows on the tree, which may be below
# a delay load import while a static path reaches it elsewhere, so the tree is
# read as a graph of the modules and walked from the executable.  The value is
# the path each base name resolved to, and the names that did not resolve are
# listed apart.
#
# A forwarded module shows below the module that forwards to it, as the
# loader records it, whichever module imports the symbol, and that importer
# may itself be delay loaded.  So the walk that follows the forwarded modules
# (LOOSE) may take in a module the loader does not map at startup, and the one
# that does not may miss one it does.
function Get-StaticModules($Tree, [switch]$Loose) {
    $edges = @{ '' = [System.Collections.Generic.List[object]]::new() }
    $ancestors = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Tree.Entries) {
        while ($ancestors.Count -gt $entry.Level) {
            $ancestors.RemoveAt($ancestors.Count - 1)
        }
        $parent = if ($entry.Level -eq 0) { '' } else { $ancestors[$entry.Level - 1] }
        $key = if ($entry.Path) { $entry.Path.ToLowerInvariant() } else { "?$($entry.Recorded)" }
        $ancestors.Add($key)
        if (-not $edges.ContainsKey($key)) {
            $edges[$key] = [System.Collections.Generic.List[object]]::new()
        }
        if ($edges.ContainsKey($parent)) {
            $edges[$parent].Add($entry)
        }
    }

    $modules = @{}
    $missing = [System.Collections.Generic.List[string]]::new()
    $seen = @{ '' = $true }
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue('')
    while ($queue.Count) {
        foreach ($entry in $edges[$queue.Dequeue()]) {
            if ($entry.Attrs -contains 'delay-load' -or (-not $Loose -and $entry.Attrs -contains 'forwarded')) {
                continue
            }
            if (-not $entry.Path) {
                $missing.Add($entry.Recorded)
                continue
            }
            $key = $entry.Path.ToLowerInvariant()
            if ($seen.ContainsKey($key)) {
                continue
            }
            $seen[$key] = $true
            $modules[(Split-Path $key -Leaf)] = $entry.Path
            $queue.Enqueue($key)
        }
    }
    [pscustomobject]@{ Modules = $modules; Missing = $missing.ToArray() }
}

# The differences between where rldd resolves the static dependencies of an
# executable (STRICT and LOOSE, as Get-StaticModules builds them) and the
# modules the loader mapped.  The loader always maps ntdll, kernel32 and
# kernelbase, and a 32 bit process has the native WOW64 layer (System32) too,
# none of which needs an import.  Two things rldd does not read are kept
# apart: the assemblies the system default activation context redirects to,
# the comctl32 version 5.82 and the gdiplus version 1.1 ones, even without a
# manifest (rldd resolves them through the system directory), and the
# application compatibility shims, which bring apphelp.dll and the modules of
# the shims along with what they import.
function Compare-Paths($Loader, $Strict, $Loose) {
    $system32 = (Join-Path $env:SystemRoot 'System32\').ToLowerInvariant()
    $always = @('ntdll.dll', 'kernel32.dll', 'kernelbase.dll')
    $redirected = @{
        'comctl32.dll' = '\\winsxs\\[^\\]*_microsoft\.windows\.common-controls_[^\\]*_5\.82\.'
        'gdiplus.dll'  = '\\winsxs\\[^\\]*_microsoft\.windows\.gdiplus_[^\\]*_1\.1\.'
    }
    $mapped = @{}
    foreach ($path in $Loader.Modules) {
        $lower = $path.ToLowerInvariant()
        if ($Loader.Wow64 -and $lower.StartsWith($system32)) {
            continue
        }
        $mapped[(Split-Path $lower -Leaf)] = $path
    }

    $differences = [System.Collections.Generic.List[string]]::new()
    $default = 0
    $shims = 0
    foreach ($name in $Loose.Modules.Keys) {
        $resolved = $Loose.Modules[$name]
        if (-not $mapped.ContainsKey($name)) {
            if ($Strict.Modules.ContainsKey($name)) {
                $differences.Add("only rldd resolves $resolved")
            }
            continue
        }
        $path = $mapped[$name]
        if ($path -ieq $resolved) {
            continue
        }
        if ($redirected.ContainsKey($name) -and $path -match $redirected[$name]) {
            $default++
            continue
        }
        $differences.Add("rldd resolves $resolved, the loader maps $path")
    }
    $shimEngine = $mapped.ContainsKey('apphelp.dll')
    foreach ($name in $mapped.Keys) {
        if ($Loose.Modules.ContainsKey($name) -or $always -contains $name) {
            continue
        }
        if ($shimEngine) {
            $shims++
            continue
        }
        $differences.Add("only the loader maps $($mapped[$name])")
    }
    foreach ($name in $Strict.Missing) {
        $differences.Add("rldd does not resolve $name, and the process starts")
    }
    [pscustomobject]@{ Differences = $differences.ToArray(); SystemDefault = $default; Shims = [int]($shims -gt 0) }
}

# The NTSTATUS exception codes a process killed by an exception exits with,
# named for the common ones.  The release build of rldd aborts on a panic,
# which is a fast fail (STATUS_STACK_BUFFER_OVERRUN).
$ExceptionNames = @{
    0xC0000005u = 'STATUS_ACCESS_VIOLATION'
    0xC0000017u = 'STATUS_NO_MEMORY'
    0xC000001Du = 'STATUS_ILLEGAL_INSTRUCTION'
    0xC0000094u = 'STATUS_INTEGER_DIVIDE_BY_ZERO'
    0xC00000FDu = 'STATUS_STACK_OVERFLOW'
    0xC000013Au = 'STATUS_CONTROL_C_EXIT'
    0xC0000374u = 'STATUS_HEAP_CORRUPTION'
    0xC0000409u = 'STATUS_STACK_BUFFER_OVERRUN'
}

# How an rldd run ended, when an exception killed it: an exit status that is
# an NTSTATUS of the error severity (0xC0000000 on, as an unsigned 32 bit
# value), which a complete looking output does not tell.
function Get-Crash($ExitCode, [string]$Run) {
    if ($null -eq $ExitCode) {
        return ''
    }
    $status = [uint32]([int64]$ExitCode -band 0xFFFFFFFFL)
    if (($status -band 0xC0000000u) -ne 0xC0000000u) {
        return ''
    }
    $name = $ExceptionNames[$status]
    $code = '0x{0:X8}' -f $status
    if ($name) {
        $code = "$code ($name)"
    }
    return "rldd $Run exited with $code"
}

# The binary under test is always rebuilt, which is a no-op when it is up to
# date.
& cargo build --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
if ($LASTEXITCODE -ne 0) { Write-Die 'cargo build failed' }
$Rldd = (Resolve-Path -LiteralPath (Join-Path $RepoRoot 'target\release\rldd.exe')).Path

$Dumpbin = Find-Dumpbin
if (-not $Dumpbin) { Write-Die 'dumpbin was not found (install the Visual C++ build tools)' }

if ($Paths) {
    Add-Type -TypeDefinition $OracleSource
}
# The whole tree of an executable is large, so the workers read it, with the
# functions passed along as text.
$WorkerFunctions = @{
    'ConvertFrom-Rldd'  = ${function:ConvertFrom-Rldd}.ToString()
    'Get-StaticModules' = ${function:Get-StaticModules}.ToString()
}
# The working directory of both the executables and rldd, which holds no
# module to find there.
$Scratch = Join-Path ([IO.Path]::GetTempPath()) "rldd-paths-$PID"
New-Item -ItemType Directory -Force $Scratch | Out-Null

$binaries = @($Root | ForEach-Object {
        if (-not (Test-Path -LiteralPath $_)) {
            return
        }
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
if ($binaries.Count -eq 0) {
     Write-Die "no binary below $($Root -join ', ')"
}


$mismatch = [System.Collections.Generic.List[string]]::new()
$caseonly = [System.Collections.Generic.List[string]]::new()
$crashes = [System.Collections.Generic.List[string]]::new()
$errors = [System.Collections.Generic.List[string]]::new()
$missing = [System.Collections.Generic.List[string]]::new()
$notFound = [System.Collections.Generic.List[string]]::new()
$pathDiffs = [System.Collections.Generic.List[string]]::new()
$notStarted = [System.Collections.Generic.List[string]]::new()
$unreadable = 0
$refused = 0
$compared = 0
$started = 0
$systemDefault = 0
$shimmed = 0

Write-Host "Sweeping $($binaries.Count) objects with $Dumpbin"
$begin = Get-Date

try {
    # The workers start the tools and the comparison is done here as the
    # results arrive, which keeps a sweep of the whole system within memory.
    $binaries | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $dumpbin = & $using:Dumpbin /nologo /dependents $_ 2>&1 | Out-String
        $rldd = & $using:Rldd -a -p --depth 1 $_ 2>&1 | Out-String
        $result = [pscustomobject]@{
            File     = $_
            Dumpbin  = $dumpbin
            Rldd     = $rldd
            RlddExit = $LASTEXITCODE
            Loader   = $null
            Strict   = $null
            Loose    = $null
            TreeExit = $null
        }
        # Starting WerFault.exe, even up to the loader breakpoint, gets the
        # process that started it killed a moment later.
        if ($using:Paths -and $_ -match '\.exe$' -and (Split-Path $_ -Leaf) -notlike 'WerFault*') {
            foreach ($function in ($using:WorkerFunctions).GetEnumerator()) {
                Set-Item -Path "function:$($function.Key)" -Value $function.Value
            }
            Set-Location -LiteralPath $using:Scratch
            $result.Loader = [RlddLoaderOracle]::Run($_, $using:Scratch, $using:Timeout * 1000)
            $text = & $using:Rldd -a -p --depth 0 $_ 2>&1 | Out-String
            $result.TreeExit = $LASTEXITCODE
            $whole = ConvertFrom-Rldd $text
            $result.Strict = Get-StaticModules $whole
            $result.Loose = Get-StaticModules $whole -Loose
        }
        $result
    } | ForEach-Object {
        $output = $_
        $tree = ConvertFrom-Rldd $output.Rldd
        $reference = ConvertFrom-Dumpbin $output.Dumpbin
        # A panic prints its message, while an exception may kill the process
        # after a complete looking output, which only the exit status tells.
        $crash = @(
            if ($tree.Failure -match 'panicked at') { $tree.Failure }
            Get-Crash $output.RlddExit '-a -p --depth 1'
            Get-Crash $output.TreeExit '-a -p --depth 0'
        ) | Where-Object { $_ }
        if ($crash) {
            $crashes.Add("$($output.File): $($crash -join ', ')")
            return
        }
        if ($tree.Failure) {
            if ($reference.Failure) {
                # Neither tool takes it as a PE object.
                $unreadable++
            }
            else {
                $errors.Add("$($output.File): $($tree.Failure)")
            }
            return
        }

        # dumpbin refuses some objects rldd reads (a packed executable, an unusual
        # optional header), which leaves them unchecked instead of failing.
        if ($reference.Failure) {
             $refused++;
             return
        }
        $compared++

        # A forwarded module is pulled in by a symbol instead of by a directory
        # entry, and the .NET runtime shim by the CLR header, so dumpbin never
        # lists them.
        $entries = @($tree.Entries | Where-Object { $_.Attrs -notcontains 'forwarded' -and $_.Attrs -notcontains 'clr' })
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
            if (-not $detail) {
                 $detail = @('the entries are in another order')
            }
            $mismatch.Add("$($output.File): $($list.Kind): $($detail -join ', ')")
        }

        # A resolved path is built from the directory the module was found on, so
        # it has to name a file that exists.
        foreach ($entry in $entries) {
            if (-not $entry.Path) {
                $notFound.Add($entry.Recorded);
                continue
            }
            if (-not (Test-Path -LiteralPath $entry.Path)) {
                $missing.Add("$($output.File): $($entry.Path)")
            }
        }

        # The executable either reached the loader breakpoint, and the paths
        # are compared, or did not start (elevation, another machine, a
        # module the loader did not find), which is only listed.
        if ($output.Loader) {
            if ($output.Loader.Failure) {
                $notStarted.Add("$($output.File): $($output.Loader.Failure)")
                return
            }
            $started++
            $comparison = Compare-Paths $output.Loader $output.Strict $output.Loose
            $systemDefault += $comparison.SystemDefault
            $shimmed += $comparison.Shims
            foreach ($difference in $comparison.Differences) {
                $pathDiffs.Add("$($output.File): $difference")
            }
        }
    }
} finally {
    Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
}


$elapsed = [int]((Get-Date) - $begin).TotalSeconds
Write-Host "$compared compared in ${elapsed}s, $unreadable not a PE object, $refused unreadable by dumpbin"

$checks = @(
    @{ Failures = $mismatch; Pass = "the dependency names match on all $compared objects"; Fail = 'objects have another dependency list' }
    @{ Failures = $caseonly; Pass = 'every name is printed as the import directory records it'; Fail = 'objects print a name with another case' }
    @{ Failures = $crashes; Pass = 'no object made rldd crash'; Fail = 'objects made rldd crash (a panic or an exception)' }
    @{ Failures = $errors; Pass = 'rldd reads every object dumpbin reads'; Fail = 'objects dumpbin reads made rldd fail' }
    @{ Failures = $missing; Pass = 'every resolved dependency names a file that exists'; Fail = 'objects resolved a dependency to a path that does not exist' }
)
if ($Paths) {
    $checks += @{ Failures = $pathDiffs; Pass = "the static dependencies of the $started executables resolve where the loader maps them"; Fail = 'differences between the resolved paths and the modules the loader maps' }
}
# The first failures of each check, or all of them with -Verbose.
$shown = if ($VerbosePreference -eq 'Continue') { [int]::MaxValue } else { 10 }
foreach ($check in $checks) {
    if ($check.Failures.Count -eq 0) {
        Write-Pass $check.Pass
    } else {
        Write-Fail "$($check.Failures.Count) $($check.Fail)"
        $check.Failures | Select-Object -First $shown | ForEach-Object { Write-Detail $_ }
    }
}

# An unresolved dependency is expected on Windows (the delay load import of an
# optional component, an object of another machine), so they are only listed.
if ($notFound.Count) {
    $names = $notFound | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    Write-Detail "$($notFound.Count) unresolved dependencies, the most common being:"
    foreach ($name in $names) { Write-Detail "    $($name.Count)  $($name.Name)" }
}
if ($Paths) {
    if ($systemDefault) {
        Write-Detail "$systemDefault comctl32 or gdiplus mapped from the assembly of the system default activation context"
    }
    if ($shimmed) {
        Write-Detail "$shimmed executables with the application compatibility shims mapped"
    }
    if ($notStarted.Count) {
        Write-Detail "$($notStarted.Count) executables did not reach the loader breakpoint, among them:"
        $notStarted | Select-Object -First 5 | ForEach-Object { Write-Detail "    $_" }
    }
}

exit ([int]($Failed -gt 0))
