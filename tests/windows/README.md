# Windows reference tool test

The PE backend resolves the dependencies the way the loader documents it, and
what it reads out of an object can only be checked against a real system.
This test runs rldd over the binaries of a system directory and compares the
dependency names with the ones `dumpbin /dependents` (the Visual C++ build
tools) reports, which is the import and the delay load import directory
contents in their recorded order.  With `-Paths` it also starts every
executable of the sweep under the debugger and compares where rldd resolves
the static dependencies to with the modules the loader maps.

Everything else the backend does (the api set schema, the KnownDLLs, the
WinSxS store, the SysWOW64 redirection and the search order) is covered by the
unit tests under [src/pe/](../../src/pe/), which `cargo test` runs.

## Running

```powershell
tests\windows\run.ps1                          # a sample of System32
tests\windows\run.ps1 -Sample 0                # all of it
tests\windows\run.ps1 -Root C:\Windows\SysWOW64
tests\windows\run.ps1 -Root C:\Windows\System32\shell32.dll
tests\windows\run.ps1 -Root C:\ -Recurse -Sample 0   # every binary of the system
tests\windows\run.ps1 -Paths                   # also check the resolved paths
```

The exit status is non-zero when any check fails.  Options:

| Option | Meaning |
| --- | --- |
| `-Root PATH...` | the directories to sweep, or single files (default: `%SystemRoot%\System32`) |
| `-Recurse` | walk the directories, instead of taking only the objects directly below them |
| `-Sample N` | sweep a random sample of N objects, 0 meaning all of them (default: 200) |
| `-Throttle N` | parallel workers (default: the processor count) |
| `-Paths` | compare the resolved paths of the executables with the modules the loader maps |
| `-Timeout N` | the seconds an executable is given to reach the loader breakpoint (default: 10) |

The binary under test is `target/release/rldd.exe`, which `cargo build
--release` brings up to date first (a no-op when it already is).

Prerequisites:

* PowerShell 7, for the parallel sweep.
* `dumpbin`, on `PATH` or found through `vswhere` in a Visual Studio install.

The default sample runs for a limited set of binaries; `-Sample 0` sweeps the
whole of System32, and `-Root C:\ -Recurse -Sample 0` every binary of the system.

## What is checked

rldd is invoked with `-a -p --depth 1`, which prints every entry of the first
level with the name its own import directory records and the path it resolved
to.

| Check | What it covers |
| --- | --- |
| dependency names | the imports and the delay load imports are the ones `dumpbin /dependents` lists, in the same order |
| name spelling | each name is printed as its own import directory records it, not as the first entry that resolved to the module spells it |
| crashes | no object makes rldd panic or die of an exception |
| errors | rldd reads every object dumpbin reads |
| resolved paths | every resolved dependency names a file that exists |
| loader paths (`-Paths`) | the static dependencies of each executable resolve to the files the loader maps |

The dependency name check is what turned up the delay load imports dropped when
the descriptors and the names live on different sections, and the name spelling
one is what turned up the entries printed with the spelling of another import.

A crash is either a panic message or an exit status that is an NTSTATUS of the
error severity (0xC0000000 and above, as an unsigned 32 bit value), which is
how a process an exception kills exits, possibly after a complete looking
output: a stack overflow (0xC00000FD), an access violation (0xC0000005), or the
fast fail (0xC0000409, STATUS_STACK_BUFFER_OVERRUN) the release build aborts
with on a panic.  The report names the code, and the common ones by name.

## The loader paths

With `-Paths`, each executable of the sweep is started under the debugger
(`DEBUG_ONLY_THIS_PROCESS`, from a small C# helper the script compiles with
`Add-Type`), and the image paths of the `LOAD_DLL_DEBUG_EVENT` events are
collected up to the initial loader breakpoint, where the loader has mapped the
static imports and everything they pull in, and no code of theirs has run yet.
The process is killed there (for a 32 bit process, at the breakpoint of the
WOW64 layer, which comes after the native one), and every wait is bounded by
`-Timeout`.  The paths come from the file handles of the events, so the
modules of a 32 bit process name the SysWOW64 files, as rldd does.  Both the
executable and rldd run from an empty directory, so the current directory holds
no module.

rldd is then invoked with `-a -p --depth 0` on the executable, and its tree is
read as a graph of the modules, walked from the executable without crossing a
delay load import (a module is only expanded where it first shows, which may be
below a delay load import while a static path reaches it elsewhere).  Each
module the loader mapped has to be on it, at the same path, and each module on
it has to be mapped.

The executables that do not reach the loader breakpoint (the ones that ask for
elevation, the protected processes, the native ones, or a module the loader
fails on) are listed, not compared.  `WerFault.exe` is never started: starting
it, even up to the loader breakpoint, gets the process that started it killed
a moment later.

## Differences that are not failures

**Forwarded modules.**  A module pulled in by a forwarded export is an rldd
extension no import directory records, so those entries are left out of the
name comparison.  In the path comparison, such a module shows below the module
that forwards to it, whichever module imports the symbol, which may itself be
delay loaded: a forwarded module the loader did not map is not a failure, while
one it did map has to be on the tree.

**Modules the loader maps on its own.**  ntdll, kernel32 and kernelbase are
mapped whatever the imports say, and a 32 bit process has the native WOW64
layer (the System32 modules) too.  The application compatibility shims, which
the loader maps for the executables the compatibility database lists, bring
apphelp.dll and the modules of the shims (AcLayers.dll, with shlwapi.dll, for
msiexec.exe and regsvr32.exe) along; when apphelp.dll is mapped, the modules
only the loader maps are counted apart.

**The system default activation context.**  The loader maps comctl32 from the
version 5.82 assembly of WinSxS, and gdiplus from the version 1.1 one, when no
manifest asks for another version, even for an executable without a manifest,
while rldd resolves them through the system directory (the WinSxS manifests of
the system default context are compressed, so rldd does not read it).  Those
are counted apart.

**Objects the reference tool cannot read.**  dumpbin refuses some objects rldd
reads (a packed executable whose section table it cannot seek, an optional
header it rejects), and reports the files that are not a PE object at all as an
invalid format warning, and the 16 bit ones as an MS-DOS executable.  Those
objects are counted, never compared.

**Unresolved dependencies.**  Unlike the ELF platforms, an unresolved
dependency is normal on Windows: a delay load import of a component that is not
installed, a driver importing a kernel module, or an object built for another
machine.  They are listed for information instead of failing the run.
