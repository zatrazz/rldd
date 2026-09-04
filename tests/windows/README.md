# Windows reference tool test

The PE backend resolves the dependencies the way the loader documents it, and
what it reads out of an object can only be checked against a real installation.
This runs rldd over the binaries of a system directory and compares the
dependency names with the ones `dumpbin /dependents` (the Visual C++ build
tools) reports, which is the import and the delay load import directory
contents in their recorded order.

Everything else the backend does — the api set schema, the KnownDLLs, the
WinSxS store, the SysWOW64 redirection and the search order — is covered by the
unit tests under [src/pe/](../../src/pe/), which `cargo test` runs.

## Running

```powershell
tests\windows\run.ps1                          # a sample of System32
tests\windows\run.ps1 -Sample 0                # all of it
tests\windows\run.ps1 -Root C:\Windows\SysWOW64
tests\windows\run.ps1 -Root C:\Windows\System32\shell32.dll
tests\windows\run.ps1 -Root C:\ -Recurse -Sample 0   # every binary of the system
```

The exit status is non-zero when any check fails.  Options:

| Option | Meaning |
| --- | --- |
| `-Root PATH...` | the directories to sweep, or single files (default: `%SystemRoot%\System32`) |
| `-Recurse` | walk the directories, instead of taking only the objects directly below them |
| `-Sample N` | sweep a random sample of N objects, 0 meaning all of them (default: 200) |
| `-Throttle N` | parallel workers (default: the processor count) |

The binary under test is `target/release/rldd.exe`, built only when it is not
there yet, so a run right after `cargo build --release` tests what was just
built.

Prerequisites:

* PowerShell 7, for the parallel sweep.
* `dumpbin`, on `PATH` or found through `vswhere` in a Visual Studio install.

The default sample runs in a few seconds; `-Sample 0` sweeps the whole of
System32, around four thousand six hundred objects, in about a minute, and
`-Root C:\ -Recurse -Sample 0` every binary of the system.  The sweep
saturates at one worker per processor, since every object costs two process
starts; the workers only start the two tools, and the comparison is done in
the main runspace as the results arrive, so nothing but the two outputs
crosses back and a sweep of the whole system stays within memory.

The script is PowerShell rather than the shell the Android suite uses: dumpbin
is a Windows program, and the shell shipped with Git rewrites an argument like
`/dependents` into a path before it ever sees it.

## What is checked

rldd is invoked one way only, `-a -p --depth 1`, which prints every entry of
the first level with the name its own import directory records and the path it
resolved to.  That single form carries everything the checks below need; the
remaining options (`--library-path`, `--no-safe-search`, `--ignore-prefix`,
`-d`, `-r`, `-v`, `-l`) change the search or the presentation rather than what
is read out of the object, and belong to the unit tests.

| Check | What it covers |
| --- | --- |
| dependency names | the imports and the delay load imports are the ones `dumpbin /dependents` lists, in the same order |
| name spelling | each name is printed as its own import directory records it, not as the first entry that resolved to the module spells it |
| panics | no object makes rldd panic |
| resolved paths | every resolved dependency names a file that exists |

The dependency name check is what turned up the delay load imports dropped when
the descriptors and the names live on different sections, and the name spelling
one is what turned up the entries printed with the spelling of another import.

## Differences that are not failures

**Forwarded modules.**  A module pulled in by a forwarded export is an rldd
extension no import directory records, so those entries are left out of the
comparison.

**Objects the reference tool cannot read.**  dumpbin refuses some objects rldd
reads (a packed executable whose section table it cannot seek, an optional
header it rejects), and reports the files that are not a PE object at all as an
invalid format warning.  Those objects are counted, never compared.

**Unresolved dependencies.**  Unlike the ELF platforms, an unresolved
dependency is normal on Windows: a delay load import of a component that is not
installed, a driver importing a kernel module, or an object built for another
machine.  They are listed for information instead of failing the run.
