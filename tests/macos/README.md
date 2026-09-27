# macOS reference tool test

The Mach-O backend takes the load paths an object records to the dyld shared
cache, the filesystem or the OS cryptex, and what it reads out of an object
and where it takes it can only be checked against a real installation.  This
runs rldd over the Mach-O objects of the system directories and over the dyld
cache images, and compares each dependency list with the one `dyld_info
-dependents` (the Xcode Command Line Tools) reports.

## Running

```sh
tests/macos/run.py                                  # a sample of /usr and the dyld cache
tests/macos/run.py -n 0                             # all of them
tests/macos/run.py -r /Applications
tests/macos/run.py -r /usr/bin/true
tests/macos/run.py -r /System/Library -r /Library -r /Applications -n 0
```

The exit status is non-zero when any check fails.  Options:

| Option | Meaning |
| --- | --- |
| `-r`, `--root DIR` | sweep this directory, or single file, may be repeated (default: `/bin`, `/sbin` and `/usr`, plus the dyld cache images) |
| `-n`, `--sample N` | sweep a random sample of N objects, 0 meaning all of them (default: 200) |
| `-j`, `--jobs N` | parallel workers (default: the processor count) |

The prerequisites are the Xcode Command Line Tools, which provide `dyld_info`
and the `python3`.  The script first runs `cargo build --release`, a no-op
when the binary is up to date, so it never sweeps with a stale one.

## What is checked

| Check | What it covers |
| --- | --- |
| dependency lists | the load paths are the ones `dyld_info -dependents` lists for the slice rldd selects (the one the host launches: arm64e, arm64, then x86_64 on Apple Silicon, and x86_64h before x86_64 on a Haswell or newer Intel host), in the same order and with the same attributes (weak-link, re-export, upward, delay-init) |
| resolved paths | each one is where dyld takes the recorded load path: the cache image with the literal path, the file on disk, the copy below Cryptexe path, or the realpath of an absolute load path; the `[dyld cache]` tag agrees; and a dependency is only reported as not found when no location provides any candidate |
| crashes | no object makes rldd panic, die of a signal (the abort on a stack overflow, for instance), or time out |

## Differences that are not failures

**Objects the reference tool lists no dependencies for.**  `dyld_info` prints
no dependency section for a relocatable object or a kernel, aborts on the
kernel collections, and refuses the Metal libraries.  Those objects are
counted and never compared.  The fat static archives of the SDKs are left out
of the sweep, since dyld_info lists their members while rldd does not read
archives.

**Unresolved dependencies.**  A dependency reported as not found is checked
against every candidate location, and fails the run when one of them provides
the image.  Like dyld, rldd passes over a file the process does not load, so
such a file does not count as providing it: one without a slice of the
process architecture (derived from the input slice), one that is not a dylib,
or, for a macOS executable, one built for another platform.

**The cache listing gaps.**  `dyld_info -all_dyld_cache` lists fewer images
than dyld resolves, so an image rldd resolves through the cache that the
listing lacks is confirmed with `dyld_info` on the image itself and reported
for information.
