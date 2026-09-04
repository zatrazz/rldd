# macOS reference tool test

The Mach-O backend takes the load paths an object records to the dyld shared
cache, the filesystem or the OS cryptex, and what it reads out of an object
and where it takes it can only be checked against a real installation.  This
runs rldd over the Mach-O objects of the system directories and over the dyld
cache images, and compares each dependency list with the one `dyld_info
-dependents` (the Xcode Command Line Tools) reports: the load paths in their
recorded order, their attributes, and whether the path rldd resolved to is
the one the recorded load path leads to.

The rest of the backend — the run-path expansion, the cryptex candidate, the
environment options and the output modes — is covered by the unit tests
under [src/macho.rs](../../src/macho.rs), which `cargo test` runs.

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

The binary under test is `target/release/rldd`, built only when it is not
there yet, so a run right after `cargo build --release` tests what was just
built.

Prerequisites: the Xcode Command Line Tools, which provide `dyld_info` and
the `python3` the script is written in.

The default sample runs in a few seconds; `-n 0` sweeps the whole of `/usr`
and the dyld cache, around five thousand objects, in well under a minute, and
the last example above every object of the system in about a minute and a
half.  The sweep saturates at one worker per processor, since every object
costs two process starts; the workers only start the two tools, and the
comparison is done in the main process as the outputs arrive.  Ctrl-C ends
the run with the exit status 130.

The script is python rather than the shell the Android suite uses: checking
where a load path leads needs the cache listing, the run-path expansion and
realpath at hand for every dependency, and python3 comes with the same
Command Line Tools that provide dyld_info.

## What is checked

rldd is invoked one way only, `rldd OBJECT`, which prints the direct
dependencies with the path each one resolved to, its attributes and the
location it was found at.  That single form carries everything the checks
below need; the remaining options (`--arch`, `--depth`, `--ignore-prefix`,
`--library-path` and the other environment paths, `--preload`, `-v`, `-l`,
`-a`, `-p`) change the search or the presentation rather than what is read
out of the object, and belong to the unit tests.

| Check | What it covers |
| --- | --- |
| dependency lists | the load paths are the ones `dyld_info -dependents` lists for the slice rldd selects, in the same order and with the same attributes (weak-link, re-export, upward, delay-init) |
| resolved paths | each one is where dyld takes the recorded load path: the cache image with the literal path, the file on disk, the copy below `/System/Volumes/Preboot/Cryptexes/OS`, or the realpath of an absolute load path; the `[dyld cache]` tag agrees; and a dependency is only reported as not found when no location provides any candidate |
| panics | no object makes rldd panic |

The resolved path check is what turned up the three dyld behaviours the
backend had to learn: a recorded load path through a symlinked directory (or
with `..` or a double slash) reaching a cache only image, the retry below the
OS cryptex, and a run-path entry ending with a slash joined without a second
one.

## Differences that are not failures

**Objects the reference tool lists no dependencies for.**  `dyld_info` prints
no dependency section for a relocatable object or a kernel, aborts on the
kernel collections, and refuses the Metal libraries.  Those objects are
counted, never compared.  The fat static archives of the SDKs are left out of
the sweep, since dyld_info lists their members while rldd does not read
archives.

**Unresolved dependencies.**  A dependency reported as not found is checked
against every candidate location, and fails the run when one of them provides
the image.  The rest is normal on macOS: the Swift runtime of an application
built for another platform, an application framework left out of the bundle,
or the `UIKit` of an iOS object.  They are listed for information.

**The cache listing gaps.**  `dyld_info -all_dyld_cache` lists fewer images
than dyld resolves (`/usr/lib/swift/libswiftWebKit.dylib` for instance), so an
image rldd resolves through the cache that the listing lacks is confirmed with
`dyld_info` on the image itself and reported for information.
