# Linux reference tool test

This runs rldd over the ELF objects of the system directories and compares each
dependency list with the one `ldd` reports, which is what the glibc loader
lists in trace mode along with the file each dependency resolved to.  The
system objects only exercise the common search rules, so `cases.sh` (see
[below](#crafted-cases)) builds small objects for the other ones.

The machine under test is the local one or any host reached through ssh,
rldd is  cross built for its architecture and copied over along with the
sweep script, and the sweep runs there as a single ssh round trip.

## Running

```sh
tests/linux/run.sh                          # a sample of the local machine
tests/linux/run.sh -n 0                     # all of it
tests/linux/run.sh -r /usr/bin/ls
tests/linux/run.sh -H debian-aarch64 -H debian-ppc64le
```

Options:

| Option | Meaning |
| --- | --- |
| `-H`, `--host HOST` | test this ssh destination, may be repeated (default: the local machine, also named `local`) |
| `-r`, `--root DIR` | sweep this directory, or single file, may be repeated (default: `/bin`, `/sbin`, `/lib`, `/lib64` and `/usr`) |
| `-n`, `--sample N` | sweep a random sample of N objects, 0 meaning all of them (default: 200) |
| `-j`, `--jobs N` | parallel workers (default: the processor count of the machine under test) |
| `-k`, `--keep` | leave the files copied to the hosts, below `~/rldd-tests` on a remote one and a temporary directory on the local one |

The local machine is swept with a release build of the checkout, which the
script always builds (a no-op when it is up to date), in `$CARGO_TARGET_DIR`
when it is set.  The sweep runs a copy of the binary, so a build replacing it
meanwhile (a checkout shared over NFS, built from another machine) does not
pull it away; a binary that does not run on the machine, built on another one,
is reported before the sweep.

Prerequisites on the machine under test: `ldd`, the glibc or the musl one,
and `python3`.

### Remote hosts

The Rust target is picked from the `uname -m` of the host, taking the first
installed one of the static musl target and the glibc one (`rustup target add`
the one wanted).  A musl target is linked with `rust-lld` and the self
contained runtime, so it needs no cross compiler and runs on any glibc
release; a glibc target is linked with the cross compiler of the distribution
(`aarch64-linux-gnu-gcc` and the like), and the binary needs a glibc on the
host at least as recent as the cross sysroot.  A `CARGO_TARGET_<TRIPLE>_LINKER`
already set in the environment is left alone.

A musl built rldd inspects a glibc system the same way as a glibc built one:
the loader of an object is read from its `PT_INTERP`, and the `ld.so.cache`
from its usual place.

## What is checked

rldd is invoked one way only, `-l`, which prints the unique dependency list as
one `name => path` per line.

| Check | What it covers |
| --- | --- |
| dependency lists | every object lists the same dependencies as `ldd`, each one resolved to the same file |
| panics | no object makes rldd panic, crash (a signal, such as a stack overflow) or time out, and rldd reads every object ldd traces |

The order of the listing is not compared: ldd prints the objects in load order
and rldd -l in dependency tree order.  The vDSO entry ldd lists is not a
dependency any object records, so it is ignored.  The loader entry is matched
through `realpath`, since ldd prints the loader with its own path and no name
where rldd prints the `DT_NEEDED` entry naming it and where the object
resolves it.

## Differences that are not failures

**What a sweep of `/` leaves out.**  The walk hands the directories to the
workers as they are found, and does not descend into the virtual filesystems
(proc, sysfs, the tmpfs and cgroup mounts), the FUSE ones, the network ones
(NFS, CIFS), the removable media below `/media`, `/mnt` and `/run/media`, nor
below `/usr/lib/debug`; any of them given as a root is swept.  A directory
the user cannot enter is counted and reported, so a sweep as root covers what
a sweep as a user cannot.  A file is opened to read its ELF header, so a sweep
of a large home directory is bound by the disk, and the sample is only drawn
once the walk is complete.

**The loader line.**  The glibc trace lists the loader only when an object
names it before 2.37, so a library whose closure has no libc gets no loader
line there, where the later releases list it always, as rldd does; the rldd
entry is accepted when ldd prints no loader at all.

**The interpreter line.**  ldd runs an object under its own loader whatever
the `PT_INTERP` says, and prints the interpreter as `PT_INTERP => loader`
when the two differ (a glibc build tree), where rldd resolves the name to the
interpreter itself.  Either is accepted for the loader entry.  A library one of
its dependencies refers back to is printed the same way, as a bare path, and
matched the same way.

**The musl ldd.**  It lists the libc under the loader path (`libc.musl-x86_64.so.1
=> /lib/ld-musl-x86_64.so.1`), which rldd prints the same way, and reports a
library it cannot find as an error on stderr rather than as `not found`, which
the sweep reads as one.

**Objects ldd cannot trace.**  ldd reports `not a dynamic executable` for the
objects of another machine (the cross compiler sysroots below
`/usr/<triplet>/lib`), the static binaries, the kernel modules and the klibc
programs.  An object whose `PT_INTERP` is not the loader ldd belongs to (a
test loader of the gdb testsuite, a musl binary on a glibc system) is traced by
ldd under its own loader, the way it would not run.  Those are counted, never
compared.  A library naming another loader than the system one (a GNU/Hurd
library naming `ld.so.1`) is traced all the same, with the loader of the ldd
process printed; rldd reporting the named one not found is accepted.

**Unresolved dependencies.**  A dependency both tools report as not found is
listed for information: a plugin whose host program is not installed, or a
library of an optional package.  A dependency only one of them resolves is a
failure.

## Crafted cases

`cases.sh` builds, for each case, a few small libraries and programs with gcc
in a temporary directory, and checks the rldd result on them on the local
machine:

```sh
tests/linux/cases.sh                        # every case
tests/linux/cases.sh nodeflib preload       # some of them
tests/linux/cases.sh -b path/to/rldd        # another binary than the checkout build
```

Options:

| Option | Meaning |
| --- | --- |
| `-b`, `--rldd PATH` | check this binary (default: a release build of the checkout, in `$CARGO_TARGET_DIR` when it is set) |
| `-k`, `--keep` | leave the objects built for the cases, and print where |
| `-l`, `--list` | list the cases |

Prerequisites: the glibc `ldd`, `gcc`, `readelf`, `objcopy`, `realpath`,
`python3` and `bash`.

Most cases compare the `rldd -l` listing with the `ldd` one (with the same
`LD_PRELOAD` or `LD_LIBRARY_PATH` as the rldd option), each dependency
resolved through `realpath`, and the loader and vDSO lines left out.  The
`-d`/`-r` cases compare the version and undefined symbol diagnostics, with
the directories left out.  The other cases check the rldd output against the
expected result, where ldd can not tell:

* the objects the glibc loader fails the whole load on (a candidate of
  another OS ABI, a separate debug info file, a linker script, an executable),
  where ldd only prints the error, and a preload of another class, which ldd
  leaves out: rldd reports the dependency as not found, with the loader error
  in verbose mode;
* the musl rules, with programs naming a musl loader in the temporary
  directory (it does not need to exist, nothing is run), and a path file next
  to it;
* the rules of the older glibc releases (the legacy hwcaps subdirectories),
  with programs naming a copy of the loader whose version banner claims glibc
  2.35, or which has none like the ones before 2.33.

| Case | What it covers |
| --- | --- |
| `rpath`, `runpath` | the DT_RPATH chain of the loading objects, which DT_RUNPATH is not part of and hides |
| `tokens`, `origin-literal` | `$ORIGIN` and `${ORIGIN}`, while `$ORIGINAL` is a directory name |
| `lib`, `platform` | `$LIB` and `${PLATFORM}`, with the values the loader prints on `--list-diagnostics` (skipped without them) |
| `empty-entry` | an empty DT_RPATH or DT_RUNPATH entry is the current directory |
| `nodeflib` | DF_1_NODEFLIB: the objects already loaded are still used, the default directories are not searched |
| `preload`, `library-path` | the tokens of the `--preload` and `--library-path` entries, the `;` separator and the empty entry of the latter |
| `slash-needed` | a DT_NEEDED entry naming a path with a token |
| `soname` | a name matching the soname of a preloaded object |
| `not-found-then-found` | a library a module does not find, loaded by the next one, and reused by a later one |
| `symlink-root` | the `$ORIGIN` of a library given through a symlink |
| `wrong-class`, `verify` | the candidate files the loader skips or fails the load on |
| `versions` | the version check diagnostics and the symbol version binding rules |
| `musl` | the musl search order, rpath chain and path file |
| `hwcaps` | the glibc-hwcaps subdirectories of the DT_RPATH, DT_RUNPATH and library path directories (for the ones `ld.so --help` lists, skipped without them) |
| `legacy-hwcaps` | the legacy hwcaps subdirectories (tls and the like) of the glibc 2.36 and older loaders, with copies of the loader claiming an older release (skipped for a loader without version banner) |
