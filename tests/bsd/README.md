# BSD reference tool test

This runs rldd over the ELF objects of the system directories of a FreeBSD,
OpenBSD or NetBSD machine and compares each dependency list with the one its
`ldd` reports.

## Running

```sh
tests/bsd/run.sh                          # a sample of the local machine
tests/bsd/run.sh -H freebsd -H openbsd -H netbsd
tests/bsd/run.sh -H netbsd -n 0           # all of it
tests/bsd/run.sh -H openbsd -r /usr/local
```

The exit status is non-zero when any check fails, and a host that cannot be
reached or built on is reported and skipped rather than ending the run.
Options:

| Option | Meaning |
| --- | --- |
| `-H`, `--host HOST` | test this ssh destination, may be repeated (default: the local machine) |
| `-r`, `--root DIR` | sweep this directory, or single file, may be repeated (default: `/bin`, `/sbin`, `/lib`, `/libexec` and `/usr`) |
| `-n`, `--sample N` | sweep a random sample of N objects, 0 meaning all of them (default: 200) |
| `-j`, `--jobs N` | parallel workers (default: the processor count of the machine under test) |
| `-k`, `--keep` | leave the files copied to the hosts, below `~/rldd-tests` on a remote one and a temporary directory on the local one |

Prerequisites on the machine under test: `ldd`, `python3`, and for a remote
host a Rust toolchain with `cargo`.  The machine is accessed through ssh,
so a passwordless ssh login and access to the crates the build needs.

The sweep runs a copy of the local binary, so a build replacing it meanwhile
does not pull it away.

## What is checked

| Check | What it covers |
| --- | --- |
| dependency lists | every object lists the same dependencies as `ldd`, each one resolved to the same file |
| panics | no object makes rldd panic, and rldd reads every object ldd traces |

The order of the listing is not compared.  The NetBSD ldd is asked for its
`-f` format with the library name pieces, from which the `DT_NEEDED` name is
built back (`-lc.12` is `libc.so.12`).

## Differences that are not failures

**What a sweep of `/` leaves out.**  The walk does not descend into the
virtual filesystems (devfs, procfs, fdescfs, kernfs, tmpfs and the like), the
FUSE ones or the network ones, nor below the debug files directories; a
directory the user cannot enter is counted and reported.

**What the loader brings along.**  For a library, ldd does not list what the
loader of its own process already had.  For instance, the FreeBSD rtld loads
`libsys` itself, and the OpenBSD ldd dlopens the library into a process that
already has the libc and the loader.  Those entries are dropped from the rldd
listing of a library when ldd lacks them.

**The OpenBSD listing.**  Its ldd stops at the first library it cannot load,
so for such an object only that one is compared, which rldd has to report as
not found too.

**Objects ldd cannot trace.**  A static binary (`not a dynamic ELF
executable` on FreeBSD, the ELF class message of the NetBSD ldd, a lone row on
OpenBSD), a set-user-ID one on FreeBSD, whose loader ignores the trace request,
and a kernel image.  Those are counted, never compared.

**Unresolved dependencies.**  A dependency both tools report as not found is
listed for information.  A dependency only one of them resolves is a failure.
