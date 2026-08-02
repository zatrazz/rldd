# rldd

The rldd tool resolves and prints the binary or shared library dependencies with different visualization options.  In opposite to the Linux ldd tool, it does not invoke the system loader but instead parses the loading information directly from either ELF or Mach-O files, along with any required system files (such as loader cache or extra configuration files).

Currently it supports Linux (glibc, android, and musl), FreeBSD, OpenBSD, NetBSD, Illumos (no support for crle/ld.config, trusted directories, or any environment variable), and macOS.

![screenshot](doc/screenshot.png)

## Output

The default visualization option prints unique dependencies, including loader and libc for Linux and BSD.

Use the '-a' option to print all dependencies (including already resolved ones), and the '-p' option to print fully resolved paths instead of just the soname.

The '-l' option mimics the ldd output, with unique libraries one per line.

## Relocation checks (ELF only)

Like ldd, the dynamic relocations can be processed to report unresolved symbol
references or unused dependencies (the resolution is done by symbol name, symbol
versioning is not taken in consideration):

- '-d' processes the data relocations and reports the undefined symbols that no
  loaded object defines.
- '-r' processes both the data and the function (PLT) relocations.
- '-u' prints the direct dependencies that provide no symbol used by the binary
  own relocations (like ldd, it suppresses the dependency listing and exits with
  status 1 when unused dependencies are found).


## Building from source

```
git clone git@github.com:zatrazz/rldd.git
cd rlld
cargo build --release
```
