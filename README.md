# rldd

The rldd tool resolves and print the binary or shared library dependencies with different visualization options.  Similar to Linux ldd tool, it does not invoke the system loader but instead parse the loading information directly from either ELF of machO files.

Currently it supports Linux, FreeBSD, OpenBSD, and macOS.

![screenshot](doc/screenshot.png)

## Output

The default visualization option prints unique dependencies, including loader and libc for Linux and BSD.

Use the '-a' option prints all dependencies (including already resolved ones), while the '-p' option to print full resolved paths instead of just the soname.

The option '-l' mimics the ldd output, with unique libraries one per line.


## Building from sources

```
git clone git@github.com:zatrazz/rldd.git
cd rlld
cargo build --release
```
