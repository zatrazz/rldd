# rldd

The rldd tool mimics the ldd shared libraries resolution and also adds some visualization options.  It is not a direct replacement, since ldd invokes the system loader and provides some extra options that are only possible at program loading (such as --unused).

![screenshot](doc/screenshot.png)

## Output

The default visualization option prints all dependencies, including loader, libc, and duplicated entries in a tree format.

Use the '-u' option filters out the duplicated entries, and the '-p' option to print full resolved paths instead of just the soname.

The option '-l' mimics the ldd output, with unique libraries one per line.


## Building from sources

```
git clone git@github.com:zatrazz/rldd.git
cd rlld
cargo build --release
```
