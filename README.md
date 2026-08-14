# rldd

The rldd tool resolves and prints the binary or shared library dependencies with different visualization options.  In opposite to the Linux ldd tool, it does not invoke the system loader but instead parses the loading information directly from either ELF or Mach-O files, along with any required system files (such as loader cache or extra configuration files).

Currently it supports Linux (glibc, android, and musl), FreeBSD, OpenBSD, NetBSD, Illumos (no support for crle/ld.config, trusted directories, or any environment variable), and macOS.

![screenshot](doc/screenshot.png)

## Output

The default visualization option prints unique dependencies, including loader and libc for Linux and BSD.

Use the '-a' option to print all dependencies (including already resolved ones), and the '-p' option to print fully resolved paths instead of just the soname.

The '-l' option mimics the ldd output, with unique libraries one per line.

## macOS

On macOS the dependencies are tracked the way 'dyld_info -dependents' and 'otool -L', where the load paths from the dylib load commands are taken verbatim (with @executable_path, @loader_path, and @rpath expanded) and resolved against the dyld shared cache (if existent) and the filesystem.  The dependencies are printed with their full path, along with the load command attributes as reported by dyld_info (weak-link, re-export, upward, and delay-init).

Like dyld_info, the input file may be an install name of an image that only exists inside the dyld shared cache.

The '--arch NAME' option selects the given slice of a universal binary instead of the host architecture, along with the matching dyld shared cache flavor (for instance '--arch x86_64' on Apple Silicon resolves against the Rosetta cache, when installed).

Since the recursive listing of a system binary expands to most of the dyld shared cache, only the direct dependencies are printed by default, and the tree can be pruned with:

- '--depth N' limits the dependency tree to N levels, with 0 meaning no limit (the default is 1, the direct dependencies).
- '--ignore-prefix PREFIX' skips dependencies whose load path starts with the prefix (for instance '--ignore-prefix /usr/lib' to hide the system libraries); the option may be used multiple times.

The '--preload' option mimics DYLD_INSERT_LIBRARIES.  The other dyld environment variables are also mimicked with options, following the dyld search order:

- '--library-path LIST' (DYLD_LIBRARY_PATH) searches the colon-separated directories for the dependency leaf name before the recorded load path.
- '--framework-path LIST' (DYLD_FRAMEWORK_PATH) searches the directories for the framework partial path (Foo.framework/Versions/A/Foo) before the recorded load path.
- '--fallback-library-path LIST' and '--fallback-framework-path LIST' (DYLD_FALLBACK_LIBRARY_PATH and DYLD_FALLBACK_FRAMEWORK_PATH) are searched after the dependency is not found on the recorded load path.
- '--image-suffix SUFFIX' (DYLD_IMAGE_SUFFIX) tries each candidate path with the suffix first (inserted before the .dylib extension, or appended otherwise).

The '-v' option also prints the object information from the load commands: the install name (like otool -D), the platform (dyld_info -platform), the UUID (dyld_info -uuid), and the dependencies compatibility and current versions (otool -L).

## Relocation checks (Linux only)

Like ldd, the dynamic relocations can be processed to report unresolved symbol
references, missing symbol versions, or unused dependencies.  The checks mimic
the glibc loader and are only supported on Linux:

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
