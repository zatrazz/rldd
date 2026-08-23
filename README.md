# rldd

The rldd tool resolves and prints the binary or shared library dependencies with different visualization options.  In opposite to the Linux ldd tool, it does not invoke the system loader but instead parses the loading information directly from either ELF, Mach-O, or PE files, along with any required system files (such as loader cache or extra configuration files).

Currently it supports Linux (glibc, android, and musl), FreeBSD, OpenBSD, NetBSD, Illumos (no support for crle/ld.config, trusted directories, or any environment variable), macOS, and Windows.

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

## Windows

On Windows the dependencies are tracked the way 'dumpbin /dependents' and the Dependencies tool, where the DLL names recorded on the import and the delay load import directories are resolved  are resolved following the [documented search order for unpackaged applications](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#search-order-for-unpackaged-apps). The delay load dependencies are printed with the 'delay-load' attribute.

The 'api-ms-*' and 'ext-ms-*' virtual names are resolved with the API set schema from 'apisetschema.dll' and printed as 'NAME -> HOST', with the module that implements them.  A set that implements nothing on the running system is reported as not found.

The KnownDLLs are always resolved from the system directory, from the search order, and for 32 bit images the system directory is SysWOW64 instead of System32.  A candidate built for another machine is skipped and the search continues.

An imported symbol that resolves to a forwarded export pulls in the module it points at, which no import directory records.  Those dependencies are printed with the 'forwarded' attribute.

The dependent assemblies declared on the manifest are resolved against the WinSxS store, which the loader searches before the loaded module list, so the same name may be loaded from more than one assembly (the version 5 and the version 6 common controls are the usual case).  The embedded RT_MANIFEST resource is used when present, and an external '<object>.manifest' file otherwise.  The publisher policy is not read, the highest installed build of the requested major and minor version is used.

When a '<object>.local' directory exists the dependencies are taken from it, and when it is a plain file they are taken from the application directory; either way the redirection is searched before the known DLLs.

The search order is the application directory, the '--library-path' directories, the system directory, the 16 bit system directory, the Windows directory, the current directory, and at last the PATH directories.

The dependencies of a known DLL are also taken from the known DLLs directory, and an object whose imports were bound at link time is printed with the 'bound' attribute.

Since the recursive listing of a system binary expands to most of the system directory, only the direct dependencies are printed by default. The tree can be pruned with:

- '--depth N' limits the dependency tree to N levels, with 0 meaning no limit (the default is 1, the direct dependencies).
- '--ignore-prefix PREFIX' skips dependencies whose resolved path starts with the prefix (for instance '--ignore-prefix C:\Windows' to hide the system libraries). The option may be used multiple times and the comparison ignores case.

The remaining loader inputs are mimicked with options:

- '--library-path LIST' searches the semicolon-separated directories right after the application one, as SetDllDirectory and AddDllDirectory.
- '--no-safe-search' searches the current directory right after the application one, as the SafeDllSearchMode registry value set to 0.

The '-v' option also prints the object information: the machine, the subsystem, the image base, the API set schema and KnownDLLs status, the dependent assemblies with the directory they resolved to, and the search path list used for the resolution.

## Import checks (Windows only)

The PE equivalent of the ELF relocation processing is to check that every imported symbol is exported by the module it is imported from:

- '-d' checks the imports bound at load time and reports the ones no dependency exports.
- '-r' also checks the delay load imports, which the loader only binds on the first call.

There is no '-u' option: an import directory only records a module when a symbol is imported from it, so a PE object has no unused dependency to report.


## Relocation checks (Linux only)

Like ldd, the dynamic relocations can be processed to report unresolved symbol references, missing symbol versions, or unused dependencies.  The checks mimic the glibc loader and are only supported on Linux:

- '-d' processes the data relocations and reports the undefined symbols that no loaded object defines.
- '-r' processes both the data and the function (PLT) relocations.
- '-u' prints the direct dependencies that provide no symbol used by the binary own relocations (like ldd, it suppresses the dependency listing and exits with status 1 when unused dependencies are found).

## Building from source

```
git clone git@github.com:zatrazz/rldd.git
cd rlld
cargo build --release
```
