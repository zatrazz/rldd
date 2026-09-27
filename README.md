# rldd

The rldd tool resolves and prints the binary or shared library dependencies
with different visualization options.  Unlike the Linux ldd tool, it does not
invoke the system loader.  Instead, it parses loading information directly from
ELF, Mach-O, or PE files, along with any required system files (such as the
loader cache or extra configuration files), and follows the search rules of
each system loader.

Currently, it supports Linux (glibc, musl, and Android), FreeBSD, OpenBSD,
NetBSD, illumos, macOS, and Windows.

Each build inspects the object format of the system it runs on: ELF on Linux,
Android, the BSDs, and illumos (or Solaris, which uses the illumos rules),
Mach-O on macOS, and PE on Windows.  A file of another object format is
reported as such (for instance `not an ELF object (this build inspects ELF
objects only)`).  The dependencies are resolved against the running system,
with its loader configuration, caches, and directories; there is no option to
resolve them against another root filesystem (a sysroot).

![screenshot](https://raw.githubusercontent.com/zatrazz/rldd/main/doc/screenshot.png)

## Installation

rldd needs Rust 1.88 or later.  To install it from crates.io:

```
cargo install rldd
```

Or to build it from source:

```
git clone https://github.com/zatrazz/rldd.git
cd rldd
cargo build --release
```

The binary is then `target/release/rldd`.  rldd builds for the `linux`,
`android`, `freebsd`, `netbsd`, `openbsd`, `illumos`, `solaris`, `macos`, and
`windows` target_os values, and a build for any other target fails with a
compile error listing them.

## Usage

```
rldd [OPTIONS] FILE...
```

For instance:

```
rldd /usr/bin/ssh                           # the dependency tree
rldd -l /usr/bin/ssh                        # one line per dependency, like ldd
rldd -p -a /usr/lib/libcurl.so.4            # resolved paths, repeated entries
rldd -v --library-path=/opt/foo/lib ./prog  # with LD_LIBRARY_PATH set
rldd --depth 0 /usr/bin/ssh                 # macOS: the whole tree
rldd --depth 0 C:\Windows\System32\cmd.exe  # Windows: the whole tree
```

The options common to every build are:

* `-a`, `--all` prints the dependencies already resolved as well, each time an
  object requests them.
* `-p`, `--path` prints the resolved path instead of the library name (always
  set on macOS).
* `-l`, `--ldd` prints an output similar to ldd.
* `-v`, `--verbose` prints the search path and object information, and the
  locations searched for each dependency not found.
* `-h`, `--help` prints the usage.

The loader environment variables and the other loader inputs are mimicked with
options, described on each system section: `--library-path`, `--preload`, and
`--platform` on the ELF systems; `--library-path`, `--framework-path`,
`--fallback-library-path`, `--fallback-framework-path`, `--preload`,
`--image-suffix`, and `--arch` on macOS; and `--library-path` and
`--no-safe-search` on Windows.  macOS and
Windows also have `--depth` and `--ignore-prefix` to prune the tree.  The
relocation checks (`-d`, `-r`, and `-u`) are only available on Linux, and the
import checks (`-d` and `-r`) on Windows.

An option that takes a value accepts it either as the next argument or in the
`--option=value` form.  Only `-h` and `--help` print the usage, so a file named
`help` is inspected like any other.  The files start at the first argument that
is neither an option nor an option value (or after `--`), and every argument
from there on is a file.

The exit status is:

* 0 when every file was processed, even if some dependencies were not found
  (like the glibc ldd).
* 1 when a file could not be processed (it does not exist, is a directory, is
  not an object of the format the build inspects, or its name is not valid
  UTF-8), on a command line error (an unknown option, a missing or invalid
  value, or no file at all), when `-u` finds unused dependencies, or when
  writing to the standard output fails for any other reason than a closed
  pipe.
* 127 when the default listing of a musl program finds unresolved symbols
  (Linux only), like the musl ldd.

With several files, the status set by the last file that failed is the one
returned (a file processed afterwards does not reset it).  When the standard
output reader goes away (for instance `rldd ... | head`), rldd exits quietly
with the status due so far.

## Output

The default visualization option prints the dependency tree of each file, with
each dependency printed once, below the first object that requests it, and
tagged with where it was resolved from (`[rpath]`, `[runpath]`,
`[LD_LIBRARY_PATH]`, `[preload]`, `[ld.so.cache]` or the cache of the system,
`[system default paths]`, `[direct]` for a path, and so on).  A dependency
whose resolved file differs from the recorded name is printed as `NAME ->
FILE`.  The tree is colorized when the standard output is a terminal, unless
`NO_COLOR` is set or `TERM` is `dumb` (or unset, outside Windows).

Use the `-a` option to print all dependencies (including already resolved
ones), and the `-p` option to print fully resolved paths instead of just the
soname.

The `-l` option mimics the ldd output, listing unique libraries on separate
lines.  Since the loader is not invoked, no load addresses are printed, the ELF
and PE entries follow the dependency resolution order instead of the loader
load order (the Mach-O ones follow the dyld load order), and the virtual
objects provided by the kernel (like the Linux vdso) are not listed.  It also
resolves binaries the loader refuses to trace, such as the set-user-ID ones or
the ones without execute permission on the BSDs, where ldd runs the target
under the loader.  A header line is only printed when multiple files are given,
with the file base name instead of the full path the BSD ldd prints.

## ELF (Linux, Android, BSD, and illumos)

On the ELF platforms, the dependencies are tracked from the DT_NEEDED entries,
and resolved in breadth-first order like the loaders: every DT_NEEDED entry of
an object is looked up before the dependencies of the objects it leads to, so a
library several objects need is resolved with the search paths of the first one
that requests it.  The search order of each loader is described on its section
below.  When a dynamic tag is repeated, the last DT_RPATH, DT_RUNPATH,
DT_SONAME, and DT_FLAGS_1 entry is the one used, as the loaders record them.

Before any search, a name is matched against the objects already loaded: the
names they were loaded under, and on glibc, FreeBSD, and OpenBSD their
DT_SONAME too (the one of the input object included, so a dependency or preload
entry naming it is not listed).  A file the search finds that is already loaded
under another name (through a symlink) is not loaded again.  A dependency not
found is searched again for each object that requests it, with the search paths
of that object.  The Android linker looks the objects up on its namespaces
instead (see below).  A name containing a slash is opened as a file path,
relative to the current directory when it is not absolute, instead of being
searched.

The DT_RPATH scope used for the indirect dependencies follows each loader
semantics:

* The glibc loader searches the object own DT_RPATH and then walks up the chain
  of loading objects (up to the executable), unless the object requesting the
  dependency has DT_RUNPATH.  The musl loader walks the same chain, where an
  object DT_RUNPATH takes the place of its DT_RPATH.
* The FreeBSD loader searches the object own DT_RPATH and then the main program
  one, neither of them when the object has DT_RUNPATH.
* The OpenBSD loader searches the object DT_RUNPATH, or without one its own
  DT_RPATH and then the main program one.  The executable keeps its DT_RPATH
  for that purpose even when it also has DT_RUNPATH, although its own
  dependencies only search the DT_RUNPATH.
* The NetBSD and illumos loaders only search the requesting object list, which
  is the last of its DT_RPATH and DT_RUNPATH entries (both tags are recorded
  in the same slot).
* The Android linker does not implement DT_RPATH, and only searches the
  requesting object DT_RUNPATH.

A shared library given as input is not a main program, so on FreeBSD and
OpenBSD its DT_RPATH does not apply to its indirect dependencies.

The search lists are split the way each loader splits them:

* glibc splits DT_RPATH and DT_RUNPATH on colons, and `--library-path` on
  colons and semicolons.  An empty entry is the current directory (shown as
  `.`), while a list without any entry is ignored.
* musl splits the lists on colons and newlines, skipping the empty entries.
* FreeBSD and OpenBSD split every list on colons and semicolons, skipping the
  empty entries.
* NetBSD and Android split the lists on colons, skipping the empty entries.
* illumos splits the lists on colons and semicolons, where an empty entry
  between colons, or at an end of the list, is the current directory.

The dynamic string tokens are expanded the way each loader does:

* glibc expands `$ORIGIN`, `$LIB`, and `$PLATFORM`, with or without braces, a
  bare one only when no identifier character follows it (so `$ORIGINAL` is a
  directory name), on DT_RPATH, DT_RUNPATH, DT_NEEDED, `--library-path`, and on
  the `--preload` and `/etc/ld.so.preload` entries naming a path.  An entry with
  a token without a value (`$PLATFORM` on RISC-V, or an `$ORIGIN` that is not
  valid UTF-8) is dropped, and a DT_NEEDED entry is not loaded.
* musl only expands `$ORIGIN` on DT_RPATH and DT_RUNPATH, matched as a prefix
  (so `$ORIGINAL` is the origin followed by `AL`), and ignores the whole list
  when it holds any other `$`.
* FreeBSD expands `$ORIGIN`, `$OSNAME`, `$OSREL`, `$PLATFORM` (the uname
  sysname, release, and machine), and `$LIB` (`lib`, or `lib32` for a 32-bit
  compat object), with or without braces and whatever follows them, on
  DT_RPATH, DT_RUNPATH, and a DT_NEEDED name with a slash, but not on
  `--library-path` or `--preload`.
* OpenBSD only expands the DT_RPATH and DT_RUNPATH entries: a `$` followed by a
  name of letters, digits, and underscores, maybe within braces, where
  `$ORIGIN`, `$OSNAME`, `$OSREL`, and `$PLATFORM` expand to the object
  directory and the uname sysname, release, and machine, and any other name to
  nothing.
* NetBSD expands `$ORIGIN`, `$OSNAME`, `$OSREL`, and `$PLATFORM` (the
  kern.ostype, kern.osrelease, and hw.machine_arch values, the netbsd32 one for
  a 32-bit compat object), and `$HWCAP` and `$ISALIST` to nothing, as `$NAME`
  not followed by a letter or as `${NAME}`, on DT_RPATH, DT_RUNPATH,
  `--library-path`, and the `ld.so.conf` directories, but not on the dependency
  or preload names.  An entry that expands to nothing is dropped.
* illumos expands `$ORIGIN`, `$PLATFORM` (uname -i), `$MACHINE` (uname -m),
  `$OSNAME`, `$OSREL`, and `$ISALIST`, recognized right after the `$` without
  braces, on DT_RPATH, DT_RUNPATH, `--library-path`, and the dependency and
  preload names.  `$ISALIST` makes one search list entry for each instruction
  set, in order (the first one elsewhere).  An entry with a token that can not
  be expanded (`$CAPABILITY`, `$HWCAP`, or a second `$ISALIST`) is dropped.
* Android expands `$ORIGIN` and, from Android 10, `$LIB` on DT_RUNPATH only
  (see the Android section).

The entries dropped because of a token are shown as `unexpanded` on the `-v`
search path information.

The `$ORIGIN` token follows each loader:

* glibc and musl expand it to the directory of the path the object was loaded
  through.  For the input object, it is the canonical path of an executable
  (which the kernel resolves), and the path as given for a shared library, the
  way dlopen (and so ldd) takes it.
* The FreeBSD, OpenBSD, illumos, and Android loaders canonicalize the object
  path first, so a symlink or a `..` component on a search path is not kept.
* The NetBSD loader expands it to the directory of the path each object was
  found at, without resolving it, and to the input object directory for the
  `--library-path` and `ld.so.conf` entries.

The DF_1_NODEFLIB flag of the object requesting a dependency restricts the
search the way each loader does, while the objects already loaded are still
matched:

* glibc skips the default directories, and the loader cache entries below them
  (an entry of another `ld.so.conf` directory is still used).
* FreeBSD skips the standard directories, and the hints directories that are
  also standard ones.
* illumos skips the default directories.
* musl, Android, NetBSD, and OpenBSD ignore the flag.

A candidate file the loader opens for a dependency is checked the way it does,
where the loader either goes on with the search or fails the load:

* glibc skips a file of another ELF class or machine (the machine check also
  covering the RISC-V float ABI, the MIPS o32 and n32 ABIs and NaN encoding, and
  the PowerPC64 ELF ABI version), and fails the load on any other mismatch:
  another data encoding, OS ABI, or ABI version, an ARM float ABI mismatch, a
  file that is not an ELF object (such as a linker script) or is too short, an
  executable, or an object without dynamic section (a separate debug info
  file).
* musl takes the first file it opens, and fails the load on any mismatch.
* The Android linker takes the first file that opens, and fails the load on the
  namespace unless it is a shared object of its class, byte order, and machine.
* FreeBSD takes the first file that exists, and fails the load on another class,
  data encoding, or machine, or on a file that is not an ELF object.
* OpenBSD fails the load unless the file is an ELF shared object of the loader
  class, byte order, and machine.
* NetBSD skips a file of another class, data encoding, or machine.
* illumos skips a file of another class, data encoding, or machine, or with an
  OS ABI other than the System V or Solaris one.

The Android, FreeBSD, OpenBSD, and NetBSD loaders do not check the OS ABI.  A
dependency the loader fails on is reported as not found, with the file and
the loader error as its searched location in verbose mode.

The loader environment variables are mimicked with options:

* `--library-path LIST` (LD_LIBRARY_PATH) searches the listed directories,
  split and expanded as described above.
* `--preload LIST` (LD_PRELOAD) preloads the listed objects.  The glibc and the
  Android loaders split the list on spaces and colons (a tab is part of a name,
  and glibc skips an entry longer than PATH_MAX), musl on any whitespace or
  colon, and the other loaders on colons or whitespace.  An entry containing a
  slash is taken as a file path, and the bare names are searched like a
  regular dependency (except on NetBSD, whose loader opens every entry as a
  file path).  On glibc the `/etc/ld.so.preload` file is also parsed, after
  the option.  The musl and Android loaders load the preloaded objects even for
  an object without any DT_NEEDED entry, which the other loaders report as
  statically linked.
* `--platform NAME` sets the `$PLATFORM` value used on the token expansion
  (and on glibc the platform of the legacy hwcaps subdirectories), instead of
  the one of the running system.  It has no effect on musl and Android, whose
  loaders do not expand `$PLATFORM`.

The `-v` option prints the search paths that apply to the input file (rpath,
preload, library path, runpath, cache, and default directories), along with the
locations searched for each dependency that was not found.

### Linux (glibc)

The glibc loader searches a dependency name on:
1. the DT_RPATH chain (see above), unless the object requesting it has
   DT_RUNPATH;
2. the `--library-path` directories;
3. the object DT_RUNPATH;
4. the loader cache;
5. and at last the default directories.

In each directory of these lists (but not for the cache), the loader first
tries the hwcaps subdirectories the machine supports, best first:

* Since glibc 2.33, the glibc-hwcaps ones: `x86-64-v4`, `x86-64-v3`, and
  `x86-64-v2` for x86-64 and x32, `power10` and `power9` for little-endian
  powerpc64, and `z16` to `z13` for s390x.
* Up to glibc 2.36, the legacy ones, after the glibc-hwcaps ones: every
  combination of `tls`, the platform, and the hwcap bits the loader uses
  (`x86_64` and `avx512_1` on x86-64, `sse2` on i386), such as
  `tls/haswell/x86_64`, `tls/haswell`, `tls/x86_64`, `tls`, `haswell/x86_64`,
  `haswell`, and `x86_64`.

The glibc release comes from the version banner of the loader of the input
object, which the loader has since glibc 2.33: a loader without one is taken as
an older one (with the legacy subdirectories only), and a loader that can not be
read as a current one.  The `-v` option lists the subdirectories on a
`subdirectories` line.

The loader cache is read directly from `/etc/ld.so.cache`, in the current, the
old, or the compat format (the old format followed by the current one), with
the entries selected for the ABI of each input object (its class, data
encoding, machine, and flags such as the float ABI), since each object runs
with the loader built for its ABI.  The entry flags are checked the way each
loader does, where the generic check (i386, 31-bit s390, 32-bit SPARC and
PowerPC, and MIPS o32, among others) also takes the `FLAG_ELF` entries the
ldconfig before glibc 2.37 writes for a library without libc dependency.  The
counts and offsets are checked against the file size like the loader does, and
a malformed cache degrades the way the loader does instead of making rldd
abort: a bad extension only leaves the glibc-hwcaps entries unusable, and an
entry with a string outside the file is skipped.

A glibc-hwcaps cache entry is only used when its subdirectory is active for
the loader on the running CPU, the best one winning over the regular entry,
and only the x86-64 (and x32), little-endian powerpc64, and s390x loaders have
them (an i386 object on a x86-64 host gets none).  The x86-64 levels are
checked the way glibc does, with AVX2 required for `x86-64-v3` and the AVX and
AVX-512 features only usable when the OS enables their state (XCR0), the
powerpc64 and s390x levels each require the lower ones, and on x86 an entry is
skipped when the CPU lacks the ISA level ldconfig recorded for it.  The legacy
hwcap bits ldconfig set up to glibc 2.36 are handled like the loader of the
object does: since glibc 2.40 any entry with them is skipped, and with an older
(or unknown) release an entry is only taken when the loader has its bits:
`tls`, and on x86-64 `x86_64` along with, on an Intel CPU with their features,
`avx512_1` and the `haswell` or `xeon_phi` platform, or on i386 `sse2` and the
`i686` or `i586` platform.  A machine whose capabilities can not be read (a
chroot without /proc) gets no glibc-hwcaps entry, and neither does a compat
format cache, as with the loader.

The default directories are the ones built into the loader of the object (its
PT_INTERP, or for a shared library the loader of its architecture the cache
lists), read from the loader file.  For instance, /lib/x86_64-linux-gnu,
/usr/lib/x86_64-linux-gnu, /lib and /usr/lib on a Debian x86_64 install,
or /lib64 and /usr/lib64 on an upstream build.  Without a loader to read, the
slibdir of the architecture and its /usr counterpart are assumed.

The `$LIB` token expands to the relative library directory the loader was
built with, read from the loader as well: `lib64` on an upstream x86_64 build,
`lp64d` for /lib64/lp64d on RISC-V, or `lib/x86_64-linux-gnu` on Debian.  The
`$PLATFORM` token expands to the platform the loader selects: `haswell` or
`xeon_phi` on an Intel CPU with their features for x86-64, and `i686` or `i586`
for i386 (the platform the kernel provides otherwise).  Both, along with the
hwcaps subdirectories, apply to every object the input object loads.

The dynamic loader is always listed, and the PT_INTERP path is used for
executables.  For shared libraries the loader soname is resolved through the
cache and the default directories.  On the `-l` output the loader is printed as
a regular `name => path` entry instead of the bare path line ldd uses.  A
DT_NEEDED entry naming the program interpreter resolves to the PT_INTERP path,
the way the loader matches the entry against its own soname without any
search, and a DT_NEEDED entry naming the vDSO is taken as already loaded.

Like ldd, the version check the loader makes whenever it loads a program is
reported even without the relocation checks (see below).

### Linux (musl)

A binary is handled as a musl one when the interpreter is one of the
ld-musl-$(ARCH)$(SUBARCH).so.1 names the musl configure script produces, when
it depends on a libc.musl- object, or, for shared libraries without a
PT_INTERP segment, when the system itself is a musl one.  Every object it
loads follows the musl rules as well, whatever its own PT_INTERP says.

The musl loader searches a dependency name on:
1. the `--library-path` directories;
2. the rpath chain of the objects that needed the library (see above);
3. and at last the directories of the path file.

A preloaded object is not needed by any object, so it gets no rpath.  There is
no loader cache: the path file is $(PREFIX)/etc/ld-musl-$(ARCH).path, where
the PREFIX is the loader path without its last two components (so
/etc/ld-musl-x86_64.path for /lib/ld-musl-x86_64.so.1), with the entries
separated by colons or newlines.  Only a missing file falls back to the
compiled-in /lib:/usr/local/lib:/usr/lib, while an empty file, or one that
can not be read, means no default directory at all.  For a shared library,
the loader is the musl one installed in /lib.

Since the musl loader and libc are the same shared object, the loader is always
listed, and a dependency named lib{c,pthread,rt,m,dl,util,xnet}.* resolves to it
without any search (the way the loader blocks reloading itself), reported once
per reserved prefix like the musl ldd does.  The libc is only part of the
symbol resolution scope when some object requests one of the reserved names.
On the `-l` output the loader is printed as a regular `name => path` entry
instead of the bare interpreter path the musl ldd uses.

### Android

The dependencies are resolved on the linker namespaces of the `ld.config.txt`
file associated with the input, which is selected the way the linker does for
the API level of the device:

* Up to Android 7 there is no configuration file, and Android 8 reads
  `/system/etc/ld.config.txt`.
* From Android 9, the first existing file of the APEX configuration (see
  below), the architecture specific `/system/etc/ld.config.<abi>.txt`, the
  generated `/linkerconfig/ld.config.txt` (from Android 11), and the VNDK ones
  (`/system/etc/ld.config.vndk_lite.txt` or
  `/system/etc/ld.config.<version>.txt`), with `/system/etc/ld.config.txt` as
  the last one.
* An executable on the bin directory of an APEX (directly there on Android 10,
  and anywhere below it from Android 11) looks for the configuration of its
  APEX first, the runtime one included: `/apex/<name>/etc/ld.config.txt` on
  Android 10, the generated `/linkerconfig/<name>/ld.config.txt` or else the
  one the APEX ships on Android 11 to 12L, and only the generated one from
  Android 13.  A shared library anywhere below `/apex/<name>` takes the
  configuration of that APEX the same way.

The file is parsed the way the bionic parser does: it is read as bytes, a `#`
starts a comment, the whitespace is trimmed (the vertical tab included), a line
with `+=` is an append split at the first one, another line with `=` an
assignment split at the first one, and an invalid line is ignored with the rest
of the section still applied.  The namespace and link lists are trimmed.  The
search and permitted paths replace the `$LIB`, `$SDK_VER`, `$VNDK_VER`, and
`$VNDK_APEX_VER` variables, with or without braces (`$ORIGIN` and `$PLATFORM`
are kept as written), and the search paths are resolved to their real path,
dropping the ones that are not a directory.  `${SDK_VER}` is the linker own
API level (10000), unless the section sets `enable.target.sdk.version` and a
`.version` file next to the binary gives the target SDK version, in which case
a file that can not be read or does not hold a positive number fails the whole
configuration, as on the device.

The section comes from the `dir.` mappings (without their trailing slashes,
and resolved to their real path from Android 10, where a directory that does
not exist is skipped), which the input matches when it is below the directory.
The mappings only cover the directories an executable is run from, which a
shared library usually is not in.  Since a library is loaded by an executable,
the section that maps the executable directory of the partition the library is
on is used instead: /system/lib64/libfoo.so is resolved with the /system/bin
section, and an object below `/apex/<name>` with the section of that APEX.
An executable that matches no directory does not fall back, the way the loader
uses the default system directories for it.

A dependency is looked up the way the linker does:
1. by DT_SONAME, on the objects loaded on the namespace of the requesting
   object, and on the namespaces it links to whose link shares the name;
2. on that namespace: the `--library-path` directories (only the default
   namespace has them), the requesting object DT_RUNPATH (only when the
   namespace can access the file found there), and the namespace search paths;
3. and at last on each namespace it links to whose link shares the name,
   where the object is then loaded.

The search on a namespace stops at the first file that opens: a file the
linker does not load (of another ELF class or machine, or not a shared object)
fails the load on that namespace and moves on to the linked ones, and a file
already loaded on the namespace is reused.  An isolated namespace only loads a
file, by its real path, whose name is on its `allowed_libs` (or `whitelisted`)
list when it has one (the default namespace never has one), and that is
directly in one of its search paths or `--library-path` directories, or
anywhere below one of its `permitted.paths`.  A binary whose target SDK version
is below 24 (set by a `.version` file) also loads the libraries the linker
exempts from that check.  A link only makes the libraries on its `shared_libs`
list accessible, unless `allow_all_shared_libs` is set.  Each object resolves
its own dependencies on the namespace it was loaded on, while the executable,
the preloaded objects, and the objects with DF_1_GLOBAL are on every
namespace.  A library the linker loads on two namespaces is listed on each,
like `linker64 --list` does.

When no configuration applies, the default system directories for the release
are used: /system/lib[64], /odm/lib[64] (from Android 9 on), and
/vendor/lib[64], each one preceded by the sanitizer specific directory for an
ASan (/data/asan/...) or HWASan (.../hwasan) instrumented object, which are
detected from the loader name (linker_asan[64] and linker_hwasan[64]).

DT_RPATH is not searched (the bionic loader does not implement it: it warns
about the unsupported dynamic entry and ignores it), only DT_RUNPATH is, from
Android 7.0.  The recorded DT_RPATH is still shown on the `-v` output, so an
object that relies on one can be told apart from one with no search path at
all.  The DT_RUNPATH entries expand `$ORIGIN`, the directory of the object
real path, and from Android 10 `$LIB`, and are then resolved to their real
path, dropping the ones that are not a directory.  No token is expanded on
DT_NEEDED, `--preload`, or `--library-path`, whose directories are only
resolved to their real path.

The objects are reported at their real path, the one the linker records and
`linker64 --list` shows: from Android 10, /system/lib64/libc.so is reported as
/apex/com.android.runtime/lib64/bionic/libc.so, the runtime APEX library it
links to, and a dependency whose real file has another name is printed as
`NAME -> FILE`.  The ld-android.so dependency of libc.so and libdl.so resolves
to the linker itself, which provides it (before Android 8 the linker provides
libdl.so instead), so it is only shown with `-a`, like an object already
loaded.

The `${LIB}` substitution and the library directory suffix follow the object ELF
class, so a 32-bit object is resolved against the `lib` directories even on a
64-bit device.  A DT_NEEDED entry naming the vDSO is not listed, since the
loader resolves it against the image the kernel maps.  For a 32-bit binary
whose target SDK version is below 23 (set by a `.version` file), a DT_NEEDED
entry naming a path is searched by its file name, the way the linker works
around old applications.

### FreeBSD

The FreeBSD loader searches a dependency name on:
1. the object DT_RPATH and then the main program one (see above);
2. the `--library-path` directories;
3. the object DT_RUNPATH;
4. the directories of the /var/run/ld-elf.so.hints file (the 32-bit compat
   objects use /var/run/ld-elf32.so.hints);
5. and at last the rtld standard directories.

A preloaded object has no requesting object, so only the `--library-path` and
the hints directories are searched for it.  The hints file is read in either
byte order, its directory list split on colons and semicolons.  The standard
directories are read from the rtld of the object (its PT_INTERP, or
/libexec/ld-elf.so.1 or /libexec/ld-elf32.so.1 for a shared library), since
they change with the release (FreeBSD 13 searches /lib/casper first, which
14.0 dropped); without an rtld to read, /lib and /usr/lib, or /lib32 and
/usr/lib32 for the compat objects, are used.

The /etc/libmap.conf mappings (/etc/libmap32.conf for the 32-bit compat
objects) are applied where rtld applies them: a dependency name is mapped for
the requesting object once no loaded object matches the name as requested (a
mapped name with a slash is opened as is), and each directory of every search
list is mapped as well.  The section matching the requesting object (by exact
path, directory prefix, or basename) that was defined last is used, with the
unconstrained mappings as fallback, and the mapping defined last for a name
wins.  A mapping taken from the section of an object also becomes an
unconstrained one, which applies to every object from then on.  A preloaded
object name is not mapped, and its directories only get the unconstrained
mappings.  Each included file and directory is parsed once, an `includedir`
only reads its regular files whose name ends with `.conf`, and the lines are
parsed like rtld does (only spaces and tabs are blanks, and a malformed
selector or a mapping with more than two words is ignored).

### OpenBSD

The OpenBSD loader searches a dependency name on:
1. the `--library-path` directories;
2. the object DT_RUNPATH, or without one its DT_RPATH and the main program one
   (see above);
3. and at last the /var/run/ld.so.hints file: its hash table, and then its
   directory list, or /usr/lib only without a valid hints file.

Like the OpenBSD loader, a dependency is matched by library name and major
version, picking the best version available in the directory: an unversioned
library at once, and otherwise the highest major and then the highest minor
(also for the input file itself when it is a shared library).  The whole search
is made twice: first with the hints for a minor version at least the requested
one, the hints being looked up before each list is scanned, and then without
the hints for any minor version, with the loader warning printed on the
standard error.  A name with a slash is matched the same way in its directory,
and the file found is loaded, or the load fails, without going on with the
search.  Before any search, a name is matched against the loaded objects of
the same library name and major version (and against their DT_SONAME).  The
loader is listed for executables and the `-l` output keeps the `name => path`
format.

The hints file header is read with the C long size of the system, so the one
of a 32-bit system (i386, armv7, or macppc) is read as well.

Since the loader can not load two libc versions in a process, the first
libc.so.* dependency found is used for every further libc load, whatever major
the other objects were linked against.

### NetBSD

The NetBSD loader searches a dependency name on:
1. the `--library-path` directories;
2. the /etc/ld.so.conf directories;
3. the requesting object DT_RPATH or DT_RUNPATH (see above);
4. and at last /usr/lib, followed by the compat subdirectory for an object of
   another architecture (for instance /usr/lib/i386 for a 32-bit object on
   amd64).

Only the `ld.so.conf` lines starting with a `/` are directories: the other ones
are the per-library hardware directives, which are skipped (they are not
supported).  The loader does not check the ELF OS ABI, so an object tagged with
another one (for instance ELFOSABI_GNU) also matches.

### illumos

The illumos loader (and the Solaris one) searches a dependency name on:
1. the `--library-path` directories;
2. the requesting object DT_RUNPATH or DT_RPATH (see above);
3. and at last the default directories, /lib and /usr/lib for a 32-bit
   object, or /lib/64 and /usr/lib/64 for a 64-bit one, whatever the
   architecture.

There is no support for the crle(1) configuration files, the capability
directories of the `$CAPABILITY` and `$HWCAP` tokens, or the secure process
rules (the trusted directories).

## macOS

On macOS, the dependencies are tracked the way `dyld_info -dependents` and
`otool -L` do, where the load paths from the dylib load commands are taken
verbatim (with @executable_path, @loader_path, and @rpath expanded) and
resolved against the dyld shared cache (if existent) and the filesystem the
way dyld does.  The dependencies are printed with their full path, along with
the load command attributes as reported by dyld_info (weak-link, re-export,
upward, and delay-init).

Like dyld_info, the input file may be the install name of an image that exists
only in the dyld shared cache.

The input slice of a universal binary is the one the host launches: arm64e,
arm64, and then x86_64 on Apple Silicon, and x86_64h before x86_64 on a Haswell
or newer Intel host, with any other slice as the last resort, so a foreign
binary can still be inspected.  The `--arch NAME` option (arm64, arm64e,
x86_64, x86_64h, i386, ppc, or ppc64) selects the specified slice instead.
Like dyld, the input slice sets the architecture of the process: the
dependencies are loaded from the slices that process takes (an arm64e main
executable only takes arm64e images, another arm64 process the arm64e and the
arm64 ones, and an x86_64 process the x86_64h ones on a Haswell host before the
x86_64 ones), and the dyld shared cache is the matching flavor (for instance,
an x86_64 input on Apple Silicon resolves to the Rosetta cache when
installed).  A dylib or bundle input takes the images any process of its cpu
type loads.

A candidate file is rejected, and the search goes on, when it has no slice the
process takes, when it is not a dylib (a bundle or an executable), or, for a
main executable built for macOS alone, when it is built for another platform
(a zippered macOS and Mac Catalyst image is loadable, and an image without any
platform load command is a macOS one).  A malformed image (a load command table
past the end of the file, a load command too small or past the table, a string
outside its load command, or a universal file nested in a slice) is rejected
the same way, and reported as an error when it is the input.

A load path is searched the way dyld does, on:
1. the `--framework-path` directories for a framework load path, or the
   `--library-path` directories for any other one;
2. the load path itself, with @rpath expanded with each entry of the run-path
   list;
3. and at last the `--fallback-framework-path` or `--fallback-library-path`
   directories, or the default ones.

Each absolute candidate path is checked against the dyld shared cache and the
filesystem, and then retried below the OS cryptex mount where dyld also looks
for the images that are not on the root filesystem.  A recorded load path that
does not start with @ and is found nowhere is at last resolved through realpath
and looked up in the cache again, so a symlinked directory still reaches an
image that exists only in the cache.  A load path that neither starts with a /
nor with @ is opened from the current directory, and is not turned into an
@rpath one (dyld only does that for dlopen).

The @executable_path, @loader_path, and @rpath prefixes are only expanded as
the leading component.  @executable_path is the main executable directory (a
real path, so the leading ../ components of the load path are resolved against
it), and @loader_path the directory of the image with the load command.  The
run-path list of an image is its own LC_RPATH entries followed by the ones of
the images that loaded it.  An LC_RPATH entry is kept whether its directory
exists or not, since the dyld cache holds images whose directory is absent from
the disk, and an entry ending with a slash is joined without a second one.

A load path or candidate names an image already loaded when it is the path the
image was loaded from, its install name, the dyld cache image an alias path
leads to, or the real path of its file, while a dependency not found is
searched again for each image that requests it.  The dependencies are loaded
in the dyld order: all the dependencies of an image are looked up before the
dependencies of the images they lead to, and the dependencies of an image are
loaded once, with the run-path list of the first image that reaches it.  The
tree prints each image below the image that loaded it, and the `-l` option
lists the images in the dyld load order (the one DYLD_PRINT_LIBRARIES
reports).

Since the recursive listing of a system binary expands to most of the dyld
shared cache, only the direct dependencies are printed by default, and the tree
can be pruned with:

* `--depth N` limits the dependency tree to N levels, with 0 meaning no limit
  (the default is 1, the direct dependencies).
* `--ignore-prefix PREFIX` skips dependencies whose load path starts with the
  prefix (for instance `--ignore-prefix /usr/lib` to hide the system
  libraries); the option may be used multiple times.

The following dyld environment variables are mimicked with options, following
the dyld search order:

* `--preload LIST` (DYLD_INSERT_LIBRARIES) inserts the libraries of the colon
  separated list (a path with spaces is a single entry), which are loaded
  before the main executable dependencies, while their own dependencies are
  loaded after the whole main executable tree.  An @rpath entry is taken as is
  (only an image with that install name, or a library or fallback directory
  holding its leaf name, provides it), an @loader_path one is only searched on
  those directories, and the default fallback directories are not searched.
* `--library-path LIST` (DYLD_LIBRARY_PATH) searches the colon-separated
  directories for the dependency leaf name before the recorded load path, for
  the load paths that are not a framework one.
* `--framework-path LIST` (DYLD_FRAMEWORK_PATH) searches the directories for the
  framework partial path (Foo.framework/Versions/A/Foo) before the recorded
  load path.
* `--fallback-library-path LIST` and `--fallback-framework-path LIST`
  (DYLD_FALLBACK_LIBRARY_PATH and DYLD_FALLBACK_FRAMEWORK_PATH) are searched
  after the dependency is not found on the recorded load path.  When the list
  is unset, the dependencies of an image built with an SDK older than the 2022
  releases (macOS 14, iOS 17, and the like) are searched on the default ones,
  /usr/local/lib and /usr/lib, or /Library/Frameworks and
  /System/Library/Frameworks, which are printed as `[system default paths]`.
* `--image-suffix LIST` (DYLD_IMAGE_SUFFIX) tries each candidate path with each
  suffix of the colon separated list first, inserted before the last dot of the
  leaf name (libz.so becomes libz_debug.so) or appended to a leaf name without
  one.  A framework leaf name made of the framework name and the suffix is
  still taken as a framework.

The DYLD_* variables a main executable records on its LC_DYLD_ENVIRONMENT load
commands are added after the options: their directories are searched after
the option ones, and the inserted libraries and the image suffixes extend the
option lists.  An entry starting with @executable_path/ or @loader_path/ is
taken below the main executable directory.  The DYLD_VERSIONED_* variables are
not supported.

A setuid or setgid main executable, or one with a `__RESTRICT,__restrict`
section, runs as a restricted process: dyld ignores its DYLD_* variables, so
the `--library-path`, `--framework-path`, fallback, `--preload`, and
`--image-suffix` options are ignored (the LC_DYLD_ENVIRONMENT ones are still
taken, without their @ entries), @executable_path and the @loader_path of the
main executable LC_RPATH entries are not expanded, a relative LC_RPATH entry or
load path is refused, and the default fallback directories are only /usr/lib
and /System/Library/Frameworks.  The further restrictions AMFI applies (the
hardened runtime without the entitlement allowing the DYLD_* variables, or the
code signing flags) are not modelled.

A Mac Catalyst program, or an iOS one running on a Mac, looks for an absolute
load path below /System/iOSSupport first, where the iOS variants of the system
libraries are, unless it is already there, and an iOS one also before each
absolute LC_RPATH entry.  The option directories and the @rpath expansions of a
Mac Catalyst program are not prefixed.

The `-v` option also prints the object information from the load commands: the
architecture, the install name (like otool -D), the platform (dyld_info
-platform), the UUID (dyld_info -uuid), why the process is restricted, the
LC_DYLD_ENVIRONMENT variables, the run-path list, the search path options,
the dyld shared cache status, and the dependencies compatibility and current
versions (otool -L).

## Windows

On Windows, the dependencies are tracked via `dumpbin /dependents`, where the
DLL names recorded in the import and delay-load import directories are resolved
according to the documented search order for unpackaged applications.  The
delay-load dependencies are printed with the `delay-load` attribute, and the
ones whose imports were bound at link time with the `bound` attribute.  The
delay-load descriptors the Visual C++ 6 linker wrote, which hold virtual
addresses instead of RVAs, are read as well.  An import descriptor without an
import name table has its names read from the address table, like the loader
does for the objects of the old Borland linkers, unless the object was bound,
where that table holds addresses and the imports are left unread.

The `api-ms-` and `ext-ms-` virtual names are resolved with the API set schema
from `apisetschema.dll` and printed as `NAME -> HOST`, with the module that
implements them.  A set that implements nothing on the running system is
reported as not found.

The search order is the application directory, the `--library-path`
directories, the system directory, the 16-bit system directory, the Windows
directory, the current directory, and at last the PATH directories.  An import
name with a path component is taken as it is when it is absolute, and
otherwise searched below each directory of the order (`p\my.dll` is looked for
as `app\p\my.dll`, even when it starts with `.\`), and it is printed as the
alias of the module it resolves to.

Only a missing file, or an image built for another machine, lets the search go
on.  Any other candidate the loader cannot map (a file that is not an image, a
truncated or an empty one, or a directory by that name) stops it, even with a
valid copy further on the order, and the dependency is printed as not found
with the `bad image` attribute (the `-v` option shows the reason on the
searched location).

The known DLLs are the sections smss creates at boot on the \KnownDlls object
directory (\KnownDlls32 for the 32-bit images): the modules of the KnownDLLs
registry key along with every module their static imports pull in, with the
API sets resolved.  They are always resolved from the known DLLs directory
(the system directory, or the expanded DllDirectory and DllDirectory32
registry values), regardless of the search order, and printed as
`[KnownDLLs]`.  A module a known DLL only pulls in through a delay load import
or a forwarder is not a known DLL itself (unless it is on the registry list, or
another known DLL statically imports it), so it follows the normal search order
and an application copy of it is taken first, as with the loader.

A 32-bit image sees the WOW64 view of the file system: every directory the
search order reaches goes through the redirection, so System32 and everything
below it stand for SysWOW64 (SysArm32 for a 32-bit ARM image), except the
catroot, catroot2, driverstore, drivers\etc, logfiles, and spool directories,
while Sysnative names the real System32.  On Windows on ARM, the SyChpe32
directory, with the hybrid build of the core x86 modules, comes before
SysWOW64 wherever the order reaches it.

A candidate built for another machine is skipped so the search continues, as
the loader does.  On ARM64, a native process loads the ARM64 and ARM64X
modules, and an emulated one (an x86_64 or ARM64EC image) the x86_64, ARM64EC,
and ARM64X ones, so the ARM64 and ARM64EC modules do not load each other.  An
AMD64 header with CHPE metadata is an ARM64EC object, unless it holds ARM64X
relocations, which make it an ARM64X one (an ARM64 header with the metadata is
always ARM64X).

A .NET image gets a `mscoree.dll` dependency with the `clr` attribute when its
imports do not record one, since the loader maps it for any .NET image (an IL
only one built for x86_64 or ARM64 imports nothing).  An IL only image built
for any CPU (a PE32 image recording i386 whose CLR header does not ask for a
32-bit process) runs as a native process, so as the input its dependencies are
resolved for the machine of the system (x86_64, or ARM64 on Windows on ARM).

An imported symbol that resolves to a forwarded export pulls in the module it
points to, which no import directory records, unless the forwarding module
statically imports it (a delay load import does not load it at startup, while
the forwarder does).  Those dependencies are printed with the `forwarded`
attribute, and a chain of forwarders is followed to its end.  The exports are
read entry by entry, so a malformed entry only drops itself.

The dependent assemblies declared on the manifest the loader activates are
resolved against the WinSxS store, which the loader searches before the loaded
module list, so the same name may be loaded from more than one assembly (the
version 5 and the version 6 common controls are the usual case).  An
executable given as input starts the process with its RT_MANIFEST resource 1,
or else the external `<name>.exe.manifest` file, or else its resource 2, and
only one of them is activated (the PreferExternalManifest registry value puts
the external file first).  Any other module only has its resource 2 activated,
never an external file, and the resource 3 is never read.  The manifests are
parsed as XML: the comments and the CDATA sections are skipped, the namespace
prefixes dropped, the entities expanded, and UTF-8 and UTF-16 are read with or
without a byte order mark.  The WinSxS directory names the store shortens (a
name over 40 characters kept as its first and last 19 around a `..`, and a
language over 8 as its first and last 3) are matched.  If the publisher policy
is not read, the highest installed build for the requested major and minor
version is used.  The side-by-side redirection does not apply to an import
name with a path.

When a `.local` directory exists, the dependencies are taken from it, and when
it is a plain file, they are taken from the application directory.  The
redirection is ignored when the process starts with a manifest (the resource 1
or the external file), unless the DevOverrideEnable value of the Image File
Execution Options key is set, and it applies to the base name of an import
name with a path as well.

The system default activation context (the loader maps comctl32 and gdiplus
from WinSxS even for an executable without a manifest), the API set schema
extensions, the application compatibility shims, and the ExcludeFromKnownDlls
registry value are not supported.

Since the recursive listing of a system binary expands to most of the system
directory, only the direct dependencies are printed by default, and the tree
can be pruned with:

* `--depth N` limits the dependency tree to N levels, with 0 meaning no limit
  (the default is 1, the direct dependencies).
* `--ignore-prefix PREFIX` skips dependencies whose resolved path starts with
  the prefix (for instance `--ignore-prefix C:\Windows` to hide the system
  libraries).  The option may be used multiple times, and the comparison ignores
  case and takes either separator.

The remaining loader inputs are mimicked with options:

* `--library-path LIST` searches the semicolon-separated directories right after
  the application one, as SetDllDirectory does, which also removes the current
  directory from the search order.  AddDllDirectory is not mimicked: it only
  applies with LOAD_LIBRARY_SEARCH_USER_DIRS, which also drops the PATH, the
  current, and the Windows directories.
* `--no-safe-search` searches the current directory immediately after the
  application directory, because the SafeDllSearchMode registry value is set to
  0 (it has no effect along with `--library-path`).

The `-v` option also prints the object information: the machine (marked as IL
only, any CPU, for such a .NET image), the subsystem, the image base, the image
type, the API set schema status, the number of known DLL sections for the
architecture of the image, the number of WinSxS assemblies, the safe search
mode, the dependent assemblies with the directory they resolved to, and the
search path list used for the resolution.

## Import checks (Windows only)

The PE equivalent of the ELF relocation processing is to check that every
imported symbol is exported by the module it is imported from:

* `-d` checks the imports bound at load time and reports the ones no dependency
  exports.
* `-r` also checks the delayed-load imports, which the loader only binds on the
  first call.

An imported symbol is bound through the forwarders the way the loader binds
it, so a missing one is reported as the symbol and the module the chain ends
on (`undefined symbol: NAME, from MODULE`, followed by the importing object).

There is no `-u` option: an import directory only records a module when a
symbol is imported from it, so a PE object has no unused dependency to report.

## Relocation checks (Linux only)

As with ldd, dynamic relocations can be processed to report unresolved symbol
references, missing symbol versions, or unused dependencies.  The checks mimic
the glibc loader and are only supported on Linux:

* `-d` processes the data relocations and reports the undefined symbols that no
  loaded object defines.
* `-r` processes both the data and the function (PLT) relocations.
* `-u` prints the direct dependencies (the preloaded objects included) that
  provide no symbol used by the binary's own relocations (like ldd, it
  suppresses the dependency listing and exits with status 1 when unused
  dependencies are found).

The symbol lookup follows the glibc rules: any definition of an object without
symbol versions satisfies a reference, a versioned reference binds to the
definition of that version, or to an unversioned one unless either is hidden,
and an unversioned reference binds to an unversioned definition or one of the
first version the object defines, or else to the single definition of a later
version that is not hidden.  A symbol without a value (other than a TLS or an
absolute one), or of another type than a code or data one, is not a
definition.

The glibc loader checks the versions the objects need whenever it loads them,
so the version check failures (``version `V' not found``, ``weak version `V'
not found``, and `no version information available`) are printed on every
listing of a glibc program, like ldd does: before the dependency tree, or after
the file header line of the `-l` output, naming the input object as given on
the command line.  They do not change the exit status.

For a musl binary the relocations are always processed (musl has no lazy
binding, and no version check), and the unresolved references are reported on
the standard error after the listing as `Error relocating OBJECT: SYMBOL:
symbol not found` and the exit status is 127.

## Testing

`cargo test` runs the unit tests for the backend of the host system.  On a
Linux host it also runs the tests of the configuration parsers and the loader
rules of the other ELF systems that do not depend on the running system (the
Android `ld.config.txt` parser and namespace lookups, the FreeBSD hints and
`libmap.conf`, the OpenBSD hints and version matching, the NetBSD
`ld.so.conf`, and the FreeBSD, OpenBSD, NetBSD, and illumos token and search
list rules).

The continuous integration runs on every push and pull request.  A job for
each host system (Linux, Windows, and macOS) runs clippy with warnings as
errors, the build, and the tests, the Linux one also checking the formatting.
The Android, FreeBSD, NetBSD, illumos, and musl targets, which have no runner,
are checked with clippy, and a job checks the OpenBSD target (a tier 3 one,
which needs the nightly toolchain) without failing the workflow when nightly
breaks.

The suites below compare rldd with the reference tool of each system on a real
installation.  Each one always builds rldd before the run (a no-op when it is
up to date), so a stale binary is never tested.  The Android, macOS, Linux, and
BSD ones report a crash (a panic, or rldd killed by a signal) as a failure, and
the Windows one a panic, or an error on an object dumpbin reads.

Its configuration parser aside, the Android backend is only compiled when cross
building and needs a real system image to be exercised.  The device test suite
is under [tests/android](tests/android), which builds rldd for the ABI of
each attached device, pushes it, and resolves every object of the system image
with it.  With `-c` (`--compare`) it also compares every executable with what
the device linker lists (`linker64 --list`, from Android 11), which catches a
library resolved from the wrong namespace or search path.  Run with:

```
tests/android/run.sh
tests/android/run.sh -c
```

Or on Windows

```
tests\android\run.ps1
```

On Windows it needs the Git Bash shell or similar (the `bash` on the Windows
`PATH` is the WSL one, which does not reach the emulators).

The PE backend reads the dependency names out of the import and the delay load
import directories, which the unit tests cannot check against a real
installation, so it has a suite of its own under
[tests/windows](tests/windows).  It runs rldd over the binaries of a system
directory and compares the dependency names with `dumpbin /dependents`.  With
`-Paths` it also starts every executable of the sweep under the debugger, up to
the initial loader breakpoint, and compares the modules the loader maps with
the paths rldd resolves the static dependencies to, each run bounded by
`-Timeout`.  What rldd does not model (the modules the loader maps on its own,
the compatibility shims, and the system default activation context) is counted
apart, and `-Verbose` lists every failure:

```
tests\windows\run.ps1
tests\windows\run.ps1 -Paths
```

The Mach-O backend takes the recorded load paths to the dyld shared cache, the
filesystem or the OS cryptex of the running system, and it has a suite of its
own under [tests/macos](tests/macos).  It runs rldd over the objects of the
system directories and the dyld cache images and compares the dependency lists,
and where each one resolved to, with `dyld_info -dependents`:

```
tests/macos/run.py
```

The Linux ELF tests run rldd over the objects of the system directories and
compare the dependency lists, and where each one resolved to, along with the
version check diagnostics, with `ldd`.  The machine under test is the local one
or any host reached through ssh, for which rldd is cross built and copied over:

```
tests/linux/run.sh
tests/linux/run.sh -H debian-aarch64 -H debian-ppc64le
```

Since the system objects only exercise the common search rules,
`tests/linux/cases.sh` builds small libraries and programs with gcc for the
other ones (the DT_RPATH chain, the tokens, the empty search list entries,
DF_1_NODEFLIB, the preload and library path lists, the hwcaps subdirectories,
the version diagnostics, the candidate files the loader skips or fails on, and
the musl rules), and compares the rldd result with the ldd one, or with the
expected one where ldd can not tell:

```
tests/linux/cases.sh
```

The FreeBSD, OpenBSD and NetBSD loaders each search differently (the hints file
and `libmap.conf`, the minor version matching, the `ld.so.conf` and the compat
directories), so the BSDs have a suite of their own under
[tests/bsd](tests/bsd).  It runs rldd over the objects of the system
directories and compares the dependency lists with the `ldd` of each system.
The machine under test is the local one or a host reached through ssh, where
the working tree is copied and rldd built:

```
tests/bsd/run.sh -H freebsd -H openbsd -H netbsd
```
