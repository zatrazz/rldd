# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- ELF: the `-v` search path information lists as `unexpanded` the search list
  entries a loader drops because of a dynamic string token without a value.
- ELF (glibc): the old and the compat `ld.so.cache` formats are read (they
  were ignored, and `-v` showed no cache where the loader used one).
- ELF (glibc): the glibc-hwcaps subdirectories the CPU supports are searched
  before each DT_RPATH, `--library-path`, DT_RUNPATH, and default directory
  for a glibc 2.33 or later loader, and the legacy hwcaps subdirectories
  (`tls`, the platform, and the hwcap bits) for a loader older than 2.37, the
  release coming from the version banner of the loader.  The `-v` option
  lists them on a `subdirectories` line.
- ELF (glibc): the loader version check failures (``version `V' not found``,
  and the weak version and `no version information available` warnings) are
  printed on a plain listing too, like ldd does, without changing the exit
  status.
- ELF (glibc): the `--library-path` entries, and the `--preload` and
  `/etc/ld.so.preload` ones naming a path, expand the `$ORIGIN`, `$LIB`, and
  `$PLATFORM` tokens, like the loader does for the main object.
- ELF (Android): the namespace `permitted.paths` are parsed, and an isolated
  namespace only loads the files it can access (the names on its
  `allowed_libs`, directly in its search paths or below its permitted paths),
  a DT_RUNPATH hit and a DT_NEEDED path included.
- ELF (Android): a 32-bit binary whose target SDK version is below 23 searches
  a DT_NEEDED path by its file name, the linker workaround for old
  applications.
- ELF (FreeBSD): `/etc/libmap32.conf` is read for the 32-bit compat objects.
- ELF (FreeBSD): a hints file of the other byte order is read, like rtld does.
- ELF (FreeBSD): the `$OSNAME`, `$OSREL`, and `$LIB` tokens.
- ELF (OpenBSD): the hints file hash table is looked up, and a library of a
  lower minor version is taken on a second pass, with the loader warning.
- ELF (OpenBSD): the `$OSNAME` and `$OSREL` tokens.
- ELF (NetBSD): the `$OSNAME`, `$OSREL`, `$HWCAP`, and `$ISALIST` tokens, and
  the token expansion of the `--library-path` and `ld.so.conf` entries.
- ELF (illumos): the `$MACHINE`, `$OSNAME`, `$OSREL`, and `$ISALIST` tokens,
  also expanded on the `--library-path`, dependency, and preload entries.
- Mach-O: the dyld restricted process rules for a setuid or setgid program, or
  one with a `__RESTRICT,__restrict` section: the DYLD_* options, the
  @executable_path expansion, and the relative LC_RPATH entries and load paths
  are ignored.  The `-v` option tells why a process is restricted.
- Mach-O: the DYLD_* variables of the main executable LC_DYLD_ENVIRONMENT load
  commands are taken after the options, and listed by `-v`.
- Mach-O: the default fallback directories (/usr/local/lib and /usr/lib, or
  /Library/Frameworks and /System/Library/Frameworks) are searched for the
  dependencies of an image built with an SDK older than the 2022 releases.
- Mach-O: a load path that is neither absolute nor starting with @ is opened
  from the current directory, like dyld does.
- Mach-O: a Mac Catalyst program, or an iOS one on a Mac, looks for an
  absolute load path below /System/iOSSupport first.
- Mach-O: the x86_64h slice and dyld shared cache are preferred on a Haswell
  or newer Intel host, like dyld does.
<!-- PE -->
- The options that take a value accept the `--option=value` form.
- `-h` prints the usage, like `--help`.
- The package declares its minimum supported Rust version (1.88), so an older
  compiler fails with a clear message.
- `tests/linux/cases.sh`, which builds small objects with gcc for the loader
  rules the system objects do not exercise, and compares the rldd result with
  the ldd one, or with the expected one where ldd can not tell.
- The `-c` (`--compare`) option of the Android device test suite, which
  compares every executable with what the device linker lists
  (`linker64 --list`, from Android 11), `--library-path` and `--preload`
  included.
- The configuration parsers of the Android and the BSD backends, and the
  loader rules of the FreeBSD, OpenBSD, NetBSD, and illumos ones, are also
  built for the Linux tests, so `cargo test` and the CI run their unit tests.
- The CI workflow runs on a push to any branch and on pull requests, with a
  Linux, a Windows, and a macOS job running clippy with warnings as errors, the
  build, and the tests, a clippy check of the Android, FreeBSD, NetBSD,
  illumos, and musl targets, and a non-blocking OpenBSD check with the nightly
  toolchain.

### Changed

- ELF: a candidate file for a dependency is checked the way each loader opens
  it, which either goes on with the search or fails the load; a failed load is
  reported as not found, with the file and the loader error in verbose mode.
  The preload entries naming a path go through the same checks.
- ELF (glibc): a candidate of another ELF class or machine (the RISC-V float
  ABI, the MIPS ABIs and NaN encoding, and the PowerPC64 ELF ABI version
  included) is skipped, while another data encoding, OS ABI, or ABI version, a
  file that is not an ELF object, an executable, or an object without dynamic
  section fails the load.
- ELF (glibc): `--preload` is split on spaces and colons only, skipping an
  entry longer than PATH_MAX, `--library-path` on semicolons too, and
  `/etc/ld.so.preload` is parsed the way the loader does (a carriage return is
  part of a name).
- ELF (musl): the search order follows the loader: `--library-path`, then the
  rpath chain, then the path file directories, with no rpath for a preloaded
  object.
- ELF (musl): the loader takes the first file it opens, so any mismatch fails
  the load instead of going on with the search.
- ELF (musl): `--preload` is split on any whitespace or colon.
- ELF (Android): the dependencies are resolved on the linker namespaces: by
  DT_SONAME on the objects of the requesting namespace and of the linked ones
  sharing the name, then on the namespace (`--library-path`, for the default
  one only, DT_RUNPATH, and the search paths), and at last on each linked
  namespace sharing the name.  The executable, the preloaded objects, and the
  objects with DF_1_GLOBAL are on every namespace, and a library may be loaded
  on two namespaces like on the device.
- ELF (Android): the search on a namespace stops at the first file that opens,
  and a file the linker does not load fails the load on that namespace.
- ELF (Android): the objects are reported at their real path, like
  `linker64 --list` does (from Android 10, libc.so is the runtime APEX one).
- ELF (Android): ld-android.so (libdl.so before Android 8) resolves to the
  linker itself, which provides it, and is only shown with `-a`.
- ELF (Android): DT_RUNPATH expands `$ORIGIN` from the object real path and
  `$LIB` from Android 10 (none before Android 7), and its directories, the
  `--library-path` ones, and the `ld.config.txt` search paths are resolved to
  their real path.  No token is expanded on DT_NEEDED or `--preload`, which is
  split on spaces and colons.
- ELF (FreeBSD): the lists, `--library-path` included, are split on colons and
  semicolons, and the tokens are only expanded on DT_RPATH, DT_RUNPATH, and
  the DT_NEEDED names with a slash.
- ELF (FreeBSD): the first file the search finds is loaded, and one of another
  class, data encoding, or machine fails the load.
- ELF (FreeBSD): the standard directories are read from the rtld (FreeBSD 14
  dropped /lib/casper).
- ELF (OpenBSD): a dependency is searched the way `_dl_load_shlib` does, with
  the best version in a directory (the highest major and minor, or an
  unversioned library at once), and a name with a slash matched in its
  directory; the file found is loaded, or the load fails.
- ELF (OpenBSD): the lists, `--library-path` included, are split on colons and
  semicolons, and only the DT_RPATH and DT_RUNPATH tokens are expanded.
- ELF (OpenBSD): a file that is not an ELF shared object of the loader machine
  fails the load, whatever its OS ABI.
- Mach-O: the input slice is the one the host launches (arm64e, arm64, then
  x86_64 on Apple Silicon), and its architecture sets the process one: a
  dependency without a slice the process loads is rejected and the search
  goes on, and the dyld shared cache is the flavor of that architecture.
- Mach-O: the dependencies are loaded in the dyld order (all the dependencies
  of an image before theirs), which decides which candidate a later load path
  matches, and the `-l` output lists them in that order.
- Mach-O: `--image-suffix` takes a colon separated list, each suffix inserted
  before the last dot of the leaf name.
- Mach-O: an @rpath `--preload` entry is taken as is and an @loader_path one is
  not expanded, like dyld; the dependencies of an inserted library are loaded
  after the main executable tree.
<!-- PE -->
- Only `-h` and `--help` print the usage, so a file named `help` is inspected.
- A file of another object format is reported as such (`not an ELF object
  (this build inspects ELF objects only)`), a directory as `is a directory` on
  every system, a file that can not be opened with the reason (such as
  `permission denied`), and the file errors start in lower case.
- A build for an unsupported target fails with a compile error listing the
  supported target_os values.
- The dependency resolution indexes the objects already loaded, so a long
  chain of libraries no longer takes quadratic time.
- The tree colors are written as plain escape sequences (the console is
  switched to the virtual terminal mode on Windows), with the same `TERM` and
  `NO_COLOR` rules.
- The package no longer ships the GitHub workflow and the git configuration
  files, and the libc crate is only a dependency of the Android build.
- The Linux, BSD, macOS, and Android test suites always build rldd first, and
  report a crash (rldd killed by a signal) as a failure.

### Fixed

- ELF: the last DT_RPATH, DT_RUNPATH, DT_SONAME, and DT_FLAGS_1 entry is used
  when a tag is repeated, like the loaders record them (the first one was).
- ELF: DF_1_NODEFLIB only restricts the search: the objects already loaded are
  matched first, so a library linked with `-z nodefaultlib` reuses the libc
  the program loaded (it reported it not found).
- ELF: a library one object fails to find no longer hides the copy another
  object loads afterwards, which a later object naming it reuses.
- ELF (glibc): the tokens follow the loader rules: `$ORIGINAL` is a literal
  directory name, and an entry with a token without a value (`$PLATFORM` on
  RISC-V) is dropped instead of expanded to an empty string.
- ELF (glibc): `$LIB` expands to the relative directory the loader was built
  with (`lib64`, or `lib/x86_64-linux-gnu` on Debian) instead of the absolute
  one, and `$PLATFORM` to the platform the x86 loader selects (`haswell`,
  `xeon_phi`, `i686`, or `i586`).
- ELF (glibc): an empty DT_RPATH, DT_RUNPATH, or `--library-path` entry is the
  current directory, like the loader takes it (it was dropped).
- ELF (glibc): the `$ORIGIN` of a shared library input is the directory of the
  path given, not of its symlink target, like dlopen and ldd.
- ELF (glibc): DF_1_NODEFLIB only skips the default directories and the cache
  entries below them, so an entry of another `ld.so.conf` directory is still
  used.
- ELF (glibc): the `ld.so.cache` entries are selected for each input object
  ABI, instead of the one of the first input, and an input for another loader
  (musl) no longer uses the glibc cache.
- ELF (glibc): a glibc-hwcaps cache entry is only used when the loader of the
  object ABI searches its subdirectory on the running CPU (the lower levels
  required on powerpc64le and s390x), and on x86 when the CPU has the ISA
  level ldconfig recorded for it; the regular entry is used otherwise (an
  unsupported entry sorting first was taken).
- ELF (glibc): the x86-64 levels require AVX2 for `x86-64-v3`, and the AVX and
  AVX-512 features the OS enables (XCR0), like glibc.
- ELF (glibc): the cache entries with legacy hwcap bits (ldconfig up to glibc
  2.36) follow the loader release: they are skipped since glibc 2.40, and taken
  before only with the bits the loader has.
- ELF (glibc): the `FLAG_ELF` entries the ldconfig before glibc 2.37 writes are
  taken by the loaders with the generic flags check (i386 and other 32-bit
  ABIs).
- ELF (glibc): a malformed `ld.so.cache` no longer aborts on a huge
  allocation, panics, or is dropped whole: the counts and offsets are checked
  against the file size, and a bad extension or string only drops what the
  loader drops.
- ELF (glibc): the version check follows the loader: a dependency without
  version definitions only gets the `no version information available`
  warning, and a missing weak version is reported as a warning.  The symbol
  lookup of `-d` and `-r` follows the glibc version binding rules.
- ELF (glibc): the relocation checks read a PT_DYNAMIC whose size is not a
  multiple of the entry size like the resolution does (they lost DT_JMPREL,
  the bind now flags, and the MIPS GOT tags).
- ELF (musl): the path file is $(PREFIX)/etc/ld-musl-$(ARCH).path, the PREFIX
  coming from the loader path, and only a missing file falls back to the
  default directories (an empty one means none).
- ELF (musl): the dependencies of a musl input follow the musl rules, whatever
  their own PT_INTERP says.
- ELF (musl): only `$ORIGIN` is expanded, on DT_RPATH and DT_RUNPATH, and a
  list with any other token is ignored, like the loader does.
- ELF (musl): DF_1_NODEFLIB is ignored, like the loader does.
- ELF (musl): every loader name the musl configure script produces is
  recognized (the MIPS soft-float variants, the powerpc and riscv64 `-sf`
  ones, riscv32, and loongarch64 were not).
- ELF (musl): a crafted MIPS object with a huge DT_MIPS_SYMTABNO no longer
  hangs the relocation check that runs on every musl input.
- ELF (Android): the configuration file is selected per release: the APEX one
  only for an executable on the bin directory of its APEX (the runtime one
  included), the shipped one on Android 10 to 12L, and the generated one from
  Android 11.
- ELF (Android): the `dir.` entries are matched the way each release does
  (resolved from Android 10, and as a string prefix).
- ELF (Android): the `ld.config.txt` lines are parsed like bionic does: as
  bytes (a Latin-1 comment no longer drops the whole configuration), with a
  value keeping any `=`, an invalid line ignored instead of ending the section,
  and the namespace lists trimmed.
- ELF (Android): the `.version` file is trimmed, and one that can not be read
  or holds no positive number fails the configuration like on the device.
- ELF (Android): `${SDK_VER}` defaults to the linker API level (10000) instead
  of the device release, and the unbraced `$LIB`, `$SDK_VER`, `$VNDK_VER`, and
  `$VNDK_APEX_VER` variables are replaced too.
- ELF (Android): DF_1_NODEFLIB is ignored, like the linker does.
- ELF (Android): the `--preload` objects are loaded for an executable without
  DT_NEEDED entries, like the linker does.
- ELF (FreeBSD): the hints directory list is also split on semicolons, and a
  hints file with offsets outside the file is rejected instead of panicking
  (the 16 KiB size limit rtld does not have is gone).
- ELF (FreeBSD): the `libmap.conf` section and mapping defined last win, a
  section matching one defined before adds to it, each included file is parsed
  once (a file including itself hung), an `includedir` only reads its regular
  `.conf` files, and the lines are parsed like `lmc_parse` does.
- ELF (FreeBSD): the `libmap.conf` mappings are applied where rtld applies
  them: after the loaded objects are matched, to the search directories too,
  with a mapping of an object section becoming an unconstrained one, and not
  to the preloaded names.
- ELF (FreeBSD): a dependency is not required to have the FreeBSD OS ABI.
- ELF (FreeBSD): the 32-bit compat default directories no longer include
  /lib/casper.
- ELF (FreeBSD): DF_1_NODEFLIB still searches the hints directories that are
  not standard ones.
- ELF (FreeBSD, OpenBSD): a name is matched against the DT_SONAME of every
  loaded object, not only the main one.
- ELF (OpenBSD): the hints file is read on the 32-bit systems (its header has
  C long fields), and one with offsets outside the file is rejected.
- ELF (OpenBSD): the search order follows the loader: `--library-path`, the
  DT_RUNPATH or else the DT_RPATH and the main program one, and the hints,
  with /usr/lib only without a valid hints file.
- ELF (OpenBSD): the executable DT_RPATH is kept along with its DT_RUNPATH for
  the libraries without DT_RUNPATH.
- ELF (OpenBSD): a loaded library is matched by name and major version, so it
  is not loaded again for another minor.
- ELF (OpenBSD, NetBSD): DF_1_NODEFLIB is ignored, like the loaders do.
- ELF (NetBSD): the `ld.so.conf` directives are skipped instead of taken as
  directories.
- ELF (NetBSD): the last of the DT_RPATH and DT_RUNPATH entries is the object
  search list, and `$ORIGIN` expands to the directory of each library, not of
  the executable.
- ELF (illumos): the 64-bit default directories are /lib/64 and /usr/lib/64,
  and any architecture is accepted (the SPARC and aarch64 inputs were
  refused).
- ELF (illumos): the search order follows ld.so.1: `--library-path`, the last
  of the DT_RPATH and DT_RUNPATH entries, and the default directories.
- ELF (illumos): `$ORIGIN` expands from the resolved object path, and the lists
  are split on colons and semicolons, an empty entry being the current
  directory.
- Mach-O: a universal file whose slice is itself a universal file no longer
  recurses until the stack overflows.
- Mach-O: an image with malformed load commands is rejected (a candidate is
  skipped) instead of being taken with a partial dependency list, and a load
  path that is not valid UTF-8 is kept.
- Mach-O: a crafted dyld cache trie no longer hangs the cache load.
- Mach-O: `--preload` is split on colons only, so a path with spaces is one
  entry.
- Mach-O: an LC_RPATH entry whose directory does not exist is kept, so an
  @rpath dependency held only by the dyld cache resolves.
- Mach-O: the images already loaded are matched the way dyld does (by path,
  install name, dyld cache alias, or file), so a not found @rpath dependency
  or a fallback directory hit no longer hides another image.
- Mach-O: a dependency candidate that is not a dylib, or, for a macOS
  executable, one built for another platform, is rejected like dyld does.
- Mach-O: `--library-path` is only searched for the load paths that are not a
  framework one, and a framework leaf with the image suffix is taken as a
  framework.
- Mach-O: @executable_path, @loader_path, and @rpath are only expanded as the
  leading component, the leading ../ of an @executable_path path are resolved
  against the executable directory, and only the load paths not starting with
  @ are retried through their realpath.
<!-- PE -->
- PE: `--ignore-prefix` matches either separator (`C:/Windows` pruned
  nothing), and no longer panics on a non-ASCII directory name.
- A closed standard output (for instance `rldd ... | head`) ends rldd quietly
  with the exit status due from the files processed so far, instead of a
  panic.
- A failed write of an error message, or of the usage (`rldd --help | true`),
  no longer panics or aborts.
- A file name that is not valid UTF-8 is reported for that file only, and the
  other files are still processed.
- A file directly in a root directory is no longer printed with a doubled
  separator (`//lib`), which also broke the Mach-O tree lookup of such a file.
- The `--depth` description shows its default.

### Removed

<!-- PE -->
- The `glob`, `raw-cpuid`, and `termcolor` dependencies, and the `tempfile`
  development dependency.
- The `help` help trigger.

## [0.5.0] - 2026-09-10

### Added

- Initial Windows support.  The dependencies recorded on the PE import and
  delay load import directories are resolved following the documented search
  order for unpackaged applications, along with the API set schema from
  `apisetschema.dll`, the `KnownDLLs` registry key, and the SysWOW64
  redirection for 32 bit images. A candidate built for another machine is
  skipped and the search continues, like the loader does.
- PE: new `--depth N` and `--ignore-prefix PREFIX` options to prune the
  dependency tree, `--library-path LIST` to mimic `SetDllDirectory`, and
  `--no-safe-search` to mimic `SafeDllSearchMode` disabled.
- PE: the `-v` option prints the object information (machine, subsystem,
  image base, API set schema, and known DLLs) along with the search path
  list used for the resolution.
- PE: the export forwarders are followed, so a module pulled in only by a
  forwarded export is listed with the `forwarded` attribute, including for
  the modules already resolved through another importer.
- PE: new `-d` and `-r` options, which check that every imported symbol is
  exported by the module it is imported from.
- PE: the dependent assemblies of the manifest, either the embedded
  `RT_MANIFEST` resource or an external `<object>.manifest` file, are
  resolved against the WinSxS store, which is searched before the loaded
  module list (so the same name may be loaded from more than one assembly).
- PE: the `.local` DLL redirection and the `bound` attribute for the imports
  bound at link time.
- ELF (Android): support for the HWASan instrumented objects, which use the
  `linker_hwasan64` loader, the `namespace.<ns>.hwasan.search.paths`
  properties, and the `$(PARTITION)/lib64/hwasan` default directories.
- A device test suite for the Android backend under `tests/android`, which
  builds rldd for the ABI of each attached device and resolves every object
  of the system image with it.
- A test suite for the PE backend under `tests/windows`, which runs rldd over
  the binaries of a system directory and compares the dependency names with
  `dumpbin /dependents`.
- A test suite for the Mach-O backend under `tests/macos`, which runs rldd
  over the objects of the system directories and the dyld cache images and
  compares the dependency lists with `dyld_info -dependents`.
- A test suite for the Linux ELF backend under `tests/linux`, which runs rldd
  over the objects of the system directories of a machine, either the local
  one or a host reached through ssh, and compares the dependency lists with
  `ldd`.
- A test suite for the BSD ELF backends under `tests/bsd`, which runs rldd
  over the objects of the system directories of a FreeBSD, OpenBSD or NetBSD
  machine, either the local one or a host reached through ssh where rldd is
  built, and compares the dependency lists with the `ldd` of each system.
- The CI workflow also builds on Windows, and checks the Android targets
  (which are only cross compiled).

### Changed

- A dependency whose resolved file differs from the recorded name is printed
  as `NAME -> FILE`, which on Windows shows the module that implements an API
  set.
- The `raw-cpuid` dependency is only used by the Linux ELF backend, and is no
  longer pulled in on the other systems.
- ELF (Android): the release is handled as the API level number it is, so a
  device newer than the ones known at build time behaves like the most recent
  handled one (it was an enumeration that stopped at Android 14, and anything
  newer failed with an unsupported release error).

### Fixed

- Mach-O: the `LC_LAZY_LOAD_DYLIB` load commands are ignored, like dyld
  does (the linker no longer emits them).
- Mach-O: a dependency not found is reported with its recorded load path
  (`@executable_path/...`, `@loader_path/...`) instead of the expanded one,
  like the `@rpath` ones and the ELF and PE names.
- Mach-O: an absolute dependency path not found on the root filesystem is
  retried below the OS cryptex mount, like dyld does for the images that
  are not on the root filesystem.
- Mach-O: a run-path entry ending with a slash no longer yields a double
  slash on the expanded @rpath candidate, which missed the dyld cache image
  (dyld joins the entry without a second slash).
- The dependency tree output is no longer colorized when stdout is not a
  terminal, and the `-l` output never is (the file header line carried
  escape sequences on a pipe).
- ELF (NetBSD): the search order follows the loader (`--library-path`,
  the `ld.so.conf` directories, the requesting object `DT_RPATH` or
  `DT_RUNPATH`, handled the same way, and then the default directories),
  and the `$ORIGIN` token expands to the executable directory for every
  object.
- ELF (FreeBSD, OpenBSD): the `$ORIGIN` token is expanded from the
  canonical object path, like both loaders do with realpath, so a symlink or
  a `..` component on the search path that reached the object is not kept.
- ELF (NetBSD): the compat subdirectory (for instance `/usr/lib/i386`)
  is searched for an object of another architecture.
- ELF (NetBSD): the ELF OS ABI of a candidate object is not checked.
- The `--preload` list also accepts whitespace as separator, like the
  loaders do with `LD_PRELOAD`.
- ELF (NetBSD): the `--preload` entries are opened as file paths, the way
  the loader handles `LD_PRELOAD` (a bare name was searched).
- ELF (glibc, FreeBSD): a dependency or preload entry naming the input
  object own `DT_SONAME` is taken as already loaded, like the loaders do.
- ELF (musl): the reserved names (`lib{c,pthread,rt,m,dl,util,xnet}.*`)
  resolve to the loader itself without any search, reported once per
  prefix as the musl ldd does.
- ELF (musl): the preloaded objects are always loaded, even for an object
  without any `DT_NEEDED` entry.
- ELF (musl): `DT_RUNPATH` is searched the way the loader searches it (like
  `DT_RPATH` along the chain of the objects that needed a library).
- ELF (FreeBSD, OpenBSD): the `DT_RPATH` of a shared library given as input
  no longer applies to its indirect dependencies.  On FreeBSD the main object
  is left out for an object with a `DT_RUNPATH`.
- ELF (OpenBSD): the first `libc.so.*` dependency found is used for every
  further libc load, like the loader does.
- Mach-O: a FAT file without a host architecture slice is still inspected
  when `--arch` is not given. The slice the system run through translation
  (x86_64 under Rosetta) is preferred, with the first slice as fallback
  (previously such files were rejected with a missing architecture error, while
  `dyld_info` and `otool` list them).
- ELF: the `--preload` entries mimic `LD_PRELOAD`. A name is searched like a
  regular dependency (it was silently ignored), an entry containing a slash is
  opened as a file path and printed as given (the resolved path was printed
  with the file name duplicated), and the entries are skipped for an object
  without any `DT_NEEDED` entry (which the loader reports as statically
  linked).
- ELF (Linux): a `DT_NEEDED` entry naming the program interpreter resolves
  to the `PT_INTERP` path, mimicking how the glibc loader matches it against
  its own soname without any search (it was resolved through the object
  search paths, so a `DT_RUNPATH` could redirect it).
- ELF (Linux): the `-u`/`--unused` check also reports an unused preloaded
  object, which the loader counts as a direct dependency.
- ELF (Linux): the first of the `ld.so.cache` entries with the same name and
  flags is taken.  It selects the right option for the case where the system
  has multiple options for system libraries (a system with both
  the multiarch `libc6:i386` and the legacy `libc6-i386` lists two
  `libc.so.6` for the 32 bit objects).
- ELF (Linux): an object of a machine without a known library directory no
  longer makes rldd panic on the `$LIB` expansion of its search path.
- ELF (Linux): a search path entry ending with a slash no longer doubles it
  on the resolved path.
- ELF (Linux): a shared library naming the loader in `DT_NEEDED` resolves it
  through the loader cache and the system directories, instead of through the
  library search paths.
- ELF (Linux): a `PT_DYNAMIC` segment whose size is not a multiple of the entry
  size is read up to what fits (instead of the object being refused).
- ELF (Linux): the system directories are the ones built into the loader of the
  object, read from its file (the multiarch directories and `/lib` and
  `/usr/lib` on Debian), instead of `/lib64` and `/usr/lib64` whatever the
  distribution.
- ELF (Linux): the `DT_SONAME` of a file is no longer checked against the name
  requested (so a symlink named otherwise than the library soname matches), and
  a name matching the `DT_SONAME` of an object already loaded is not loaded again.
- ELF (Linux): a dependency name containing a slash is opened as a file path,
  relative to the current directory when it is not absolute, instead of being
  searched through the directories, and a missing one is reported with its
  recorded name (`tmpdir/libfoo.so`) instead of its base name.
- ELF (Linux): a dependency name not found is searched again for each object
  requesting it, with the search paths of that object.
- ELF: handle `DT_AUXILIARY` and `DT_FILTER` entries of a dependency. The entries
  from the root object are not listed, and an object without any `DT_NEEDED`
  entry is reported statically linked whatever its filters.
- ELF: a dependency name holding a dynamic string token (`$ORIGIN`, `$LIB`,
  `$PLATFORM`) is expanded.
- ELF: a dependency referring back to the root object by its path is listed,
  once, the way the loader trace lists it.
- ELF (Linux): a `DT_NEEDED` entry naming the vDSO (`linux-vdso.so.1` and
  the like) is taken as already loaded.
- ELF (Android): any object without a `PT_INTERP` segment (including the
  loader itself) no longer panics, and its dependencies are resolved with
  the default system directories.
- ELF (Android): a `${LIB}` substitution and a default directory of an
  architecture without an explicit entry (`riscv64`) no longer panics or
  fails. Both are now derived from the object ELF class like the loader does.
- ELF (Android): the `/odm/lib[64]` default directory is used from Android 9
  onward (it was dropped again from Android 14).
- ELF (Android): the `/linkerconfig/<apex>/ld.config.txt` path had a stray
  character, so an executable shipped on an APEX always fell back to the
  system configuration.
- ELF (Android): the `${VNDK_APEX_VER}` substitution uses the `v` delimiter
  instead of the `-` one used by `${VNDK_VER}`, and the `current` VNDK
  version is the one that expands to an empty string (`default` was checked
  instead).
- ELF (Android): a namespace link only makes the libraries listed on its
  `shared_libs` property accessible, unless `allow_all_shared_libs` is set
  (the list was parsed for validation but not used on the resolution).
- ELF (Android): a `.version` file that can not be read falls back to the
  running release instead of failing the whole configuration parsing, and
  an unreadable `ro.vndk.lite` property no longer panics.
- ELF (Android): a `DT_NEEDED` entry naming the vDSO (the arm translation
  objects have one) is not reported as not found, since the loader resolves
  it against the image the kernel maps.
- ELF (Android): a shared library, which never matches a `dir.` mapping since
  those only cover the executable directories, is resolved with the section
  that maps the executable directory of its partition (`/system/lib64` uses
  the `/system/bin` one) instead of falling back to the default system
  directories, which left every dependency provided by an APEX unresolved.
- ELF (Android): `DT_RPATH` is not searched, since the bionic loader does not
  implement it.

## [0.4.0] - 2026-08-17

This release contains a major rework of the Mach-O dependency resolution,
extended relocation checks on Linux/glibc, and multiple resolution fixes
for the BSDs and Linux/musl.

### Added

- New `-v`/`--verbose` option that prints the search path information used
  to resolve each dependency, and the searched locations for dependencies
  that are not found.
- ELF (Linux): new relocation check options `-d`/`--data-relocs`,
  `-r`/`--function-relocs`, and `-u`/`--unused`, which verify whether the
  relocations can be resolved with the loaded dependencies and report
  unused ones.
- ELF: FreeBSD `libmap.conf` support.
- Mach-O: new `--arch NAME` option to select a slice of a universal binary
  along with the matching dyld shared cache flavor (for instance
  `--arch x86_64` on Apple Silicon resolves against the Rosetta cache).
- Mach-O: support for `DYLD_FALLBACK_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`,
  and `DYLD_FALLBACK_FRAMEWORK_PATH`.
- Mach-O: support for dyld shared cache subcaches and the macOS Sonoma,
  Sequoia, and Tahoe cache layouts; the cache location is now probed on the
  filesystem.  The input file may be an install name of an image that only
  exists inside the dyld shared cache, like `dyld_info`.
- Mach-O: the `-v` option also prints the object information from the load
  commands: the install name, the platform, the UUID, and the dependencies
  compatibility and current versions.

### Changed

- ELF: dependencies are resolved in breadth-first order, matching the
  dynamic loader behavior.
- ELF: the relocation checks take symbol versioning in consideration, and
  process COPY relocations, TLSDESC relocations, and the MIPS global GOT
  symbols.
- ELF: relocations for musl objects are processed like the musl ldd, and
  the musl dependency resolution was fixed.
- ELF: the ldd mode output prints `statically linked` for objects with no
  dependencies, always lists the dynamic loader, and objects without
  `PT_INTERP` assume the system loader.
- Mach-O: the dependency resolution was reworked to follow the dyld search
  order: the run-path list is searched from the whole loading chain,
  `@loader_path` is expanded on `LC_RPATH` entries, unversioned framework
  paths are resolved against the dyld shared cache, and dependencies are
  tracked like `dyld_info` and `dylibtree`.
- A missing file argument now exits with an error status.

### Fixed

- ELF: fix `$PLATFORM` expansion on rpath/runpath.
- ELF: fix the `DT_RPATH` search to follow the loader chain, and its scope
  for indirect dependencies on the BSDs.
- ELF: fix the `ld.so.cache` entry flags check for arm, riscv, LoongArch,
  and SPARC (v9 and v8+), and the mips64el REL relocation decoding.
- ELF: fix the FreeBSD default library search paths and the resolution of
  FreeBSD 32-bit compat objects.
- ELF: fix the OpenBSD library version matching, mimic the OpenBSD loader
  minor version matching for the input object, and list the loader for
  OpenBSD executables.
- ELF: avoid a panic on malformed `PT_INTERP` offsets and reject objects
  with an empty dynamic section.
- Mach-O: honor the `-a` option for already resolved dependencies, and do
  not handle `LC_ID_DYLIB` as a dependency.
- Fix the ldd mode output for not found and duplicated entries.

## [0.3.0] - 2025-02-01

### Added

- GitHub Actions CI workflow.

### Fixed

- ELF: fix the dependency path value for the `-p` option.
- ELF: fix the SPARC default system directories.

### Changed

- Update dependencies and multiple cargo clippy and cargo fmt cleanups
  across all supported systems.

## [0.2.0] - 2023-01-24

### Added

- Initial Android support: `ld.config.txt` namespaces, SDK/VNDK version
  substitutions, and asan system paths.
- ELF: check the `CACHE_MAGIC` for the old `ld.so.cache` format.
- Print a help message when no argument is provided.

## [0.1.0] - 2023-01-05

- Initial release with ELF support for Linux (glibc, musl, and Android),
  FreeBSD, OpenBSD, and NetBSD, and initial Mach-O support for macOS.
