# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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

- The dependency tree output is no longer colorized when stdout is not a
  terminal, and the `-l` output never is (the file header line carried
  escape sequences on a pipe).
- ELF (NetBSD): the search order follows the loader (`--library-path`,
  the `ld.so.conf` directories, the requesting object `DT_RPATH` or
  `DT_RUNPATH`, handled the same way, and then the default directories),
  and the `$ORIGIN` token expands to the executable directory for every
  object.
- ELF (FreeBSD, OpenBSD): the `$ORIGIN` token is expanded from the
  canonical object path.
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
