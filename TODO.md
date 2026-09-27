# rldd 

## Generic

### TODO

- [ ] Support the path names that are not valid UTF-8 end to end.  The command
      line keeps such a file name, but the backends take the paths as a
      `&str`, so the file is reported as an error (and an `$ORIGIN` or an
      ld.so.cache entry that is not valid UTF-8 is dropped).

## ELF

### TODO

- [ ] illumos: read the crle(1) configuration files (the default and the
      trusted directories, and the alternate objects).
- [ ] illumos: search the capability directories of the `$CAPABILITY` and
      `$HWCAP` tokens, whose entries are dropped.
- [ ] illumos: apply the secure process rules (the trusted directories of a
      set-user-ID program).
- [ ] OpenBSD: search the requesting object DT_RPATH and the main program one
      as two lists, like _dl_load_shlib does.  They are kept in a single list,
      so the hints are looked up for the directories of both before either
      one is scanned.
- [ ] NetBSD: handle the hardware dependent library directives of ld.so.conf
      (the lines not starting with '/'), which are skipped.
- [ ] Linux: check the z17 glibc-hwcaps level glibc 2.42 adds for s390x, which
      tests the stfle facility list rather than an AT_HWCAP bit.
- [ ] Linux: take the AT_HWCAP and platform bits of the non-x86 loaders before
      glibc 2.40 on the legacy ld.so.cache entries (only the tls one is), and
      their hwcap names on the legacy hwcaps subdirectories.
- [ ] Linux: add an option to set the /usr prefix of the default directories
      assumed when the loader can not be read.
- [ ] Android: the linker fallback to the normalized path of a search
      directory it can not resolve, and the directories inside a zip file.

## MachO

### TODO

- [ ] The AMFI policies dyld4 defers to, which no dyld source ties to the file:
      a hardened runtime program without the
      com.apple.security.cs.allow-dyld-environment-variables entitlement, and
      the CS_RESTRICT code signing flag under SIP.
- [ ] The DYLD_VERSIONED_LIBRARY_PATH and DYLD_VERSIONED_FRAMEWORK_PATH
      variables of the LC_DYLD_ENVIRONMENT load commands.
- [ ] The platform rules of the processes other than a macOS one (an iOS or a
      Mac Catalyst app on a Mac also loads the macOS images, and a simulator
      process some host ones), and of a dylib input, whose dependency
      candidates are not checked for their platform.

## PE

### TODO

- [ ] Side-by-side: read the Win32 publisher policy.  The highest installed build of the requested major and minor version is used instead, and a Windows 11 install carries no Win32 policy assembly to check it against (the '*_policy.*' ones on WinSxS are managed assemblies).
- [ ] The package dependency graph of a packaged application.
- [ ] API set schema version 4 (Windows 8.1), only version 6 is parsed.


## Done

- [x] PE: Follow the export forwarders, including for the modules already
      resolved through another importer.
- [x] PE: Resolve the side-by-side assemblies of the embedded and the
      external manifests.
- [x] PE: Handle the '.local' DLL redirection and the known DLL dependencies.
- [x] PE: Report the bound imports.
- [x] PE: Check the imports against the export tables (-d and -r).
- [x] MachO: Implement DYLD_FALLBACK_LIBRARY_PATH.
- [x] MachO: Implement DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_FRAMEWORK_PATH.
- [x] Take symbol versioning in consideration on the -d/-r/-u relocation checks.
- [x] FreeBSD: Add [libmap.conf](https://www.freebsd.org/cgi/man.cgi?libmap.conf) support.
- [x] Add search path information for -v option.
- [x] Print the searched locations for not found libraries in verbose mode.
- [x] MachO: Add initial MacOSX support.
- [x] MachO: Resolve the dyld cache dependencies.  It requires not only parsing the cache entries, but the entries themselves.
- [x] Linux: read /etc/ld.so.cache instead of parsing /etc/ld.so.conf.
- [x] Implement DYLD_INSERT_LIBRARIES.
- [x] Linux: add [glibc-hwcap support](https://sourceware.org/pipermail/libc-alpha/2020-June/115250.html), which affects symbol resolution paths for x86_64, powerpc64, aarch64, and s390-64.
- [x] Linux: add Android support.
