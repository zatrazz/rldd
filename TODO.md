# rldd 

## Generic

## ELF

### TODO

## MachO

## PE

### TODO

- [ ] Side-by-side: read the publisher policy, the highest installed build of the requested major and minor version is used instead.
- [ ] The package dependency graph of a packaged application.
- [ ] API set schema version 4 (Windows 8.1), only version 6 is parsed.


## Done

- [x] PE: Follow the export forwarders, including for the modules already
      resolved through another importer.
- [x] PE: Resolve the side-by-side assemblies of the embedded and the
      external manifests.
- [x] PE: Handle the '.local' DLL redirection and the known DLL dependencies.
- [x] PE: Report the bound imports.
- [x] PE: Check the imports against the export tables (-d, -r, and -u).
- [x] MachO: Implement DYLD_FALLBACK_LIBRARY_PATH.
- [x] MachO: Implement DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_FRAMEWORK_PATH.
- [x] Take symbol versioning in consideration on the -d/-r/-u relocation checks.
- [x] FreeBSD: Add [libmap.conf](https://www.freebsd.org/cgi/man.cgi?libmap.conf) support.
- [x] Add search path information for -v option.
- [x] Print the searched locations for not found libraries in verbose mode.
- [x] MachO: Add initial MacOSX support.
- [x] MachO: Resolve the dyld cache dependencies.  It requires not only parsing the cache entries, but the entries itself.
- [x] Linux: read /etc/ld.so.cache instead of parsing /etd/ld.so.conf.
- [x] Implement DYLD_INSERT_LIBRARIES.
- [x] Linux: add [glibc-hwcap support](https://sourceware.org/pipermail/libc-alpha/2020-June/115250.html), which affects symbol resolution paths fro x86_64, powerpc64, aarch64, and s390-64.
- [x] Linux: add Android support.
