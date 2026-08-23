# rldd 

## Generic

## ELF

### TODO

## MachO

## PE

### TODO

- [ ] The export forwarders are only followed for the symbols the first importer of a module records, since the resolution stops at the first time a module is added to the tree.
- [ ] Side-by-side: read the external '.manifest' files and the publisher policy, only the embedded RT_MANIFEST resource is parsed and the highest installed build of the requested version is used.
- [ ] DLL redirection with the '.local' file.
- [ ] The package dependency graph of a packaged application.
- [ ] Treat the dependencies of a known DLL as known DLLs as well.
- [ ] Parse the bound import directory and report a 'bound' attribute.
- [ ] API set schema version 4 (Windows 8.1), only version 6 is parsed.


## Done

- [x] PE: Follow the export forwarders.
- [x] PE: Resolve the side-by-side assemblies of the embedded manifest.
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
