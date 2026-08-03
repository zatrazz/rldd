# rldd 

## Generic

- [ ] Add better debug messages for not found libraries.

## ELF

### TODO

- [ ] FreeBSD: Add [libmap.conf](https://www.freebsd.org/cgi/man.cgi?libmap.conf) support.  This is used to filter and map origins to new targets.
- [ ] Take symbol versioning in consideration on the -d/-r/-u relocation checks.

## MachO

- [ ] Implement DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_FRAMEWORK_PATH.
- [ ] Implement DYLD_FALLBACK_LIBRARY_PATH.

## Done

- [x] Add search path information for -v option.
- [x] MachO: Add initial MacOSX support.
- [x] MachO: Resolve the dyld cache dependencies.  It requires not only parsing the cache entries, but the entries itself.
- [x] Linux: read /etc/ld.so.cache instead of parsing /etd/ld.so.conf.
- [x] Implement DYLD_INSERT_LIBRARIES.
- [x] Linux: add [glibc-hwcap support](https://sourceware.org/pipermail/libc-alpha/2020-June/115250.html), which affects symbol resolution paths fro x86_64, powerpc64, aarch64, and s390-64.
- [x] Linux: add Android support.
