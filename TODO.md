# rldd 

## Generic

- [ ] Add better debug messages for not found libraries.
- [ ] Add better search patch information for -v option.

## ELF

### TODO

- [ ] Linux add [glibc-hwcap support](https://sourceware.org/pipermail/libc-alpha/2020-June/115250.html), which affects symbol resolution paths fro x86_64, powerpc64, aarch64, and s390-64.
- [ ] Linux: read /etc/ld.so.cache instead of parsing /etd/ld.so.conf.
- [ ] FreeBSD: Add [libmap.conf](https://www.freebsd.org/cgi/man.cgi?libmap.conf) support.  This is used to filter and map origins to new targets.

## MachO

## Done

- [ X ] MachO: Add initial MacOSX support.
- [ X ] MachO: Resolve the dyld cache dependencies.  It requires not only parsing the cache entries, but the entries itself.
