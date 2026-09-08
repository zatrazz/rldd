#!/usr/bin/env python3
"""Runs on the BSD under test: compare 'rldd -l' with ldd over the ELF
objects below the roots and print a machine readable report for run.sh to
check.  Kept in one script so a remote sweep is a single ssh round trip.

usage: sweep.py --rldd PATH [--sample N] [--jobs N] ROOT...

The report lines are tab separated:

  FILES n            objects inspected
  COMPARED n         objects both tools list the dependencies of
  UNTRACED n         objects ldd traces nothing for (another machine, static)
  UNREADABLE n       objects without read permission
  UNREADABLE-DIRS n  directories the walk could not enter
  PANIC path what    the object made rldd panic, or time out
  REFUSED path what  ldd traces the object, rldd refused it
  DIFF path what     the two listings differ
  UNRESOLVED path name
                     both tools report the dependency as not found
"""

import argparse
import multiprocessing
import os
import random
import re
import signal
import stat
import struct
import subprocess
import sys
import threading

import platform

NOT_FOUND = "not found"
OS = platform.system()
SKIPPED_DIRS = ("/usr/lib/debug", "/usr/libdata/debug")

# The loader must not see the environment of the sweep itself, and its
# messages must not be translated.
ENV = {k: v for k, v in os.environ.items() if not k.startswith("LD_")}
ENV["LC_ALL"] = "C"

RLDD = None


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=300, env=ENV)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -1, "", str(e)


ET_EXEC, ET_DYN = 2, 3
PT_INTERP = 3


def elf_info(path):
    """(e_type, interp, class) of an ELF file, or None when it is not one."""
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF" or ident[4] not in (1, 2):
                return None
            bits = ident[4]
            endian = "<" if ident[5] == 1 else ">"
            fmt = endian + ("HHIIIIIHHHHHH" if bits == 1 else "HHIQQQIHHHHHH")
            fields = struct.unpack(fmt, f.read(struct.calcsize(fmt)))
            e_type, phoff, phentsize, phnum = fields[0], fields[4], fields[8], fields[9]
            interp = None
            if e_type in (ET_EXEC, ET_DYN) and phnum:
                f.seek(phoff)
                phdrs = f.read(phentsize * phnum)
                for i in range(phnum):
                    ph = phdrs[i * phentsize:(i + 1) * phentsize]
                    if bits == 1:
                        p_type, p_offset, _, _, p_filesz = struct.unpack(endian + "IIIII", ph[:20])
                    else:
                        p_type, _, p_offset, _, _, p_filesz = struct.unpack(endian + "IIQQQQ", ph[:40])
                    if p_type == PT_INTERP:
                        f.seek(p_offset)
                        interp = f.read(p_filesz).split(b"\0", 1)[0].decode("utf-8", "replace")
                        break
            return e_type, interp, bits
    except (OSError, struct.error, ValueError):
        return None


def is_loadable(path):
    info = elf_info(path)
    return info is not None and info[0] in (ET_EXEC, ET_DYN)


def quiet_interrupt():
    signal.signal(signal.SIGINT, lambda *_: os._exit(130))


def pool(jobs):
    return multiprocessing.get_context("fork").Pool(jobs, initializer=quiet_interrupt)


# The filesystems with nothing to load, or which may hang the walk.
VIRTUAL_FS = ("devfs", "fdescfs", "procfs", "linprocfs", "linsysfs", "tmpfs", "mfs", "kernfs",
              "ptyfs", "fusefs", "autofs", "mqueuefs")


def skipped_mounts():
    """The mount points of the virtual filesystems, and the FUSE and network
    ones, which a sweep of / would otherwise descend into, from the mount
    listing ('DEV on DIR (TYPE, ...)' on FreeBSD, 'DEV on DIR type TYPE' on
    the others)."""
    skipped = set()
    _, out, _ = run(["/sbin/mount"])
    for line in out.split("\n"):
        m = re.match(r"^\S+ on (\S+) (?:type (\S+)|\((\w+)[,)])", line)
        if not m:
            continue
        fstype = m.group(2) or m.group(3)
        if fstype in VIRTUAL_FS or fstype.startswith(("fuse", "nfs", "smb")):
            skipped.add(m.group(1))
    return skipped


def list_dir(directory):
    """The loadable ELF files of a directory and its subdirectories, without
    following symlinks, and whether the directory could be read at all."""
    files = []
    subdirs = []
    readable = True
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.path)
                    elif entry.is_file(follow_symlinks=False) and is_loadable(entry.path):
                        st = entry.stat(follow_symlinks=False)
                        files.append((entry.path, st.st_dev, st.st_ino))
                except OSError:
                    continue
    except OSError:
        readable = False
    return files, subdirs, readable


MEDIA_DIRS = ("/media", "/mnt", "/run/media")


def find_objects(roots, jobs):
    """Every loadable ELF file below the roots, a hard link counted once and a
    root reached through another one (/lib on a merged /usr) walked once.  A
    root may also be a single file.  The directories are handed to the
    workers as they are found, each one queuing its subdirectories, so a slow
    directory (a spun down disk) only holds the worker reading it."""
    skipped = set(SKIPPED_DIRS) | set(MEDIA_DIRS) | skipped_mounts()
    files = []
    directories = []
    seen = set()
    for root in roots:
        root = os.path.realpath(root)
        if root in seen:
            continue
        seen.add(root)
        if os.path.isfile(root):
            st = os.stat(root)
            files.append((root, st.st_dev, st.st_ino))
        elif os.path.isdir(root):
            directories.append(root)

    lock = threading.Lock()
    done = threading.Event()
    state = {"pending": 0, "walked": 0, "unreadable": 0}

    def submit(directory):
        with lock:
            state["pending"] += 1
        p.apply_async(list_dir, (directory,), callback=collect)

    def collect(result):
        part, subdirs, readable = result
        with lock:
            files.extend(part)
            state["walked"] += 1
            state["unreadable"] += not readable
            walked = state["walked"]
            state["pending"] -= 1
        for subdir in subdirs:
            if subdir not in skipped:
                submit(subdir)
        with lock:
            if state["pending"] == 0:
                done.set()

    if directories:
        with pool(jobs) as p:
            for directory in directories:
                submit(directory)
            # A plain wait would not see Ctrl-C.
            while not done.wait(0.5):
                pass
    seen = set()
    paths = []
    for path, dev, ino in sorted(files):
        if (dev, ino) not in seen:
            seen.add((dev, ino))
            paths.append(path)
    return paths, state["unreadable"]


# FreeBSD prints a header line for the object, then # 'NAME => PATH (0xADDR)' or
# 'NAME => not found (0)', and a '[vdso]' line.  An object it cannot trace gets
# 'not a dynamic ELF executable' on stderr.
FREEBSD_DEP = re.compile(r"^(.+?) => (.+) \(0x[0-9a-fA-F]+\)$")
FREEBSD_NOT_FOUND = re.compile(r"^(.+?) => not found \(0\)$")
# NetBSD prints the entries with a format, which is asked as the library
# name pieces and the path, tab separated, with 'not found' as the path and
# '(null)' as the major of a name without one.
NETBSD_FORMAT = "%o\t%m\t%p\n"
# OpenBSD prints a table, one row per object mapped. The object itself
# first (exe, or dlib for a library dlopen'ed), the libraries (rlib) and
# the loader (ld.so), with the path only; an object it cannot trace stops
# it with 'can't load library' on stderr.
OPENBSD_ROW = re.compile(r"^[0-9a-f]+\s+[0-9a-f]+\s+(\S+)\s+\d+\s+\d+\s+\d+\s+(.+)$")
OPENBSD_NOT_FOUND = re.compile(r"can't load library '(.+?)'")
# The rldd -l output: 'NAME => PATH' or 'NAME => not found'.
RLDD_DEP = re.compile(r"^(.+?) => (.+)$")


def ldd_command(path):
    if OS == "NetBSD":
        return ["ldd", "-f", NETBSD_FORMAT, path]
    return ["ldd", path]


def parse_ldd(rc, out, err):
    deps = set()
    bare = []
    lines = [line.strip() for line in out.split("\n") if line.strip()]
    if OS == "FreeBSD":
        if "not a dynamic ELF executable" in err:
            return "not a dynamic ELF executable", deps, bare
        # The header comes before the trace, so an object the loader refuses
        # (a kernel, without execute permission) leaves it alone with the
        # error on stderr.
        if rc != 0:
            return (err.strip() or "exit status %d" % rc).split("\n")[-1], deps, bare
        for line in lines[1:]:
            if line.startswith("[vdso]"):
                continue
            m = FREEBSD_DEP.match(line)
            if m:
                deps.add((m.group(1), m.group(2)))
                continue
            m = FREEBSD_NOT_FOUND.match(line)
            if m:
                deps.add((m.group(1), NOT_FOUND))
                continue
            return "unexpected line: " + line, deps, bare
        return ("ok" if deps else "static"), deps, bare
    if OS == "NetBSD":
        if rc != 0:
            return (err.strip() or "exit status %d" % rc).split("\n")[0], deps, bare
        for line in lines:
            fields = line.split("\t")
            if len(fields) != 3:
                return "unexpected line: " + line, deps, bare
            name, major, path = fields
            # The name pieces of the '-lNAME.MAJOR' spelling, back to the
            # DT_NEEDED entry they come from.
            name = "lib%s.so%s" % (name, "." + major if major not in ("", "(null)") else "")
            deps.add((name, NOT_FOUND if path == "not found" else path))
        return ("ok" if deps else "static"), deps, bare
    if OS == "OpenBSD":
        m = OPENBSD_NOT_FOUND.search(err)
        if m:
            deps.add((m.group(1), NOT_FOUND))
            return "missing", deps, bare
        if "not a dynamic executable" in lines:
            return "not a dynamic executable", deps, bare
        if rc != 0:
            return (err.strip() or "exit status %d" % rc).split("\n")[0], deps, bare
        rows = [OPENBSD_ROW.match(line) for line in lines]
        rows = [m for m in rows if m]
        if not rows:
            return "unexpected output", deps, bare
        # The first row is the object itself, an executable run or a library
        # dlopen'ed, for which the loader row is the one of the ldd process.
        library = rows[0].group(1) != "exe"
        for m in rows[1:]:
            kind, path = m.group(1), m.group(2)
            if kind == "rlib" or (kind == "ld.so" and not library):
                bare.append(path)
        return ("ok" if bare else "static"), deps, bare
    return "unsupported system: " + OS, deps, bare


def parse_rldd(out):
    deps = set()
    for line in out.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line == "statically linked":
            return "static", deps
        m = RLDD_DEP.match(line)
        if not m:
            return "unexpected line: " + line, deps
        deps.add((m.group(1), m.group(2)))
    return "ok", deps


def is_setid(path):
    try:
        return bool(os.stat(path).st_mode & (stat.S_ISUID | stat.S_ISGID))
    except OSError:
        return False


def realpath(path):
    try:
        return os.path.realpath(path)
    except OSError:
        return path


# The FreeBSD ldd has the libc (listed) and libsys (not, the rtld loads it
# itself), and the OpenBSD one dlopens the library into a process that has
# the libc and the loader (neither listed).  The FreeBSD ldd traces a 32 bit
# PIE executable that way too, only a 64 bit one is run.
IMPLICIT = {"FreeBSD": re.compile(r"^(libsys|libc)\.so\."),
            "OpenBSD": re.compile(r"^(libc\.so\.|ld\.so$)")}


def traced_as_library(info):
    e_type, interp, bits = info
    return interp is None or (OS == "FreeBSD" and bits == 1 and e_type == ET_DYN)


def compare(info, ldd_deps, ldd_bare, rldd_deps):
    interp = info[1]
    rldd_deps = set(rldd_deps)
    ldd_deps = set(ldd_deps)
    diffs = []
    implicit = IMPLICIT.get(OS)
    if traced_as_library(info) and implicit:
        listed = dict((n, p) for n, p in ldd_deps)
        for name, path in list(rldd_deps):
            if path == NOT_FOUND or not implicit.match(name):
                continue
            rldd_deps.remove((name, path))
            if name in listed and realpath(listed[name]) == realpath(path):
                rldd_deps.add((name, listed[name]))
            elif name in listed:
                rldd_deps.add((name, path))
            elif os.path.basename(path) in {os.path.basename(p) for p in ldd_bare}:
                rldd_deps.add((name, path))
    if OS == "OpenBSD":
        # Paths only, the loader included for an executable; the input object
        # itself may be listed again when a dependency refers back to it.
        want = {realpath(path) for path in ldd_bare}
        got = {realpath(path) for name, path in rldd_deps if path != NOT_FOUND}
        for path in sorted(want - got):
            diffs.append("ldd loads %s, which rldd does not list" % path)
        for path in sorted(got - want):
            diffs.append("rldd resolves %s, which ldd does not load" % path)
        for name, path in sorted(rldd_deps):
            if path == NOT_FOUND:
                diffs.append("%s => not found: only rldd" % name)
        return diffs
    for path in ldd_bare:
        real = realpath(path)
        matched = {d for d in rldd_deps if d[1] != NOT_FOUND and realpath(d[1]) == real}
        if matched:
            rldd_deps -= matched
        elif not (interp and realpath(interp) == real):
            diffs.append("ldd loads %s, which rldd does not list" % path)
    only_ldd = sorted(ldd_deps - rldd_deps)
    only_rldd = sorted(rldd_deps - ldd_deps)
    for name, path in only_ldd:
        other = [p for n, p in only_rldd if n == name]
        if other:
            diffs.append("%s: ldd %s, rldd %s" % (name, path, other[0]))
        else:
            diffs.append("%s => %s: only ldd" % (name, path))
    for name, path in only_rldd:
        if not any(n == name for n, _ in only_ldd):
            diffs.append("%s => %s: only rldd" % (name, path))
    return diffs


def check(path):
    if not os.access(path, os.R_OK):
        return [("UNREADABLE",)]
    info = elf_info(path) or (None, None, None)
    interp = info[1]

    rc, out, err = run([RLDD, "-l", path])
    if "panicked" in err or (rc == -1 and err == "timeout"):
        what = [l for l in err.split("\n") if "panicked" in l]
        return [("PANIC", path, what[0] if what else err.strip())]
    if rc != 0 and not out:
        rldd_status, rldd_deps = "error", set()
        refused = err.strip().split("\n")[0] if err.strip() else "exit status %d" % rc
    else:
        rldd_status, rldd_deps = parse_rldd(out)
        refused = rldd_status

    rc, out, err = run(ldd_command(path))
    if rc == -1 and err == "timeout":
        return [("PANIC", path, "ldd timeout")]
    ldd_status, ldd_deps, ldd_bare = parse_ldd(rc, out, err)
    if ldd_status == "static" and is_setid(path):
        # The FreeBSD ldd runs the object in trace mode, and the loader
        # ignores the trace request of a set-user-ID one, so nothing comes.
        return [("UNTRACED",)]
    if ldd_status == "missing":
        # The OpenBSD ldd stops at the first library it cannot load, so only
        # that one is compared: rldd has to report it not found too.
        if rldd_status not in ("ok", "static"):
            return [("REFUSED", path, refused)]
        name = next(iter(ldd_deps))[0]
        if (name, NOT_FOUND) in rldd_deps:
            return [("COMPARED",), ("UNRESOLVED", path, name)]
        return [("COMPARED",), ("DIFF", path, "ldd cannot load %s, which rldd %s" % (
            name, "resolves" if any(n == name for n, _ in rldd_deps) else "does not list"))]
    if ldd_status not in ("ok", "static"):
        return [("UNTRACED",)]

    if rldd_status not in ("ok", "static"):
        return [("REFUSED", path, refused)]
    if ldd_status != rldd_status:
        listed = ", ".join(sorted(n for n, _ in (ldd_deps or rldd_deps)))
        return [("DIFF", path, "ldd: %s; rldd: %s (%s)" % (ldd_status, rldd_status, listed))]

    lines = [("COMPARED",)]
    diffs = compare(info, ldd_deps, ldd_bare, rldd_deps)
    if diffs:
        lines.append(("DIFF", path, "; ".join(diffs)))
    for name, resolved in sorted(ldd_deps & rldd_deps):
        if resolved == NOT_FOUND:
            lines.append(("UNRESOLVED", path, name))
    return lines


def main():
    global RLDD
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--rldd", required=True)
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()
    RLDD = os.path.abspath(args.rldd)

    objects, unreadable_dirs = find_objects(args.roots, args.jobs)
    if args.sample and len(objects) > args.sample:
        objects = sorted(random.sample(objects, args.sample))

    counters = {"FILES": len(objects), "COMPARED": 0, "UNTRACED": 0, "UNREADABLE": 0,
                "UNREADABLE-DIRS": unreadable_dirs}
    with pool(max(1, min(args.jobs, len(objects)))) as p:
        for lines in p.imap_unordered(check, objects, chunksize=4):
            for line in lines:
                if len(line) == 1:
                    counters[line[0]] += 1
                else:
                    print("\t".join(line))
    for key, value in counters.items():
        print("%s\t%d" % (key, value))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
