#!/usr/bin/env python3
"""Runs on the machine under test: compare 'rldd -l' with ldd over the ELF
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
import struct
import subprocess
import sys
import threading

NOT_FOUND = "not found"
VDSO = ("linux-vdso", "linux-gate")
SKIPPED_DIRS = ("/usr/lib/debug",)

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
    """(e_type, interp) of an ELF file, or None when it is not one."""
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
            return e_type, interp
    except (OSError, struct.error, ValueError):
        return None


def is_loadable(path):
    info = elf_info(path)
    return info is not None and info[0] in (ET_EXEC, ET_DYN)


def quiet_interrupt():
    """On Ctrl-C a worker just goes away, leaving the report to the parent
    (a handler rather than SIG_IGN, which the tools would inherit)."""
    signal.signal(signal.SIGINT, lambda *_: os._exit(130))


def pool(jobs):
    # Forked, so the workers see RLDD (Python 3.14 spawns them from scratch
    # by default).
    return multiprocessing.get_context("fork").Pool(jobs, initializer=quiet_interrupt)


# The filesystems with nothing to load, or which may hang the walk.
VIRTUAL_FS = ("proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "pstore",
              "bpf", "debugfs", "tracefs", "securityfs", "configfs", "fusectl", "hugetlbfs",
              "mqueue", "binfmt_misc", "autofs", "efivarfs", "nsfs", "rpc_pipefs", "ramfs")


def skipped_mounts():
    skipped = set()
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 3:
                    continue
                fstype = fields[2]
                if fstype in VIRTUAL_FS or fstype.startswith(("fuse", "nfs", "cifs", "smb")):
                    skipped.add(fields[1].replace("\\040", " "))
    except OSError:
        pass
    return skipped


def list_dir(directory):
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


# Where the removable media is mounted, left out of a sweep of / unless given
# as a root: a backup or a photo disk holds nothing to load and takes hours.
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


# The ldd output: 'NAME => PATH (0xADDR)', 'NAME => not found', 'PATH (0xADDR)'
# for the interpreter or a DT_NEEDED with a slash, 'NAME (0xADDR)' for the vDSO.
# The verdicts (statically linked, not a dynamic executable) go to stderr on the
# recent releases.
LDD_DEP = re.compile(r"^(.+?) => (.+) \(0x[0-9a-fA-F]+\)$")
LDD_NOT_FOUND = re.compile(r"^(.+?) => not found$")
LDD_BARE = re.compile(r"^(.+) \(0x[0-9a-fA-F]+\)$")
# The rldd -l output: 'NAME => PATH' or 'NAME => not found'.
RLDD_DEP = re.compile(r"^(.+?) => (.+)$")
# The loader names of glibc and of musl.  ldd runs an object under its own
# loader whatever the PT_INTERP says, so an object naming another one (a
# test loader of the gdb testsuite, a musl binary on a glibc system) is
# traced the way it would not run, and is left out.
GLIBC_LOADER = re.compile(r"^(ld-linux[\w.-]*\.so\.\d+|ld\.so\.1|ld64\.so\.[12])$")
MUSL_LOADER = re.compile(r"^ld-musl-[\w.-]*\.so\.1$")
SYSTEM_LOADER = GLIBC_LOADER


def ldd_flavor():
    """The loader ldd belongs to, from its version banner."""
    _, out, err = run(["ldd", "--version"])
    return MUSL_LOADER if "musl" in out + err else GLIBC_LOADER
# The musl ldd reports a missing library on stderr, with the listing so far
# on stdout, where the glibc one lists it as not found.
MUSL_NOT_FOUND = re.compile(r"^Error loading shared library (.+?): .* \(needed by .*\)$")


def parse_ldd(rc, out, err):
    """(status, deps, bare): 'ok', 'static' or the failure reason, the
    (name, path or 'not found') set, and the paths listed without a name."""
    deps = set()
    bare = []
    for line in err.split("\n") + out.split("\n"):
        line = line.strip()
        if line == "statically linked":
            return "static", deps, bare
        if line == "not a dynamic executable" or line.endswith("Not a valid dynamic program"):
            return line, deps, bare
        m = MUSL_NOT_FOUND.match(line)
        if m:
            deps.add((m.group(1), NOT_FOUND))
    if rc != 0 and not out.strip():
        return (err.strip() or "exit status %d" % rc).split("\n")[0], deps, bare
    for line in out.split("\n"):
        line = line.strip()
        if not line:
            continue
        m = LDD_DEP.match(line)
        if m:
            deps.add((m.group(1), m.group(2)))
            continue
        m = LDD_NOT_FOUND.match(line)
        if m:
            deps.add((m.group(1), NOT_FOUND))
            continue
        m = LDD_BARE.match(line)
        if m and "/" in m.group(1):
            bare.append(m.group(1))
        elif not m or not m.group(1).startswith(VDSO):
            return "unexpected line: " + line, deps, bare
    return "ok", deps, bare


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


def realpath(path):
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def compare(interp, ldd_deps, ldd_bare, rldd_deps):
    """The differences between the two listings, as text."""
    rldd_deps = set(rldd_deps)
    ldd_deps = set(ldd_deps)
    diffs = []
    # ldd prints the loader with its own path and no name, rldd the DT_NEEDED
    # entry naming it and where the object resolves it; the interpreter of
    # the object is loaded whether or not an entry names it.  ldd runs the
    # object under its own loader whatever the PT_INTERP says, and prints
    # the interpreter as 'PT_INTERP => loader' when the two differ, where
    # rldd resolves the name to the interpreter itself.  An entry ldd also
    # lists under its own name is left for that comparison (the musl libc
    # resolves to the loader too), the others matching the file are the
    # loader line, or the root object a dependency refers back to, which
    # ldd prints the same way.
    loaders = [(path, {realpath(path)}) for path in ldd_bare]
    for name, path in list(ldd_deps):
        if name == interp and path != NOT_FOUND:
            ldd_deps.remove((name, path))
            loaders.append((path, {realpath(path), realpath(interp)}))
    for path, reals in loaders:
        matched = {d for d in rldd_deps if d[1] != NOT_FOUND and realpath(d[1]) in reals}
        if matched:
            rldd_deps -= {d for d in matched if d not in ldd_deps}
        elif interp and realpath(interp) in reals:
            pass
        elif interp is None and any(GLIBC_LOADER.match(n) for n, _ in rldd_deps):
            # For a library, the loader ldd prints is the one of its own
            # process; rldd resolves the loader the library names, which
            # may be another one it does not find (a GNU/Hurd library
            # naming ld.so.1, traced by the Linux ldd all the same).
            pass
        else:
            diffs.append("ldd loads %s, which rldd does not list" % path)
    if not loaders and not any(GLIBC_LOADER.match(n) for n, _ in ldd_deps):
        # The glibc trace lists the loader only when an object names it
        # before 2.37 (a library whose closure has no libc gets no loader
        # line there), where the later releases always list it, as rldd.
        rldd_deps = {d for d in rldd_deps if not GLIBC_LOADER.match(d[0])}
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
    info = elf_info(path)
    interp = info[1] if info else None
    if interp and not SYSTEM_LOADER.match(os.path.basename(interp)):
        return [("UNTRACED",)]

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

    rc, out, err = run(["ldd", path])
    if rc == -1 and err == "timeout":
        return [("PANIC", path, "ldd timeout")]
    ldd_status, ldd_deps, ldd_bare = parse_ldd(rc, out, err)
    if ldd_status not in ("ok", "static"):
        return [("UNTRACED",)]

    if rldd_status not in ("ok", "static"):
        return [("REFUSED", path, refused)]
    if ldd_status != rldd_status:
        listed = ", ".join(sorted(n for n, _ in (ldd_deps or rldd_deps)))
        return [("DIFF", path, "ldd: %s; rldd: %s (%s)" % (ldd_status, rldd_status, listed))]

    lines = [("COMPARED",)]
    diffs = compare(interp, ldd_deps, ldd_bare, rldd_deps)
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
    global SYSTEM_LOADER
    SYSTEM_LOADER = ldd_flavor()

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
