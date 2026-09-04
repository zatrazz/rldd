#!/usr/bin/env python3
"""Check the rldd Mach-O backend against 'dyld_info -dependents'.

The load paths an object records, and where dyld takes them (the shared
cache, the filesystem, the OS cryptex), can only be checked against a real
installation.  This runs rldd over the Mach-O objects of the system
directories and over the dyld cache images, and compares each dependency
list with the one dyld_info reports: the load paths in their recorded
order, their attributes, and whether the path rldd resolved to is the one
the recorded load path leads to.

The exit status is non-zero when any check fails.

usage: tests/macos/run.py [-r ROOT]... [-n N] [-j N]
"""

import argparse
import collections
import os
import platform
import random
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
from multiprocessing import Pool

CRYPTEX = "/System/Volumes/Preboot/Cryptexes/OS"
ATTRS = ("weak-link", "re-export", "upward", "delay-init")
# The slices rldd selects for the host: the first of its cpu type in the
# fat header order, and the only one of a thin object of another type.
HOST_SLICES = {"arm64": ("arm64", "arm64e", "arm64e.v1"), "x86_64": ("x86_64", "x86_64h")}
# Past this many walkers they only contend on the filesystem locks.
WALKERS = 8

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The report.

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
RED, GREEN, OFF = ("\033[31m", "\033[32m", "\033[0m") if COLOR else ("", "", "")
FAILED = 0


def write_pass(message):
    print("  %sPASS%s  %s" % (GREEN, OFF, message))


def write_fail(message):
    global FAILED
    FAILED += 1
    print("  %sFAIL%s  %s" % (RED, OFF, message))


def write_detail(message):
    print("        %s" % message)


def die(message):
    print("%serror:%s %s" % (RED, OFF, message), file=sys.stderr)
    sys.exit(2)


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


# The reference tool, on PATH or on the selected developer directory.

def find_tool(name):
    found = shutil.which(name)
    if found:
        return found
    rc, out, _ = run(["xcrun", "--find", name])
    return out.strip() if rc == 0 and out.strip() else None


HEADER = re.compile(r"^(\S.*) \[([A-Za-z0-9_.]+)\]:$")


def cache_images(dyld_info):
    """The install names dyld_info lists for the dyld cache, fewer than dyld
    resolves (see dyld_info_knows)."""
    _, out, _ = run([dyld_info, "-all_dyld_cache"])
    names = []
    for line in out.split("\n"):
        m = HEADER.match(line)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names


def parse_dyld_info(out):
    """{arch: {'deps': [(attrs, loadpath)], 'rpaths': [...], 'linked'}}, in
    the fat header order.  A slice dyld_info gives up on (old arm64e bind
    opcodes, a kernel) has no dependency section."""
    slices = collections.OrderedDict()
    cur = None
    state = None
    for line in out.split("\n"):
        m = HEADER.match(line)
        if m:
            cur = slices.setdefault(m.group(2), {"deps": [], "rpaths": [], "linked": False})
            state = None
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("-") and s.endswith(":"):
            state = s[1:-1]
            cur["linked"] |= state == "linked_dylibs"
            continue
        if not line.startswith("        ") or not s or s == "attributes     load path":
            continue
        if state == "linked_dylibs":
            attrs = set()
            while True:
                tok = s.split(None, 1)
                if len(tok) == 2 and tok[0] in ATTRS:
                    attrs.add(tok[0])
                    s = tok[1].lstrip()
                else:
                    break
            cur["deps"].append((frozenset(attrs), s))
        elif state == "rpaths":
            cur["rpaths"].append(s)
    return slices


# The rldd output: '\_ PATH [attrs] [mode]', or '\_ LOADPATH not found
# [attrs]' when the dependency was not resolved.

ENTRY = re.compile(r"^(.*?)((?: \[[^\[\]]*\])*)$")


def parse_rldd(out):
    deps = []
    for line in out.split("\n"):
        if not line.startswith("\\_ "):
            continue
        m = ENTRY.match(line[3:])
        body, attrs, mode = m.group(1), set(), ""
        for grp in re.findall(r"\[([^\[\]]*)\]", m.group(2)):
            if all(t in ATTRS for t in grp.split()):
                attrs.update(grp.split())
            else:
                mode = grp
        found = not body.endswith(" not found")
        if not found:
            body = body[: -len(" not found")]
        deps.append((body, frozenset(attrs), mode, found))
    return deps


# The objects to test.

MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
FAT_MAGICS = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")


def is_macho(path):
    """A Mach-O object or a fat file of them, but not a fat static archive
    (the SDK libraries), which is not a loadable object."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
            if head[:4] in MACHO_MAGICS:
                return True
            if head[:4] not in FAT_MAGICS or len(head) < 8:
                return False
            # A Java class file has the same magic and a large minor version.
            count = struct.unpack(">I", head[4:8])[0]
            if count == 0 or count >= 0x30:
                return False
            # cputype, cpusubtype, then the offset of the first slice.
            if head[:4] == b"\xca\xfe\xba\xbe":
                offset = struct.unpack(">I", f.read(12)[8:12])[0]
            else:
                offset = struct.unpack(">Q", f.read(16)[8:16])[0]
            f.seek(offset)
            return f.read(4) in MACHO_MAGICS
    except (OSError, struct.error):
        return False


def walk(task):
    """The Mach-O files of a directory, or below it, without following
    symlinks."""
    directory, recurse = task
    files = []
    for cur, dirs, names in os.walk(directory, followlinks=False):
        dirs[:] = [d for d in dirs if recurse and not os.path.islink(os.path.join(cur, d))]
        for name in names:
            path = os.path.join(cur, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and is_macho(path):
                files.append((path, st.st_dev, st.st_ino))
    return files


def find_objects(roots, jobs):
    """Every Mach-O file below the roots, a hard link counted once.  A root
    may also be a single file, so a report can be reproduced for one
    object.  Each subdirectory of a root is walked by its own worker, so a
    deep tree does not fall to a single one."""
    tasks = []
    files = []
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root):
            st = os.stat(root)
            files.append((root, st.st_dev, st.st_ino))
        elif os.path.isdir(root):
            tasks.append((root, False))
            with os.scandir(root) as entries:
                tasks.extend((e.path, True) for e in entries if e.is_dir(follow_symlinks=False))
    with Pool(min(jobs, WALKERS), initializer=quiet_interrupt) as pool:
        for part in pool.imap_unordered(walk, tasks):
            files.extend(part)
    seen = set()
    paths = []
    for path, dev, ino in sorted(files):
        if (dev, ino) not in seen:
            seen.add((dev, ino))
            paths.append(path)
    return paths


# Where a load path leads to, in the dyld order: the cache with the literal
# path, the filesystem, the OS cryptex, and for a recorded absolute path the
# realpath looked up in the cache again.

CACHE = set()


def in_cache(name):
    if name in CACHE:
        return True
    # Foo.framework/Foo answers for Foo.framework/Versions/A/Foo, and back.
    m = re.match(r"^(.*/([^/]+)\.framework)/Versions/[^/]+/\2$", name)
    if m and m.group(1) + "/" + m.group(2) in CACHE:
        return True
    m = re.match(r"^(.*/([^/]+)\.framework)/\2$", name)
    if m:
        prefix, leaf = m.group(1) + "/Versions/", "/" + m.group(2)
        return any(c.startswith(prefix) and c.endswith(leaf) for c in CACHE)
    return False


def realpath_leaf(path):
    head, leaf = os.path.split(path)
    return os.path.join(os.path.realpath(head), leaf)


def where(candidate, recorded):
    if in_cache(candidate):
        return "cache"
    if os.path.exists(candidate):
        return "disk"
    if os.path.exists(CRYPTEX + candidate):
        return "cryptex"
    if recorded and in_cache(realpath_leaf(candidate)):
        return "realpath"
    return None


def same_path(printed, expected):
    """rldd prints the cache path verbatim, a filesystem path canonicalized,
    and the realpath of a load path resolved through it."""
    for candidate in (expected, CRYPTEX + expected, realpath_leaf(expected)):
        if printed == candidate or os.path.realpath(printed) == os.path.realpath(candidate):
            return True
    return False


def expand(path, directory):
    for token in ("@executable_path", "@loader_path"):
        if path == token or path.startswith(token + "/"):
            return directory + path[len(token):]
    return path


def check_dependency(loadpath, dep, rpaths, directory, dyld_info):
    """(kind, detail) when the rldd entry is not what the recorded load path
    leads to, ('gap', path) for a cache image the listing lacks, or None."""
    path, _, mode, found = dep
    if loadpath.startswith("@rpath/"):
        rest = loadpath[len("@rpath/"):]
        # dyld does not add a second slash to an entry ending with one.
        candidates = [expand(r, directory) + ("" if r.endswith("/") else "/") + rest for r in rpaths]
        recorded = False
    elif loadpath.startswith("@"):
        candidates, recorded = [expand(loadpath, directory)], False
    elif loadpath.startswith("/"):
        candidates, recorded = [loadpath], True
    else:
        return None  # A relative load path, too rare to model.

    expected = next(((c, where(c, recorded)) for c in candidates if where(c, recorded)), None)
    if not found:
        if path != loadpath:
            return ("path", "%s printed as %s" % (loadpath, path))
        if expected:
            return ("path", "%s not found, but %s is on the %s" % (loadpath, expected[0], expected[1]))
        return None
    if expected is None:
        if mode == "dyld cache" and dyld_info_knows(dyld_info, path):
            return ("gap", path)
        return ("path", "%s resolved to %s, which no location provides" % (loadpath, path))
    candidate, location = expected
    if not same_path(path, candidate):
        return ("path", "%s resolved to %s, dyld finds %s on the %s" % (loadpath, path, candidate, location))
    if (mode == "dyld cache") != (location in ("cache", "realpath")):
        return ("path", "%s tagged [%s], but the image is on the %s" % (path, mode, location))
    if mode != "dyld cache" and not os.path.exists(path):
        return ("path", "%s does not exist" % path)
    return None


def dyld_info_knows(dyld_info, path):
    """Whether dyld_info resolves the path, which it does through the cache
    for the images its -all_dyld_cache listing lacks."""
    rc, out, _ = run([dyld_info, "-dependents", path])
    return rc == 0 and any(HEADER.match(line) for line in out.split("\n"))


# The sweep.  The workers only start the two tools, and the comparison is
# done in the main process as the outputs arrive.

def quiet_interrupt():
    """On Ctrl-C a worker just goes away, leaving the report to the parent
    (a handler rather than SIG_IGN, which the tools would inherit)."""
    signal.signal(signal.SIGINT, lambda *_: os._exit(130))


def run_tools(item):
    path, rldd, dyld_info = item
    return path, run([rldd, path]), run([dyld_info, "-dependents", path])


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-r", "--root", action="append", metavar="DIR",
                        help="sweep this directory, or single file, may be repeated"
                        " (default: /bin, /sbin and /usr, plus the dyld cache images)")
    parser.add_argument("-n", "--sample", type=int, default=200, metavar="N",
                        help="sweep a random sample of N objects, 0 meaning all (default: 200)")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4, metavar="N",
                        help="parallel workers (default: the processor count)")
    args = parser.parse_args()

    if platform.system() != "Darwin":
        die("this test only runs on macOS")
    dyld_info = find_tool("dyld_info")
    if not dyld_info:
        die("dyld_info was not found (install the Xcode Command Line Tools)")

    # The binary under test, built only when it is not there yet, so a run
    # right after 'cargo build --release' tests what was just built.
    rldd = os.path.join(REPO_ROOT, "target", "release", "rldd")
    if not os.access(rldd, os.X_OK):
        if subprocess.run(["cargo", "build", "--release"], cwd=REPO_ROOT).returncode != 0:
            die("cargo build failed")

    CACHE.update(cache_images(dyld_info))
    roots = args.root or ["/bin", "/sbin", "/usr"]
    objects = find_objects(roots, args.jobs) + sorted(CACHE)
    if args.sample and len(objects) > args.sample:
        objects = sorted(random.sample(objects, args.sample))
    if not objects:
        die("no object below %s" % ", ".join(roots))

    host = HOST_SLICES.get(platform.machine(), ())
    lists = []
    paths = []
    panics = []
    gaps = collections.Counter()
    not_found = collections.Counter()
    compared = unreadable = 0
    done = 0

    print("Sweeping %d objects with %s" % (len(objects), dyld_info))
    with Pool(args.jobs, initializer=quiet_interrupt) as pool:
        items = [(path, rldd, dyld_info) for path in objects]
        for path, (rc, out, err), (drc, dout, _) in pool.imap_unordered(run_tools, items, chunksize=4):
            done += 1
            if "panicked at" in err or rc == -1:
                panics.append("%s: %s" % (path, err.strip().split("\n")[-1][:200] if rc != -1 else "timeout"))
                continue
            slices = collections.OrderedDict(
                (name, s) for name, s in parse_dyld_info(dout).items() if s["linked"])
            name = next((n for n in slices if n in host), next(iter(slices), None))
            if name is None:
                unreadable += 1  # A relocatable object, a kernel, a Metal library.
                continue
            ref = slices[name]
            if rc != 0:
                if ref["deps"]:
                    lists.append("%s: rldd refused it: %s" % (path, (err or out).strip().split("\n")[0][:200]))
                else:
                    unreadable += 1
                continue
            compared += 1

            deps = parse_rldd(out)
            if len(deps) != len(ref["deps"]):
                lists.append("%s: rldd lists %d dependencies, dyld_info %d" % (path, len(deps), len(ref["deps"])))
                continue
            directory = os.path.dirname(path)
            for dep, (attrs, loadpath) in zip(deps, ref["deps"]):
                if dep[1] != attrs:
                    lists.append("%s: %s: rldd [%s], dyld_info [%s]" % (
                        path, loadpath, " ".join(sorted(dep[1])), " ".join(sorted(attrs))))
                if not dep[3]:
                    not_found[dep[0]] += 1
                result = check_dependency(loadpath, dep, ref["rpaths"], directory, dyld_info)
                if result and result[0] == "gap":
                    gaps[result[1]] += 1
                elif result:
                    paths.append("%s: %s" % (path, result[1]))

    # The verdict.

    print("%d compared, %d not readable by dyld_info or without dependencies" % (compared, unreadable))
    for failures, good, bad in (
        (lists, "the dependency lists match dyld_info on all %d objects" % compared,
         "objects list other dependencies or attributes than dyld_info"),
        (paths, "every dependency resolves where its recorded load path leads",
         "dependencies resolve elsewhere than their recorded load path leads"),
        (panics, "no object made rldd panic", "objects made rldd panic"),
    ):
        if not failures:
            write_pass(good)
        else:
            write_fail("%d %s" % (len(failures), bad))
            for failure in failures[:10]:
                write_detail(failure)

    # The images resolved through the cache that its listing lacks, and the
    # dependencies checked to be missing from every location, only listed.
    if gaps:
        write_detail("%d dependencies resolve through the dyld cache although -all_dyld_cache does not list them:"
                     % sum(gaps.values()))
        for dep, count in gaps.most_common(5):
            write_detail("    %d  %s" % (count, dep))
    if not_found:
        write_detail("%d unresolved dependencies, none provided by any location, the most common being:"
                     % sum(not_found.values()))
        for dep, count in not_found.most_common(5):
            write_detail("    %d  %s" % (count, dep))
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
