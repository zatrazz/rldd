#!/usr/bin/env python3
"""Check the rldd Mach-O backend against 'dyld_info -dependents'.

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
# Past this many walkers they only contend on the filesystem locks.
WALKERS = 8

CPU_ARM64, CPU_X86_64 = 0x0100000C, 0x01000007
MH_EXECUTE, MH_DYLIB = 2, 6
PLATFORM_MACOS, PLATFORM_MACCATALYST = 1, 6
# The slice architectures, by cpu type and subtype, and the names dyld_info
# prints for them.
ARM64E, ARM64E_V1, ARM64, ARM64_V8 = (CPU_ARM64, 0x80000002), (CPU_ARM64, 0x81000002), (CPU_ARM64, 0), (CPU_ARM64, 1)
X86_64, X86_64H = (CPU_X86_64, 3), (CPU_X86_64, 8)
NAMES = {ARM64E: "arm64e", ARM64E_V1: "arm64e.v1", ARM64: "arm64", ARM64_V8: "arm64",
         (CPU_ARM64, 2): "arm64e.old", X86_64: "x86_64", X86_64H: "x86_64h"}

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    """(status, stdout, stderr), the status being negative when a signal
    killed the command, and None when it timed out."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timeout"


def crash(rc, err):
    """Why rldd crashed (a panic, a signal such as the abort on a stack
    overflow, or a timeout), or None."""
    if rc is None:
        return "timeout"
    if "panicked at" in err:
        return err.strip().split("\n")[-1][:200]
    if rc < 0:
        try:
            name = signal.Signals(-rc).name
        except ValueError:
            name = "signal %d" % -rc
        return "killed by %s: %s" % (name, err.strip().split("\n")[-1][:200])
    return None


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


# The platform of the LC_VERSION_MIN_* load commands.
VERSION_MIN = {0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}


def image(f, offset):
    """(cputype, cpusubtype, filetype, platforms) of the little endian
    Mach-O image at OFFSET, the platforms in the load command order, or
    None."""
    f.seek(offset)
    head = f.read(32)
    if head[:4] not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return None
    cputype, subtype, filetype, ncmds, sizeofcmds = struct.unpack("<5I", head[4:24])
    f.seek(offset + (32 if head[0] == 0xCF else 28))
    cmds = f.read(sizeofcmds)
    platforms = []
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(cmds):
            break
        cmd, size = struct.unpack("<2I", cmds[pos:pos + 8])
        if cmd == 0x32 and pos + 12 <= len(cmds):
            platforms.append(struct.unpack("<I", cmds[pos + 8:pos + 12])[0])
        elif cmd in VERSION_MIN:
            platforms.append(VERSION_MIN[cmd])
        if size < 8:
            break
        pos += size
    return cputype, subtype, filetype, platforms


def file_slices(path):
    """[((cputype, cpusubtype), image)] of a Mach-O file: its only image, or
    each slice of a fat one with the architecture its header records."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
            if head[:4] not in FAT_MAGICS:
                img = image(f, 0)
                return [(tuple(img[:2]), img)] if img else []
            count = struct.unpack(">I", head[4:8])[0]
            if count == 0 or count >= 0x30:
                return []
            fat64 = head[:4] == b"\xca\xfe\xba\xbf"
            entries = []
            for _ in range(count):
                if fat64:
                    cputype, subtype, offset = struct.unpack(">IIQ", f.read(32)[:16])
                else:
                    cputype, subtype, offset = struct.unpack(">3I", f.read(20)[:12])
                    # libtool leaves out the arm64e ABI version bits.
                    if (cputype, subtype) == (CPU_ARM64, 2):
                        subtype = ARM64E[1]
                entries.append(((cputype, subtype), offset))
            return [(arch, image(f, offset)) for arch, offset in entries]
    except (OSError, struct.error):
        return []


def same_arch(a, b):
    """The dyld Architecture equality, where the subtype capability bits
    are ignored, but for the arm64e ABI version."""
    if a[0] != b[0]:
        return False
    if a[0] == CPU_ARM64:
        return a[1] == b[1]
    return (a[1] & 0xFFFFFF) == (b[1] & 0xFFFFFF)


def built_for_macos(cputype, platforms):
    """Whether dyld takes an image as built for macOS: its first platform
    is macOS, or it is a zippered one, and an image without any platform is
    a macOS one on Intel and arm64."""
    if not platforms:
        return cputype in (CPU_X86_64, 7, CPU_ARM64)
    return platforms[0] == PLATFORM_MACOS or (
        platforms[0] == PLATFORM_MACCATALYST and PLATFORM_MACOS in platforms)


HASWELL = False


class Process:
    """The architectures and platform of the process running an input,
    which rldd checks each dependency candidate against (Arch::process in
    src/macho/arch.rs, and loads_platform in src/macho.rs)."""

    def __init__(self, arch, filetype, platforms):
        cputype, subtype = arch
        self.cputype = cputype
        if cputype == CPU_ARM64:
            keys_on = filetype == MH_EXECUTE and subtype & 0xFFFFFF == 2
            self.graded = [ARM64E] if keys_on else [ARM64E, ARM64E_V1, ARM64, ARM64_V8]
        elif cputype == CPU_X86_64:
            self.graded = [X86_64H, X86_64] if subtype & 0xFFFFFF == 8 or HASWELL else [X86_64]
        else:
            self.graded = None
        self.macos = (filetype == MH_EXECUTE and built_for_macos(cputype, platforms)
                      and PLATFORM_MACCATALYST not in platforms)

    def loads(self, path):
        """Whether the process loads the file as a dependency: a dylib with
        a slice of its architecture, built for macOS in a macOS process."""
        slices = file_slices(path)
        if self.graded is None:
            best = next((s for s in slices if s[0][0] == self.cputype), None)
        else:
            best = next((s for g in self.graded for s in slices if same_arch(s[0], g)), None)
        if best is None or best[1] is None:
            return False
        cputype, subtype, filetype, platforms = best[1]
        if self.graded is not None and not any(same_arch((cputype, subtype), g) for g in self.graded):
            return False
        return filetype == MH_DYLIB and (not self.macos or built_for_macos(cputype, platforms))


def launch_archs(host):
    """The slices the host launches, best first (dyld
    GradedArchitectures::currentLaunch)."""
    if host == "arm64":
        return [ARM64E, ARM64, X86_64]
    if host == "x86_64":
        return [X86_64H, X86_64] if HASWELL else [X86_64]
    return []


def input_slice(path, host, names):
    """The dyld_info name of the slice rldd inspects and the process it
    runs, the way Arch::input_slice selects it: the one the host launches,
    then one of those architectures with other subtype bits, then another
    subtype of their cpu type, and at last the first one.  An input that is
    only in the dyld cache is a dylib of the host flavor."""
    slices = [s for s in file_slices(path) if s[1]]
    if not slices:
        for arch in launch_archs(host):
            if NAMES.get(arch) in names:
                return NAMES[arch], Process(arch, MH_DYLIB, [])
        return next(iter(names), None), None
    chosen = slices[0]
    for match in (same_arch,
                  lambda a, b: a[0] == b[0] and a[1] & 0xFFFFFF == b[1] & 0xFFFFFF,
                  lambda a, b: a[0] == b[0]):
        found = next((s for arch in launch_archs(host) for s in slices if match(s[0], arch)), None)
        if found:
            chosen = found
            break
    cputype, subtype, filetype, platforms = chosen[1]
    process = Process((cputype, subtype), filetype, platforms)
    # A thin file has a single slice listed, whatever its name.
    if len(slices) == 1:
        return next(iter(names), None), process
    arch = chosen[0]
    if arch[0] != CPU_ARM64:
        arch = (arch[0], arch[1] & 0xFFFFFF)
    return NAMES.get(arch), process


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
# realpath looked up in the cache again.  A file the process does not load
# (another architecture, not a dylib, or another platform) is passed over.

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


def where(candidate, recorded, process):
    loads = lambda path: os.path.exists(path) and (process is None or process.loads(path))
    if in_cache(candidate):
        return "cache"
    if loads(candidate):
        return "disk"
    if loads(CRYPTEX + candidate):
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
    """The leading @executable_path or @loader_path expanded against the
    input directory, dropping the leading ../ components of an
    @executable_path one against it like dyld does (expand_at_path in
    src/macho.rs)."""
    for token in ("@executable_path", "@loader_path"):
        if path == token or path.startswith(token + "/"):
            tail = path[len(token):]
            if token == "@executable_path":
                if not tail:
                    return directory + "/"
                while tail.startswith("/..") and directory.rfind("/") > 0:
                    directory, tail = directory[:directory.rfind("/")], tail[3:]
            return directory + tail
    return path


def default_fallbacks(loadpath):
    """The default fallback candidates dyld searches for a dependency of a
    pre-2022 image when no other candidate provides it (fallback_directories
    in src/macho.rs): the framework partial path below /Library/Frameworks and
    /System/Library/Frameworks, or the leaf name below /usr/local/lib and
    /usr/lib."""
    leaf = loadpath.rsplit("/", 1)[-1]
    idx = loadpath.rfind(".framework/")
    start = loadpath.rfind("/", 0, idx) + 1 if idx >= 0 else 0
    if idx >= 0 and loadpath[start:idx] == leaf:
        return ["%s/%s" % (d, loadpath[start:]) for d in ("/Library/Frameworks", "/System/Library/Frameworks")]
    return ["%s/%s" % (d, leaf) for d in ("/usr/local/lib", "/usr/lib")]


def check_dependency(loadpath, dep, rpaths, directory, dyld_info, process):
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

    expected = next(((c, w) for c in candidates for w in [where(c, recorded, process)] if w), None)
    if not found:
        if path != loadpath:
            return ("path", "%s printed as %s" % (loadpath, path))
        if expected:
            return ("path", "%s not found, but %s is on the %s" % (loadpath, expected[0], expected[1]))
        return None
    if expected is None:
        if mode == "dyld cache" and dyld_info_knows(dyld_info, path):
            return ("gap", path)
        if mode == "system default paths" and any(same_path(path, c) for c in default_fallbacks(loadpath)):
            return None
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


def quiet_interrupt():
    """On Ctrl-C a worker just goes away, leaving the report to the parent
    (a handler rather than SIG_IGN, which the tools would inherit)."""
    signal.signal(signal.SIGINT, lambda *_: os._exit(130))


# rldd is invoked with -a, since an object may record the same dylib twice
# (a load and a re-export), which the default output lists once.
def run_tools(item):
    path, rldd, dyld_info = item
    return path, run([rldd, "-a", path]), run([dyld_info, "-dependents", path])


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

    # Always build, which is a no-op when the binary is up to date, so the
    # sweep never runs a stale one.
    rldd = os.path.join(REPO_ROOT, "target", "release", "rldd")
    if subprocess.run(["cargo", "build", "--release"], cwd=REPO_ROOT).returncode != 0:
        die("cargo build failed")

    # dyld prefers the x86_64h slices on a Haswell or newer Intel host.
    global HASWELL
    host = platform.machine()
    HASWELL = host == "x86_64" and run(["sysctl", "-n", "hw.cpusubtype"])[1].strip() == "8"

    CACHE.update(cache_images(dyld_info))
    roots = args.root or ["/bin", "/sbin", "/usr"]
    objects = find_objects(roots, args.jobs) + sorted(CACHE)
    if args.sample and len(objects) > args.sample:
        objects = sorted(random.sample(objects, args.sample))
    if not objects:
        die("no object below %s" % ", ".join(roots))

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
            reason = crash(rc, err)
            if reason:
                panics.append("%s: %s" % (path, reason))
                continue
            slices = collections.OrderedDict(
                (name, s) for name, s in parse_dyld_info(dout).items() if s["linked"])
            name, process = input_slice(path, host, slices)
            if name not in slices:
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
                result = check_dependency(loadpath, dep, ref["rpaths"], directory, dyld_info, process)
                if result and result[0] == "gap":
                    gaps[result[1]] += 1
                elif result:
                    paths.append("%s: %s" % (path, result[1]))

    print("%d compared, %d not readable by dyld_info or without dependencies" % (compared, unreadable))
    for failures, good, bad in (
        (lists, "the dependency lists match dyld_info on all %d objects" % compared,
         "objects list other dependencies or attributes than dyld_info"),
        (paths, "every dependency resolves where its recorded load path leads",
         "dependencies resolve elsewhere than their recorded load path leads"),
        (panics, "no object made rldd crash",
         "objects made rldd crash (a panic, a signal, or a timeout)"),
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
