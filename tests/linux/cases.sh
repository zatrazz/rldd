#!/bin/bash
#
# Check the rldd ELF backend on small objects built with gcc for each case,
# against the ldd of the machine, or against the expected result where ldd
# can not tell (it fails the whole trace, or the case uses another loader).
#
# usage: tests/linux/cases.sh [-b RLDD] [-k] [CASE...]

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_YELLOW=$(printf '\033[33m')
    C_BOLD=$(printf '\033[1m')
    C_OFF=$(printf '\033[0m')
else
    C_RED= C_GREEN= C_YELLOW= C_BOLD= C_OFF=
fi

PASSED=0
FAILED=0
SKIPPED=0

pass() {
    PASSED=$((PASSED + 1))
    printf '  %sPASS%s  %s\n' "$C_GREEN" "$C_OFF" "$*"
}

fail() {
    FAILED=$((FAILED + 1))
    printf '  %sFAIL%s  %s\n' "$C_RED" "$C_OFF" "$*"
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    printf '  %sSKIP%s  %s\n' "$C_YELLOW" "$C_OFF" "$*"
}

die() {
    printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2
    exit 2
}

usage() {
    cat <<'EOF'
usage: tests/linux/cases.sh [options] [CASE...]

  -b, --rldd PATH       the rldd binary to check (default: a release build of
                        the checkout)
  -k, --keep            leave the objects built for the cases
  -l, --list            list the cases
  -h, --help            this message
EOF
}

CASES="rpath runpath tokens origin-literal lib platform empty-entry nodeflib
preload library-path slash-needed soname not-found-then-found symlink-root
wrong-class verify versions musl"

RLDD=
KEEP=false
SELECTED=

while [ $# -gt 0 ]; do
    case $1 in
    -b | --rldd)
        [ $# -ge 2 ] || die "$1 needs a path"
        RLDD=$2
        shift 2
        ;;
    -k | --keep) KEEP=true; shift ;;
    -l | --list) echo $CASES | tr ' ' '\n'; exit 0 ;;
    -h | --help) usage; exit 0 ;;
    -*) die "unknown option '$1' (try --help)" ;;
    *) SELECTED="$SELECTED $1"; shift ;;
    esac
done

[ "$(uname -s)" = Linux ] || die "this test only runs on Linux"
for tool in gcc ldd readelf objcopy realpath python3; do
    command -v $tool >/dev/null 2>&1 || die "$tool is not installed"
done
ldd --version 2>&1 | head -1 | grep -q -i -E 'glibc|gnu libc' ||
    die "the ldd of the machine is not the glibc one"

if [ -z "$RLDD" ]; then
    (cd "$REPO_ROOT" && cargo build --quiet -r) || die "cargo build failed"
    RLDD=${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/rldd
fi
[ -x "$RLDD" ] || die "$RLDD is not an executable"
RLDD=$(realpath "$RLDD")

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rldd-cases.XXXXXX") || die "could not create a temporary directory"
$KEEP || trap 'rm -rf "$WORK"' EXIT

# The loader of the objects gcc builds, and the values it expands $LIB and
# $PLATFORM to (glibc 2.33 and later print them).
echo 'int main(void){return 0;}' > "$WORK/probe.c"
gcc -o "$WORK/probe" "$WORK/probe.c" || die "gcc can not build a program"
LOADER=$(readelf -l "$WORK/probe" | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p')
DIAGNOSTICS=$("$LOADER" --list-diagnostics 2>/dev/null)
DST_LIB=$(printf '%s\n' "$DIAGNOSTICS" | sed -n 's/^dl_dst_lib="\(.*\)"$/\1/p')
PLATFORM=$(printf '%s\n' "$DIAGNOSTICS" | sed -n 's/^dl_platform="\(.*\)"$/\1/p')

# The objects of a case.
lib() { # lib OUTPUT SOURCE [GCC OPTION...]
    out=$1 src=$2
    shift 2
    mkdir -p "$(dirname "$out")"
    gcc -shared -fPIC -o "$out" "$src" "$@"
}

prog() { # prog OUTPUT SOURCE [GCC OPTION...]
    out=$1 src=$2
    shift 2
    mkdir -p "$(dirname "$out")"
    gcc -o "$out" "$src" "$@"
}

# The listings, one 'name<TAB>path' per line with the path resolved through
# realpath, sorted.  The vDSO and the loader lines are left out: ldd lists
# the loader only when some object names it before glibc 2.37, as a bare
# path, where rldd lists it always.
resolve() {
    while IFS='	' read -r name path; do
        case $name in
        linux-vdso* | linux-gate* | ld-linux* | ld.so.* | ld64.so.*) continue ;;
        esac
        [ "$path" = "not found" ] || path=$(realpath -m -- "$path")
        printf '%s\t%s\n' "$name" "$path"
    done | sort -u
}

ldd_listing() { # ldd_listing FILE [ENV=VALUE...]
    file=$1
    shift
    env "$@" ldd "$file" 2>/dev/null | awk '
        function base(p) { n = split(p, parts, "/"); return parts[n] }
        { sub(/^[ \t]+/, ""); sub(/ \(0x[0-9a-fA-F]+\)$/, "") }
        / => / { split($0, a, " => "); print base(a[1]) "\t" a[2]; next }
        /^statically linked$/ { next }
        { print base($0) "\t" $0 }' | resolve
}

rldd_listing() { # rldd_listing [OPTION...] FILE
    "$RLDD" -l "$@" 2>/dev/null | awk '
        function base(p) { n = split(p, parts, "/"); return parts[n] }
        { sub(/^[ \t]+/, "") }
        / => / { split($0, a, " => "); print base(a[1]) "\t" a[2] }' | resolve
}

# check_ldd NAME FILE [ENV=VALUE...] [-- RLDD_OPTION...]: the rldd -l listing
# of FILE with the options matches the ldd one with the environment.
check_ldd() {
    name=$1 file=$2
    shift 2
    envs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do
        envs+=("$1")
        shift
    done
    [ $# -gt 0 ] && shift
    want=$(ldd_listing "$file" "${envs[@]+"${envs[@]}"}")
    got=$(rldd_listing "$@" "$file")
    if [ -z "$want" ]; then
        fail "$name: ldd lists nothing for $file"
    elif [ "$want" = "$got" ]; then
        pass "$name"
    else
        fail "$name"
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^\([<>]\)/        \1/p' |
            sed 's/^        </        ldd: /; s/^        >/        rldd:/'
    fi
}

# check_output NAME PATTERN RLDD_ARGUMENT...: some line of the rldd output
# (standard output and error) matches the extended regular expression.
check_output() {
    name=$1 pattern=$2
    shift 2
    out=$("$RLDD" "$@" 2>&1)
    if printf '%s\n' "$out" | grep -q -E -- "$pattern"; then
        pass "$name"
    else
        fail "$name: no line matches '$pattern'"
        printf '%s\n' "$out" | head -20 | sed 's/^/        /'
    fi
}

# check_no_output NAME PATTERN RLDD_ARGUMENT...: no line of the rldd output
# matches the pattern.
check_no_output() {
    name=$1 pattern=$2
    shift 2
    out=$("$RLDD" "$@" 2>&1)
    if printf '%s\n' "$out" | grep -q -E -- "$pattern"; then
        fail "$name: a line matches '$pattern'"
        printf '%s\n' "$out" | head -20 | sed 's/^/        /'
    else
        pass "$name"
    fi
}

# The version and symbol diagnostics of a relocation processing, with the
# directories dropped (ldd prints the program as given, rldd its full path).
relocation_lines() {
    grep -E "version \`|no version information|undefined symbol" |
        sed -E 's#[^ ()	]*/##g' | sort -u
}

# check_relocs NAME OPTION FILE: the -d or -r diagnostics of rldd match the
# ldd ones.
check_relocs() {
    name=$1 option=$2 file=$3
    want=$(ldd "$option" "$file" 2>&1 | relocation_lines)
    got=$("$RLDD" "$option" "$file" 2>&1 | relocation_lines)
    if [ -z "$want" ]; then
        fail "$name: ldd reports nothing for $file"
    elif [ "$want" = "$got" ]; then
        pass "$name"
    else
        fail "$name"
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed -n 's/^\([<>]\)/        \1/p' |
            sed 's/^        </        ldd: /; s/^        >/        rldd:/'
    fi
}

cd "$WORK" || die "could not enter $WORK"
echo 'int foo(void) { return 1; }' > foo.c
echo 'int foo(void); int main(void) { return foo(); }' > main.c
echo 'int bar(void) { return 2; }' > bar.c
echo 'int bar(void); int foo(void) { return bar(); }' > foobar.c
echo 'int foo(void); int bar(void) { return foo(); }' > barfoo.c

# A minimal ELFCLASS32 i386 shared object, whatever the machine: a PT_LOAD
# and a PT_DYNAMIC with DT_SONAME, DT_STRTAB, DT_STRSZ and DT_NULL.
elf32() { # elf32 OUTPUT
    mkdir -p "$(dirname "$1")"
    python3 - "$1" <<'EOF'
import struct, sys
ehsz, phsz, nph = 52, 32, 2
strtab_off = ehsz + nph * phsz
strtab = b"\0lib32.so\0"
dyn_off = (strtab_off + len(strtab) + 3) & ~3
dyn = struct.pack("<iI", 14, 1) + struct.pack("<iI", 5, strtab_off)
dyn += struct.pack("<iI", 10, len(strtab)) + struct.pack("<iI", 0, 0)
size = dyn_off + len(dyn)
ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\0" * 7
eh = ident + struct.pack("<HHIIIIIHHHHHH", 3, 3, 1, 0, ehsz, 0, 0, ehsz, phsz, nph, 40, 0, 0)
load = struct.pack("<IIIIIIII", 1, 0, 0, 0, size, size, 5, 0x1000)
dynph = struct.pack("<IIIIIIII", 2, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 6, 4)
data = eh + load + dynph + strtab
data += b"\0" * (dyn_off - len(data)) + dyn
open(sys.argv[1], "wb").write(data)
EOF
}

# The DT_RPATH of the objects that loaded a library is searched for its own
# dependencies, up to the executable, but not the DT_RUNPATH.
case_rpath() {
    lib rpath/lib2/libbar.so bar.c
    lib rpath/lib/libfoo.so foobar.c -Lrpath/lib2 -lbar
    prog rpath/main main.c -Lrpath/lib -lfoo -Wl,-rpath-link,rpath/lib2 \
        -Wl,-rpath,'$ORIGIN/lib:$ORIGIN/lib2' -Wl,--disable-new-dtags
    check_ldd "DT_RPATH chain" rpath/main
}

case_runpath() {
    lib runpath/lib2/libbar.so bar.c
    lib runpath/lib/libfoo.so foobar.c -Lrunpath/lib2 -lbar
    prog runpath/main main.c -Lrunpath/lib -lfoo -Wl,-rpath-link,runpath/lib2 \
        -Wl,-rpath,'$ORIGIN/lib:$ORIGIN/lib2' -Wl,--enable-new-dtags
    check_ldd "DT_RUNPATH is not inherited" runpath/main
    # An object DT_RUNPATH hides its DT_RPATH, and the whole chain.
    lib runpath/lib3/libfoo.so foobar.c -Lrunpath/lib2 -lbar -Wl,-rpath,'$ORIGIN' \
        -Wl,--enable-new-dtags
    prog runpath/main2 main.c -Lrunpath/lib3 -lfoo -Wl,-rpath-link,runpath/lib2 \
        -Wl,-rpath,'$ORIGIN/lib3:$ORIGIN/lib2' -Wl,--disable-new-dtags
    check_ldd "DT_RUNPATH skips the DT_RPATH chain" runpath/main2
}

case_tokens() {
    lib tokens/lib/libfoo.so foo.c
    prog tokens/braces main.c -Ltokens/lib -lfoo -Wl,-rpath,'${ORIGIN}/lib' \
        -Wl,--disable-new-dtags
    check_ldd '${ORIGIN} on DT_RPATH' tokens/braces
    prog tokens/runpath main.c -Ltokens/lib -lfoo -Wl,-rpath,'$ORIGIN-x:$ORIGIN/lib' \
        -Wl,--enable-new-dtags
    check_ldd '$ORIGIN on DT_RUNPATH' tokens/runpath
}

# $ORIGINAL is not a token for glibc, but a directory relative to the
# current one.
case_origin_literal() {
    lib 'origin-literal/$ORIGINAL/libfoo.so' foo.c
    lib origin-literal/binAL/libfoo.so foo.c
    prog origin-literal/bin/main main.c -Lorigin-literal/binAL -lfoo -Wl,-rpath,'$ORIGINAL' \
        -Wl,--disable-new-dtags
    (cd origin-literal && check_ldd '$ORIGINAL is not $ORIGIN' bin/main)
}

case_lib() {
    if [ -z "$DST_LIB" ]; then
        skip '$LIB (the loader does not print its dl_dst_lib)'
        return
    fi
    lib "lib/$DST_LIB/libfoo.so" foo.c
    lib lib/lib64/libfoo.so foo.c
    lib lib/lib/libfoo.so foo.c
    prog lib/main main.c "-Llib/$DST_LIB" -lfoo -Wl,-rpath,'$ORIGIN/$LIB' -Wl,--disable-new-dtags
    check_ldd "\$LIB on DT_RPATH ($DST_LIB)" lib/main
}

case_platform() {
    if [ -z "$PLATFORM" ]; then
        skip '$PLATFORM (the loader does not print its dl_platform)'
        return
    fi
    lib "platform/$PLATFORM/libfoo.so" foo.c
    prog platform/main main.c "-Lplatform/$PLATFORM" -lfoo -Wl,-rpath,'$ORIGIN/${PLATFORM}' \
        -Wl,--disable-new-dtags
    check_ldd "\${PLATFORM} on DT_RPATH ($PLATFORM)" platform/main -- --platform "$PLATFORM"
}

# An empty entry is the current directory.
case_empty_entry() {
    lib empty-entry/cwd/libfoo.so foo.c
    prog empty-entry/rpath main.c -Lempty-entry/cwd -lfoo -Wl,-rpath,'/nonexistent:' \
        -Wl,--disable-new-dtags
    prog empty-entry/runpath main.c -Lempty-entry/cwd -lfoo -Wl,-rpath,':/nonexistent' \
        -Wl,--enable-new-dtags
    (
        cd empty-entry/cwd || exit
        check_ldd "empty DT_RPATH entry" ../rpath
        check_ldd "empty DT_RUNPATH entry" ../runpath
    )
}

# DF_1_NODEFLIB only restricts the search, not the objects already loaded.
case_nodeflib() {
    echo '#include <stdio.h>
int foo(void) { puts("x"); return 1; }' > nodeflib.c
    lib nodeflib/libc-user/libfoo.so nodeflib.c -Wl,-z,nodefaultlib
    prog nodeflib/main main.c -Lnodeflib/libc-user -lfoo -Wl,-rpath,'$ORIGIN/libc-user' \
        -Wl,--disable-new-dtags
    check_ldd "DF_1_NODEFLIB with an already loaded library" nodeflib/main
    lib nodeflib/lib/libbar.so bar.c
    lib nodeflib/lib/libfoo.so foobar.c -Lnodeflib/lib -lbar -Wl,-z,nodefaultlib
    prog nodeflib/main2 main.c -Lnodeflib/lib -lfoo -Wl,-rpath-link,nodeflib/lib \
        -Wl,-rpath,'$ORIGIN/lib' -Wl,--disable-new-dtags
    check_ldd "DF_1_NODEFLIB searching the inherited DT_RPATH" nodeflib/main2
    # A library only found on the default directories.
    lib nodeflib/libm-user/libfoo.so foo.c -Wl,--no-as-needed -lm -Wl,-z,nodefaultlib
    prog nodeflib/main3 main.c -Lnodeflib/libm-user -lfoo -Wl,-rpath,'$ORIGIN/libm-user' \
        -Wl,--disable-new-dtags
    check_ldd "DF_1_NODEFLIB skipping the default directories" nodeflib/main3
}

case_preload() {
    lib preload/libpre.so bar.c
    lib preload/lib/libfoo.so foo.c
    prog preload/main main.c -Lpreload/lib -lfoo -Wl,-rpath,'$ORIGIN/lib' -Wl,--disable-new-dtags
    check_ldd 'preload with $ORIGIN' preload/main 'LD_PRELOAD=$ORIGIN/libpre.so' \
        -- --preload '$ORIGIN/libpre.so'
    check_ldd 'preload with ${ORIGIN} and a bare name' preload/main \
        'LD_PRELOAD=${ORIGIN}/libpre.so libfoo.so' -- --preload '${ORIGIN}/libpre.so libfoo.so'
    if [ -n "$DST_LIB" ]; then
        lib "preload/$DST_LIB/libpre2.so" bar.c
        check_ldd 'preload with $LIB' preload/main 'LD_PRELOAD=$ORIGIN/$LIB/libpre2.so' \
            -- --preload '$ORIGIN/$LIB/libpre2.so'
    fi
}

case_library_path() {
    lib library-path/bin/llp/libfoo.so foo.c
    prog library-path/bin/main main.c -Llibrary-path/bin/llp -lfoo
    check_ldd 'library path with $ORIGIN' library-path/bin/main 'LD_LIBRARY_PATH=$ORIGIN/llp' \
        -- --library-path '$ORIGIN/llp'
    (
        cd library-path/bin || exit
        check_ldd "library path separated with ';'" ./main 'LD_LIBRARY_PATH=/nonexistent;llp' \
            -- --library-path '/nonexistent;llp'
        cd llp || exit
        check_ldd "empty library path entry" ../main 'LD_LIBRARY_PATH=/nonexistent:' \
            -- --library-path '/nonexistent:'
    )
}

# A DT_NEEDED entry naming a path, with a token.
case_slash_needed() {
    lib slash-needed/sub/libfoo.so foo.c -Wl,-soname,'$ORIGIN/sub/libfoo.so'
    prog slash-needed/main main.c slash-needed/sub/libfoo.so
    check_ldd "DT_NEEDED with a path" slash-needed/main
}

# A name matches the DT_SONAME of an object already loaded, without any
# search: the preloaded one here.
case_soname() {
    lib soname/lib/libfoo.so.1 foo.c -Wl,-soname,libfoo.so.1
    prog soname/main main.c soname/lib/libfoo.so.1
    check_ldd "soname of a preloaded object" soname/main "LD_PRELOAD=$WORK/soname/lib/libfoo.so.1" \
        -- --preload "$WORK/soname/lib/libfoo.so.1"
}

# A library a module fails to find is found by the next one, and reused by
# a later one which does not find it on its own.
case_not_found_then_found() {
    echo 'int x(void) { return 1; }' > x.c
    lib nf/d1/x/libX.so x.c
    for l in A B Z; do
        echo "int x(void); int f$l(void) { return x(); }" > "$l.c"
    done
    lib nf/d1/libA.so A.c -Lnf/d1/x -lX -Wl,-rpath,'$ORIGIN/empty' -Wl,--enable-new-dtags
    lib nf/d1/libB.so B.c -Lnf/d1/x -lX -Wl,-rpath,'$ORIGIN/x' -Wl,--enable-new-dtags
    lib nf/d1/libZ.so Z.c -Lnf/d1/x -lX -Wl,-rpath,'$ORIGIN/empty' -Wl,--enable-new-dtags
    echo 'int fA(void), fB(void), fZ(void); int main(void) { return fA() + fB() + fZ(); }' > nf.c
    prog nf/main nf.c -Lnf/d1 -lA -lB -lZ -Wl,-rpath-link,nf/d1/x -Wl,-rpath,'$ORIGIN/d1' \
        -Wl,--disable-new-dtags
    check_ldd "a library not found, then found" nf/main
    # Only libA does not find it.
    count=$("$RLDD" -a nf/main 2>&1 | grep -c 'libX\.so not found')
    if [ "$count" -eq 1 ]; then
        pass "a library not found, then found, is reused"
    else
        fail "a library not found, then found, is reused: $count not found entries"
    fi
}

# A shared library given through a symlink expands $ORIGIN from the symlink
# directory.
case_symlink_root() {
    lib symlink/real/lib/libfoo.so foo.c
    lib symlink/other/lib/libfoo.so foo.c
    lib symlink/real/libbar.so barfoo.c -Lsymlink/real/lib -lfoo -Wl,-rpath,'$ORIGIN/lib' \
        -Wl,--disable-new-dtags
    ln -s ../real/libbar.so symlink/other/libbar.so
    check_ldd "library input through a symlink" symlink/other/libbar.so
}

# A preload entry of another class is not loaded (ldd leaves it out).
case_wrong_class() {
    elf32 wrong-class/lib32.so
    prog wrong-class/main probe.c
    check_output "preload of another class" 'lib32\.so: wrong ELF class: ELFCLASS32' \
        -v --preload "$WORK/wrong-class/lib32.so" wrong-class/main
    check_no_output "preload of another class (not loaded)" 'lib32\.so \[preload\]' \
        --preload "$WORK/wrong-class/lib32.so" wrong-class/main
}

# A candidate file the glibc loader fails the load on, where ldd reports
# the error and lists nothing.
case_verify() {
    lib verify/good/libfoo.so foo.c
    verify_case() { # verify_case NAME DIR PATTERN
        prog "verify/$2/main" main.c -Lverify/good -lfoo \
            -Wl,-rpath,"\$ORIGIN/first:\$ORIGIN/../good" -Wl,--disable-new-dtags
        check_output "$1" "$3" -v "verify/$2/main"
    }
    mkdir -p verify/osabi/first
    cp verify/good/libfoo.so verify/osabi/first/
    printf '\011' | dd of=verify/osabi/first/libfoo.so bs=1 seek=7 conv=notrunc 2>/dev/null
    verify_case "a candidate of another OS ABI" osabi 'first/libfoo\.so: ELF file OS ABI invalid'
    mkdir -p verify/debug/first
    objcopy --only-keep-debug verify/good/libfoo.so verify/debug/first/libfoo.so
    verify_case "a separate debug info candidate" debug \
        'first/libfoo\.so: object file has no dynamic section'
    mkdir -p verify/script/first
    echo 'INPUT(libbar.so)' > verify/script/first/libfoo.so
    verify_case "a linker script candidate" script 'first/libfoo\.so: file too short'
    mkdir -p verify/exec/first
    gcc -no-pie -o verify/exec/first/libfoo.so main.c verify/good/libfoo.so
    verify_case "an executable candidate" exec 'first/libfoo\.so: cannot dynamically load executable'
    # A file of another class is skipped.
    elf32 verify/class/first/libfoo.so
    prog verify/class/main main.c -Lverify/good -lfoo \
        -Wl,-rpath,'$ORIGIN/first:$ORIGIN/../good' -Wl,--disable-new-dtags
    check_ldd "a candidate of another class is skipped" verify/class/main
}

case_versions() {
    # A versioned reference to an object without version definitions is
    # only a warning.
    echo 'FOO_1 { global: foo; local: *; };' > foo.map
    lib versions/v/libfoo.so foo.c -Wl,--version-script=foo.map -Wl,-soname,libfoo.so
    lib versions/nov/libfoo.so foo.c -Wl,-soname,libfoo.so
    prog versions/main main.c -Lversions/v -lfoo -Wl,-rpath,'$ORIGIN/nov' \
        -Wl,--disable-new-dtags
    check_relocs "no version information available" -r versions/main
    # An unversioned reference does not bind to a hidden only definition.
    cat > foohidden.c <<'EOF'
int foo_impl(void) { return 1; }
__asm__(".symver foo_impl,foo@V2");
int bar(void) { return 2; }
EOF
    echo 'V1 { global: bar; local: *; }; V2 { } V1;' > hidden.map
    lib versions/plain/libfoo.so foo.c -Wl,-soname,libfoo.so
    lib versions/hidden/libfoo.so foohidden.c -Wl,--version-script=hidden.map -Wl,-soname,libfoo.so
    prog versions/main2 main.c -Lversions/plain -lfoo -Wl,-rpath,'$ORIGIN/hidden' \
        -Wl,--disable-new-dtags
    check_relocs "unversioned reference to a hidden version" -d versions/main2
    # A version the provider does not define.
    echo 'FOO_1 { global: foo; local: *; }; FOO_2 { global: bar; } FOO_1;' > foo2.map
    cat foo.c bar.c > foobar2.c
    lib versions/v2/libfoo.so foobar2.c -Wl,--version-script=foo2.map -Wl,-soname,libfoo.so
    echo 'int foo(void), bar(void); int main(void) { return foo() + bar(); }' > main2.c
    prog versions/main3 main2.c -Lversions/v2 -lfoo -Wl,-rpath,'$ORIGIN/v' -Wl,--disable-new-dtags
    check_relocs "version not found" -r versions/main3
}

# The musl rules, with a program naming a musl loader of the machine
# architecture (installed or not, it is never run).
case_musl() {
    case $(uname -m) in
    x86_64 | aarch64 | riscv64 | s390x) arch=$(uname -m) ;;
    i?86) arch=i386 ;;
    *)
        skip "musl (no musl loader name for $(uname -m))"
        return
        ;;
    esac
    loader=$WORK/musl/m/lib/ld-musl-$arch.so.1
    lib musl/a/lib/libfoo.so foo.c
    lib musl/a/llp/libfoo.so foo.c
    prog musl/a/main main.c -Lmusl/a/lib -lfoo -Wl,-rpath,'$ORIGIN/lib' \
        -Wl,--disable-new-dtags "-Wl,--dynamic-linker=$loader"
    check_output "musl searches the library path first" 'llp/libfoo\.so \[LD_LIBRARY_PATH\]' \
        -p --library-path musl/a/llp musl/a/main
    check_output "musl does not search a rpath for a preload" '^\\_ libfoo\.so not found' \
        --preload libfoo.so musl/a/main
    # The DT_RUNPATH of the object that loaded a library is searched for its
    # own dependencies (libbaz loads libfoo, which needs libbar), where glibc
    # does not.
    lib musl/b/lib/sub/libbar.so bar.c
    lib musl/b/lib/libfoo.so foobar.c -Lmusl/b/lib/sub -lbar
    echo 'int foo(void); int baz(void) { return foo(); }' > bazfoo.c
    lib musl/b/lib/libbaz.so bazfoo.c -Lmusl/b/lib -lfoo -Wl,-rpath-link,musl/b/lib/sub \
        -Wl,-rpath,'$ORIGIN:$ORIGIN/sub' -Wl,--enable-new-dtags
    echo 'int baz(void); int main(void) { return baz(); }' > mb.c
    prog musl/b/main mb.c -Lmusl/b/lib -lbaz -Wl,-rpath-link,musl/b/lib:musl/b/lib/sub \
        -Wl,-rpath,'$ORIGIN/lib' -Wl,--disable-new-dtags "-Wl,--dynamic-linker=$loader"
    check_output "musl follows the DT_RUNPATH chain" 'libbar\.so \[rpath\]' musl/b/main
    prog musl/b/main-glibc mb.c -Lmusl/b/lib -lbaz -Wl,-rpath-link,musl/b/lib:musl/b/lib/sub \
        -Wl,-rpath,'$ORIGIN/lib' -Wl,--disable-new-dtags
    check_ldd "glibc does not follow the DT_RUNPATH chain" musl/b/main-glibc
    # The path file next to the loader: missing, empty, or listing
    # directories.
    mkdir -p musl/m/etc
    check_output "musl without path file" "default paths: /lib:/usr/local/lib:/usr/lib\$" \
        -v musl/a/main
    : > "musl/m/etc/ld-musl-$arch.path"
    check_output "musl with an empty path file" 'default paths: \(none\)$' -v musl/a/main
    printf '/opt/a\n/opt/b:' > "musl/m/etc/ld-musl-$arch.path"
    check_output "musl with a path file" 'default paths: /opt/a:/opt/b$' -v musl/a/main
}

for case_name in $CASES; do
    if [ -n "$SELECTED" ]; then
        case " $SELECTED " in
        *" $case_name "*) ;;
        *) continue ;;
        esac
    fi
    printf '%s==> %s%s\n' "$C_BOLD" "$case_name" "$C_OFF"
    case $case_name in
    rpath) case_rpath ;;
    runpath) case_runpath ;;
    tokens) case_tokens ;;
    origin-literal) case_origin_literal ;;
    lib) case_lib ;;
    platform) case_platform ;;
    empty-entry) case_empty_entry ;;
    nodeflib) case_nodeflib ;;
    preload) case_preload ;;
    library-path) case_library_path ;;
    slash-needed) case_slash_needed ;;
    soname) case_soname ;;
    not-found-then-found) case_not_found_then_found ;;
    symlink-root) case_symlink_root ;;
    wrong-class) case_wrong_class ;;
    verify) case_verify ;;
    versions) case_versions ;;
    musl) case_musl ;;
    esac
done

$KEEP && printf '\nthe objects are kept in %s\n' "$WORK"
printf '\n%s%s passed, %s failed, %s skipped%s\n' "$C_BOLD" "$PASSED" "$FAILED" "$SKIPPED" "$C_OFF"

[ "$FAILED" -eq 0 ]
