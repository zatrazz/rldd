#!/bin/sh
#
# Check the rldd ELF backend against the glibc ldd, on the local machine or
# on hosts reached through ssh, for which rldd is cross built and copied over.
#
# usage: tests/linux/run.sh [-H HOST]... [-r ROOT]... [-n N] [-j N] [-k]

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

# Relative to the home directory of the remote user, where ssh starts.
REMOTE_DIR=rldd-tests

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_BOLD=$(printf '\033[1m')
    C_OFF=$(printf '\033[0m')
else
    C_RED= C_GREEN= C_BOLD= C_OFF=
fi

PASSED=0
FAILED=0

pass() {
    PASSED=$((PASSED + 1))
    printf '  %sPASS%s  %s\n' "$C_GREEN" "$C_OFF" "$*"
}

fail() {
    FAILED=$((FAILED + 1))
    printf '  %sFAIL%s  %s\n' "$C_RED" "$C_OFF" "$*"
}

info() {
    printf '        %s\n' "$*"
}

die() {
    printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2
    exit 2
}

usage() {
    cat <<'EOF'
usage: tests/linux/run.sh [options]

  -H, --host HOST       test this ssh destination (may be repeated; the
                        default is the local machine, also named 'local')
  -r, --root DIR        sweep this directory, or single file (may be repeated;
                        the default is /bin, /sbin, /lib, /lib64 and /usr)
  -n, --sample N        sweep a random sample of N objects, 0 meaning all
                        (default: 200)
  -j, --jobs N          parallel workers (default: the processor count of
                        the machine under test)
  -k, --keep            leave the files copied to the hosts
  -h, --help            this message
EOF
}

HOSTS=
ROOTS=
SAMPLE=200
JOBS=
KEEP=false

while [ $# -gt 0 ]; do
    case $1 in
    -H | --host)
        [ $# -ge 2 ] || die "$1 needs a host"
        HOSTS="$HOSTS $2"
        shift 2
        ;;
    -r | --root)
        [ $# -ge 2 ] || die "$1 needs a directory"
        ROOTS="$ROOTS $2"
        shift 2
        ;;
    -n | --sample)
        [ $# -ge 2 ] || die "$1 needs a count"
        SAMPLE=$2
        shift 2
        ;;
    -j | --jobs)
        [ $# -ge 2 ] || die "$1 needs a count"
        JOBS=$2
        shift 2
        ;;
    -k | --keep) KEEP=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[ -n "$HOSTS" ] || HOSTS=local
[ -n "$ROOTS" ] || ROOTS="/bin /sbin /lib /lib64 /usr"

[ "$(uname -s)" = Linux ] || die "this test only runs on Linux"

host_sh() {
    host=$1
    shift
    if [ "$host" = local ]; then
        sh -c "$*"
    else
        ssh -o BatchMode=yes "$host" "$*" </dev/null
    fi
}

host_libc() {
    host_sh "$1" "ldd --version 2>&1 | head -2 | grep -E '^(ldd|musl|Version)' | tr '\\n' ' ' | sed 's/ \$//'"
}

rust_targets() {
    case $1 in
    x86_64) echo "x86_64-unknown-linux-musl x86_64-unknown-linux-gnu" ;;
    i?86) echo "i686-unknown-linux-musl i686-unknown-linux-gnu" ;;
    aarch64) echo "aarch64-unknown-linux-musl aarch64-unknown-linux-gnu" ;;
    armv[6-8]l) echo "armv7-unknown-linux-musleabihf armv7-unknown-linux-gnueabihf" ;;
    loongarch64) echo "loongarch64-unknown-linux-musl loongarch64-unknown-linux-gnu" ;;
    ppc64le) echo "powerpc64le-unknown-linux-musl powerpc64le-unknown-linux-gnu" ;;
    ppc64) echo "powerpc64-unknown-linux-musl powerpc64-unknown-linux-gnu" ;;
    ppc) echo "powerpc-unknown-linux-gnu" ;;
    riscv64) echo "riscv64gc-unknown-linux-musl riscv64gc-unknown-linux-gnu" ;;
    s390x) echo "s390x-unknown-linux-musl s390x-unknown-linux-gnu" ;;
    sparc64) echo "sparc64-unknown-linux-gnu" ;;
    *) return 1 ;;
    esac
}

pick_target() {
    installed=$(rustup target list --installed 2>/dev/null)
    for candidate in $(rust_targets "$1"); do
        if printf '%s\n' "$installed" | grep -qx "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Build rldd for a target.
build_target() {
    target=$1
    var=$(printf 'CARGO_TARGET_%s' "$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')")
    eval "linker=\${${var}_LINKER:-}"
    if [ -z "$linker" ]; then
        case $target in
        *-musl*)
            export "${var}_LINKER=rust-lld"
            export "${var}_RUSTFLAGS=-C linker-flavor=ld.lld -C link-self-contained=yes -C target-feature=+crt-static"
            ;;
        *)
            arch=${target%%-*}
            case $arch in
            armv7) arch=arm ;;
            riscv64gc) arch=riscv64 ;;
            esac
            linker="$arch-linux-${target##*-}-gcc"
            if command -v "$linker" >/dev/null 2>&1; then
                export "${var}_LINKER=$linker"
            elif [ "$arch" != "$(uname -m)" ]; then
                fail "no cross compiler for $target ($linker is not on PATH)"
                return 1
            fi
            ;;
        esac
    fi
    if ! (cd "$REPO_ROOT" && cargo build --quiet -r --target "$target"); then
        fail "cargo build -r --target $target failed"
        return 1
    fi
}

# Resolve every object below the roots with rldd and ldd, on the host.  The
# sweep prints its report on stdout, which comes back through ssh.
check_sweep() {
    host=$1
    rldd=$2
    sweep=$3
    jobs=${JOBS:-$(host_sh "$host" 'nproc 2>/dev/null || echo 4')}

    report=$(host_sh "$host" "python3 $sweep --rldd $rldd --sample $SAMPLE --jobs $jobs $ROOTS")

    files=$(printf '%s\n' "$report" | sed -n "s/^FILES\t//p")
    compared=$(printf '%s\n' "$report" | sed -n "s/^COMPARED\t//p")
    untraced=$(printf '%s\n' "$report" | sed -n "s/^UNTRACED\t//p")
    unreadable=$(printf '%s\n' "$report" | sed -n "s/^UNREADABLE\t//p")
    unreadable_dirs=$(printf '%s\n' "$report" | sed -n "s/^UNREADABLE-DIRS\t//p")

    # An empty report means the sweep did not run, not a clean run.
    if [ -z "${files:-}" ] || [ "$files" -eq 0 ]; then
        fail "$host: nothing was inspected"
        printf '%s\n' "$report" | sed 's/^/        /' | head -5
        return 1
    fi
    info "$files objects: $compared compared, $untraced ldd traces nothing for, $unreadable not readable"
    [ "${unreadable_dirs:-0}" -eq 0 ] || info "$unreadable_dirs directories could not be entered (run as root to sweep them)"

    for kind in DIFF REFUSED PANIC; do
        failures=$(printf '%s\n' "$report" | grep "^$kind	" || true)
        n=$(printf '%s' "$failures" | grep -c . || true)
        case $kind:$n in
        DIFF:0) pass "the dependency lists match ldd on all $compared objects" ;;
        DIFF:*) fail "$n objects list other dependencies or paths than ldd" ;;
        REFUSED:0) pass "every object ldd traces is read" ;;
        REFUSED:*) fail "$n objects ldd traces were refused by rldd" ;;
        PANIC:0) pass "no object made rldd panic" ;;
        PANIC:*) fail "$n objects made rldd panic" ;;
        esac
        printf '%s\n' "$failures" | grep . | head -10 |
            awk -F'\t' '{ printf "        %s\n            %s\n", $2, $3 }'
    done

    # Both tools agree the dependency is missing (a plugin whose host program
    # is not installed), only listed.
    unresolved=$(printf '%s\n' "$report" | grep '^UNRESOLVED	' || true)
    if [ -n "$unresolved" ]; then
        info "$(printf '%s\n' "$unresolved" | wc -l | tr -d ' ') dependencies both tools report as not found, the most common being:"
        printf '%s\n' "$unresolved" | awk -F'\t' '{ print $3 }' | sort | uniq -c | sort -rn | head -5 |
            awk '{ printf "            %s  %s\n", $1, $2 }'
    fi
}

run_host() {
    host=$1

    if [ "$host" = local ]; then
        printf '\n%s==> local  %s  %s%s\n' "$C_BOLD" "$(uname -m)" "$(host_libc local)" "$C_OFF"
        rldd=$REPO_ROOT/target/release/rldd
        if [ ! -x "$rldd" ] && ! (cd "$REPO_ROOT" && cargo build --quiet -r); then
            fail "cargo build failed"
            return 1
        fi
        # A copy, so a build replacing the binary during the sweep (a checkout
        # shared over NFS, built from another machine) does not pull it away.
        dir=$(mktemp -d "${TMPDIR:-/tmp}/rldd-tests.XXXXXX") || {
            fail "could not create a temporary directory"
            return 1
        }
        cp "$rldd" "$dir/rldd" && cp "$SCRIPT_DIR/sweep.py" "$dir/sweep.py"
        if [ -z "$("$dir/rldd" -l /bin/sh 2>/dev/null)" ]; then
            fail "$rldd does not run here (built on another machine?)"
            rm -rf "$dir"
            return 1
        fi
        check_sweep local "$dir/rldd" "$dir/sweep.py"
        $KEEP || rm -rf "$dir"
        return
    fi

    arch=$(host_sh "$host" uname -m)
    if [ -z "$arch" ]; then
        fail "$host: could not reach it"
        return 1
    fi
    libc=$(host_libc "$host")
    if [ -z "$libc" ]; then
        fail "$host: ldd is not installed"
        return 1
    fi
    if ! target=$(pick_target "$arch"); then
        fail "$host: no Rust target installed for $arch (rustup target add $(rust_targets "$arch" | cut -d' ' -f1))"
        return 1
    fi

    printf '\n%s==> %s  %s  %s  (%s)%s\n' "$C_BOLD" "$host" "$arch" "$libc" "$target" "$C_OFF"

    build_target "$target" || return 1
    rldd=$REPO_ROOT/target/$target/release/rldd

    host_sh "$host" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
    if ! scp -q -o BatchMode=yes "$rldd" "$SCRIPT_DIR/sweep.py" "$host:$REMOTE_DIR/" </dev/null; then
        fail "$host: could not copy the files to $REMOTE_DIR"
        return 1
    fi
    host_sh "$host" "chmod 755 $REMOTE_DIR/rldd"

    # A binary built for the wrong ABI would otherwise show up as a
    # suspiciously clean run.
    if [ -z "$(host_sh "$host" "$REMOTE_DIR/rldd -l /bin/sh 2>/dev/null")" ]; then
        fail "$host: the rldd copied to $REMOTE_DIR does not run there"
        return 1
    fi

    check_sweep "$host" "$REMOTE_DIR/rldd" "$REMOTE_DIR/sweep.py"

    $KEEP || host_sh "$host" "rm -rf $REMOTE_DIR"
}

for host in $HOSTS; do
    run_host "$host" || true
done

printf '\n%s%s passed, %s failed%s\n' "$C_BOLD" "$PASSED" "$FAILED" "$C_OFF"

[ "$FAILED" -eq 0 ]
