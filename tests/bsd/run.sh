#!/bin/sh
#
# Check the rldd ELF backend against the ldd of FreeBSD, OpenBSD and NetBSD,
# on the local machine or on hosts reached through ssh, where the working
# tree is copied and rldd built.
#
# usage: tests/bsd/run.sh [-H HOST]... [-r ROOT]... [-n N] [-j N] [-k]

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

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
usage: tests/bsd/run.sh [options]

  -H, --host HOST       test this ssh destination (may be repeated)
  -r, --root DIR        sweep this directory, or single file (may be repeated.
                        The default is /bin, /sbin, /lib, /libexec and /usr)
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
[ -n "$ROOTS" ] || ROOTS="/bin /sbin /lib /libexec /usr"


host_sh() {
    host=$1
    shift
    if [ "$host" = local ]; then
        sh -c "$*"
    else
        ssh -o BatchMode=yes "$host" "$*" </dev/null
    fi
}

host_system() { host_sh "$1" uname -sr; }

host_python() {
    host_sh "$1" 'command -v python3 || ls /usr/pkg/bin/python3.[0-9] /usr/pkg/bin/python3.[0-9][0-9] /usr/local/bin/python3.[0-9] /usr/local/bin/python3.[0-9][0-9] 2>/dev/null | tail -1'
}

host_jobs() { host_sh "$1" '/sbin/sysctl -n hw.ncpu 2>/dev/null || echo 4'; }

# Resolve every object below the roots with rldd and ldd, on the host.  The
# sweep prints its report on stdout, which comes back through ssh.
check_sweep() {
    host=$1
    rldd=$2
    sweep=$3
    python=$4
    jobs=${JOBS:-$(host_jobs "$host")}

    report=$(host_sh "$host" "$python $sweep --rldd $rldd --sample $SAMPLE --jobs $jobs $ROOTS")

    files=$(printf '%s\n' "$report" | sed -n "s/^FILES	//p")
    compared=$(printf '%s\n' "$report" | sed -n "s/^COMPARED	//p")
    untraced=$(printf '%s\n' "$report" | sed -n "s/^UNTRACED	//p")
    unreadable=$(printf '%s\n' "$report" | sed -n "s/^UNREADABLE	//p")
    unreadable_dirs=$(printf '%s\n' "$report" | sed -n "s/^UNREADABLE-DIRS	//p")

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

    # Both tools agree the dependency is missing, only listed.
    unresolved=$(printf '%s\n' "$report" | grep '^UNRESOLVED	' || true)
    if [ -n "$unresolved" ]; then
        info "$(printf '%s\n' "$unresolved" | wc -l | tr -d ' ') dependencies both tools report as not found, the most common being:"
        printf '%s\n' "$unresolved" | awk -F'\t' '{ print $3 }' | sort | uniq -c | sort -rn | head -5 |
            awk '{ printf "            %s  %s\n", $1, $2 }'
    fi
}

run_host() {
    host=$1

    system=$(host_system "$host")
    case $system in
    FreeBSD* | OpenBSD* | NetBSD*) ;;
    '')
        fail "$host: could not reach it"
        return 1
        ;;
    *)
        fail "$host: this test only runs on FreeBSD, OpenBSD or NetBSD ($system)"
        return 1
        ;;
    esac
    python=$(host_python "$host")
    if [ -z "$python" ]; then
        fail "$host: python3 is not installed"
        return 1
    fi

    printf '\n%s==> %s  %s  %s%s\n' "$C_BOLD" "$host" "$(host_sh "$host" uname -m)" "$system" "$C_OFF"

    if [ "$host" = local ]; then
        rldd=$REPO_ROOT/target/release/rldd
        if [ ! -x "$rldd" ] && ! (cd "$REPO_ROOT" && cargo build --quiet -r); then
            fail "cargo build failed"
            return 1
        fi
        # A copy, so a build replacing the binary during the sweep does not
        # pull it away.
        dir=$(mktemp -d "${TMPDIR:-/tmp}/rldd-tests.XXXXXX") || {
            fail "could not create a temporary directory"
            return 1
        }
        cp "$rldd" "$dir/rldd" && cp "$SCRIPT_DIR/sweep.py" "$dir/sweep.py"
        check_sweep local "$dir/rldd" "$dir/sweep.py" "$python"
        $KEEP || rm -rf "$dir"
        return
    fi

    host_sh "$host" "mkdir -p $REMOTE_DIR/src"
    if ! (cd "$REPO_ROOT" && git ls-files -z | tar -cf - --null -T -) |
        ssh -o BatchMode=yes "$host" "tar -xf - -C $REMOTE_DIR/src"; then
        fail "$host: could not copy the sources to $REMOTE_DIR/src"
        return 1
    fi
    printf '%s==> building on %s%s\n' "$C_BOLD" "$host" "$C_OFF"
    if ! host_sh "$host" "cd $REMOTE_DIR/src && cargo build --release --quiet"; then
        fail "$host: cargo build failed (is cargo installed there, with room for the build?)"
        $KEEP || host_sh "$host" "rm -rf $REMOTE_DIR"
        return 1
    fi
    rldd=$REMOTE_DIR/src/target/release/rldd
    if [ -z "$(host_sh "$host" "$rldd -l /usr/bin/ssh 2>/dev/null")" ]; then
        fail "$host: the rldd built in $REMOTE_DIR/src does not run there"
        return 1
    fi
    # The sweep script as it is here, tracked or not.
    if ! scp -q -o BatchMode=yes "$SCRIPT_DIR/sweep.py" "$host:$REMOTE_DIR/sweep.py" </dev/null; then
        fail "$host: could not copy sweep.py"
        return 1
    fi

    check_sweep "$host" "$rldd" "$REMOTE_DIR/sweep.py" "$python"

    $KEEP || host_sh "$host" "rm -rf $REMOTE_DIR"
}

for host in $HOSTS; do
    run_host "$host" || true
done

printf '\n%s%s passed, %s failed%s\n' "$C_BOLD" "$PASSED" "$FAILED" "$C_OFF"

[ "$FAILED" -eq 0 ]
