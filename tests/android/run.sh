#!/bin/sh
#
# Run the rldd Android device test on every attached device.
#
# usage: tests/android/run.sh [-d SERIAL]... [-k]

set -u

# Invoked from PowerShell or cmd in a Windows system.
self=$0
case $self in
[A-Za-z]:[/\\]*)
    command -v cygpath >/dev/null 2>&1 && self=$(cygpath -u "$self")
    ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

case "$(uname -s)" in
MINGW* | MSYS*) export MSYS_NO_PATHCONV=1 ;;
esac

DEVICE_DIR=/data/local/tmp/rldd-tests
ADB=${ADB:-adb}

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
    printf '        %s\n' "$*"; 
}

die() {
    printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: tests/android/run.sh [options]

  -d, --device SERIAL   only test this device (may be repeated)
  -c, --compare         also compare every executable with the device linker
                        (Android 11 and later)
  -k, --keep            leave the pushed files on the device
  -h, --help            this message

The ADB environment variable overrides the adb binary, and ANDROID_NDK_HOME
(or ANDROID_HOME) points at the NDK used to link the device binaries.
EOF
}

SERIALS=
KEEP=false
COMPARE=false

while [ $# -gt 0 ]; do
    case $1 in
    -d | --device)
        [ $# -ge 2 ] || die "$1 needs a device serial"
        SERIALS="$SERIALS $2"
        shift 2
        ;;
    -c | --compare) COMPARE=true; shift ;;
    -k | --keep) KEEP=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument '$1' (try --help)" ;;
    esac
done

# The host paths.  Cargo and the NDK wrappers are Windows programs, and
# MSYS_NO_PATHCONV stops the shell from converting their arguments, so a path
# handed to one of them is converted here instead.

# 'C:\Android\ndk\30.0' to the MSYS form '/c/Android/ndk/30.0'.
msys_path() {
    case "$1" in
    [A-Za-z]:[/\\]*)
        printf '%s\n' "$1" | sed -e 's|\\|/|g' -e 's|^\([A-Za-z]\):|/\L\1|' -e 's|/*$||'
        ;;
    *) printf '%s\n' "${1%/}" ;;
    esac
}

native_path() {
    case "$(uname -s)" in
    MINGW* | MSYS*)
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -m "$1"
        else
            printf '%s\n' "$1" | sed -e 's|^/\([A-Za-z]\)/|\1:/|'
        fi
        ;;
    *) printf '%s\n' "$1" ;;
    esac
}

host_tag() {
    case "$(uname -s)" in
    MINGW* | MSYS*) printf 'windows-x86_64\n' ;;
    Darwin) printf 'darwin-x86_64\n' ;;
    *) printf 'linux-x86_64\n' ;;
    esac
}

# The Rust target triple for an 'ro.product.cpu.abi' value.
rust_target() {
    case "$1" in
    arm64-v8a) printf 'aarch64-linux-android\n' ;;
    armeabi-v7a | armeabi) printf 'armv7-linux-androideabi\n' ;;
    x86) printf 'i686-linux-android\n' ;;
    x86_64) printf 'x86_64-linux-android\n' ;;
    riscv64) printf 'riscv64-linux-android\n' ;;
    *) return 1 ;;
    esac
}

# The NDK clang wrapper that links a target.
ndk_linker() {
    ndk=
    for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${NDK_HOME:-}"; do
        [ -n "$candidate" ] || continue
        ndk=$(msys_path "$candidate")
        [ -d "$ndk" ] && break
        ndk=
    done
    if [ -z "$ndk" ] && [ -n "${ANDROID_HOME:-}" ]; then
        # The highest installed revision below $ANDROID_HOME/ndk.
        ndk=$(ls -d "$(msys_path "$ANDROID_HOME")"/ndk/* 2>/dev/null | sort -V | tail -1)
    fi
    [ -n "$ndk" ] || return 1

    case "$1" in
    armv7-linux-androideabi) prefix=armv7a-linux-androideabi ;;
    *) prefix=$1 ;;
    esac
    clang="$ndk/toolchains/llvm/prebuilt/$(host_tag)/bin/${prefix}21-clang"

    [ -f "$clang.cmd" ] && { printf '%s\n' "$clang.cmd"; return 0; }
    [ -f "$clang" ] && { printf '%s\n' "$clang"; return 0; }
    return 1
}

# Build rldd for a target, setting RLDD_BIN to the binary cargo reports.  A
# fixed path below target/ would be a stale binary (or none at all) when
# CARGO_TARGET_DIR or build.target-dir moves the build elsewhere.
build_target() {
    RLDD_BIN=
    if linker=$(ndk_linker "$1"); then
        var=$(printf 'CARGO_TARGET_%s_LINKER' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')")
        export "$var=$(native_path "$linker")"
    fi

    if ! json=$(cd "$REPO_ROOT" &&
        cargo build --quiet -r --target "$1" --message-format=json); then
        fail "cargo build -r --target $1 failed (is the target installed?)"
        return 1
    fi

    # The last artifact with an executable is the rldd binary, whose path has
    # its backslashes escaped on Windows.
    RLDD_BIN=$(printf '%s\n' "$json" |
        sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1 | sed 's/\\\\/\\/g')
    if [ -z "$RLDD_BIN" ]; then
        fail "cargo build -r --target $1 did not report the rldd binary"
        return 1
    fi
    RLDD_BIN=$(msys_path "$RLDD_BIN")
}

adb_sh() {
    adb_serial=$1
    shift
    # The device shell returns the exit status of the command, and the CRLF the
    # pty adds would end up inside the values the caller compares.
    "$ADB" -s "$adb_serial" shell "$@" </dev/null | tr -d '\r'
}

adb_push() {
    # adb reports the transfer rate on stderr.
    out=$("$ADB" -s "$1" push "$(native_path "$2")" "$3" </dev/null 2>&1) || {
        fail "$1: could not push $2"
        printf '%s\n' "$out" | sed 's/^/        /' | head -3
        return 1
    }
}

# The number of distinct differences check_compare lists.
DIFF_LIMIT=25

# Report the comparison of a device-sweep.sh run with the device linker.  The
# differences are grouped by entry, with the number of executables each one
# shows up on, since a single search rule usually accounts for many of them.
check_compare() {
    report=$1
    what=$2

    same=$(printf '%s\n' "$report" | sed -n 's/^SAME //p')
    nocmp=$(printf '%s\n' "$report" | grep -c '^NOCMP ' || true)
    diffs=$(printf '%s\n' "$report" | grep -c '^DIFF ' || true)
    counts="${same:-0} the same, $nocmp the device linker could not list"

    # An object for another architecture, the translated ones, say.
    if [ "$nocmp" -gt 0 ]; then
        info "$nocmp executable(s) the device linker could not list, not compared:"
        printf '%s\n' "$report" | sed -n 's/^NOCMP /          /p' | head -"$DIFF_LIMIT"
    fi

    if [ "$diffs" -eq 0 ]; then
        pass "$what: resolved like the device linker ($counts)"
        return
    fi
    fail "$what: $diffs executable(s) resolved unlike the device linker ($counts)"

    tab=$(printf '\t')
    groups=$(printf '%s\n' "$report" | awk '
        /^DIFF[+-] / {
            key = substr($1, 5, 1) " " substr($0, length($1) + length($2) + 3)
            count[key]++
            if (!(key in example)) example[key] = $2
        }
        END { for (key in count) printf "%d\t%s\t%s\n", count[key], key, example[key] }' |
        sort -t "$tab" -k1,1nr -k2,2)
    info "'+' only rldd reports it, '-' only the device linker does:"
    printf '%s\n' "$groups" | head -"$DIFF_LIMIT" |
        awk -F "$tab" '{ printf "        %5d x %s  (%s)\n", $1, $2, $3 }'
    more=$(($(printf '%s\n' "$groups" | wc -l) - DIFF_LIMIT))
    [ "$more" -le 0 ] || info "... and $more more"
}

# Resolve every object of the system image.  The roots stay unquoted through to
# the device shell, which expands them; a tree the image does not have simply
# matches nothing.
check_sweep() {
    dev=$1
    api=$2

    roots="/system/bin/* /system/lib/*.so /system/lib64/*.so"
    roots="$roots /vendor/lib/*.so /vendor/lib64/*.so"
    roots="$roots /system/bin/arm/* /system/bin/arm64/*"
    roots="$roots /apex/com.android.art/bin/* /apex/com.android.runtime/bin/*"
    # The vendor executables and the /apex directory listing are only
    # readable as root (adb root on a userdebug image), and the '@version'
    # APEX mounts are left out.
    roots="$roots /vendor/bin/* /vendor/bin/hw/* /system_ext/bin/* /product/bin/*"
    roots="$roots /apex/*[!0-9]/bin/*"

    # The device linker lists the dependencies (--list) from Android 11 on.
    compare=
    if $COMPARE; then
        if [ "$api" -ge 30 ]; then
            compare=compare
        else
            info "compare: the device linker has no --list before Android 11 (API 30)"
        fi
    fi

    report=$(adb_sh "$dev" "sh $DEVICE_DIR/device-sweep.sh $DEVICE_DIR/rldd '$roots' $compare")

    files=$(printf '%s\n' "$report" | sed -n 's/^FILES //p')
    errors=$(printf '%s\n' "$report" | sed -n 's/^ERRORS //p')
    panics=$(printf '%s\n' "$report" | grep -c '^PANIC ' || true)
    crashes=$(printf '%s\n' "$report" | grep -c '^CRASH ' || true)
    unloadable=$(printf '%s\n' "$report" | grep -c '^UNRESOLVED .* no$' || true)
    unresolved=$(printf '%s\n' "$report" | grep -c '^UNRESOLVED .* yes$' || true)

    # An empty sweep means the device side script did not run, not a clean run.
    if [ -z "${files:-}" ] || [ "$files" -eq 0 ]; then
        fail "sweep: nothing was inspected"
        printf '%s\n' "$report" | sed 's/^/        /' | head -5
        return
    fi
    summary="$files objects, ${errors:-0} not readable"

    if [ "$panics" -gt 0 ] || [ "$crashes" -gt 0 ]; then
        fail "sweep: $panics object(s) panicked, $crashes killed by a signal"
        printf '%s\n' "$report" | grep '^PANIC ' | sed 's/^PANIC /        /'
        printf '%s\n' "$report" | grep '^CRASH ' |
            awk '{ printf "        %s (signal %s)\n", $2, $3 }'
    else
        pass "sweep: no panics nor crashes ($summary)"
    fi

    if [ "$unresolved" -gt 0 ]; then
        fail "sweep: unresolved dependencies"
        printf '%s\n' "$report" | grep '^UNRESOLVED .* yes$' |
            awk '{ printf "        %s (%s)\n", $2, $3 }'
    else
        pass "sweep: every dependency resolved ($summary)"
    fi

    # An object of the other bitness on a single ABI image: the device has no
    # loader for it, so reporting its system dependencies as missing is right.
    if [ "$unloadable" -gt 0 ]; then
        info "$unloadable object(s) the device itself cannot load, not counted:"
        printf '%s\n' "$report" | grep '^UNRESOLVED .* no$' |
            awk '{ printf "          %s (%s unresolved)\n", $2, $3 }'
    fi

    [ -z "$compare" ] || check_compare "$report" "compare"
}

# The options that change the resolution, --library-path and --preload, on a
# few executables of the primary ABI, compared with the device linker given
# the same LD_LIBRARY_PATH and LD_PRELOAD: the ART APEX library directory
# holds its own libc++ and libbase, and libcutils brings in dependencies of
# its own.  The options that only change the output (-v, -a and -p) are only
# checked for crashes.
check_options() {
    dev=$1
    api=$2

    roots="/system/bin/toybox /system/bin/logcat /system/bin/sh"
    lib=$(adb_sh "$dev" "[ -e /system/bin/linker64 ] && echo lib64 || echo lib")

    status=$(adb_sh "$dev" "$DEVICE_DIR/rldd -v -a -p $roots >/dev/null 2>&1; echo \$?")
    case $status in
    '' | *[!0-9]*) fail "options: rldd -v -a -p did not run" ;;
    *)
        if [ "$status" -gt 128 ]; then
            fail "options: rldd -v -a -p was killed by signal $((status - 128))"
        else
            pass "options: -v -a -p run (status $status)"
        fi
        ;;
    esac

    if $COMPARE && [ "$api" -ge 30 ]; then
        report=$(adb_sh "$dev" "sh $DEVICE_DIR/device-sweep.sh $DEVICE_DIR/rldd '$roots' compare /apex/com.android.art/$lib libcutils.so")
        if printf '%s\n' "$report" | grep -q '^PANIC \|^CRASH '; then
            fail "options: --library-path and --preload crashed"
        fi
        check_compare "$report" "options"
    fi
}

run_device() {
    dev=$1

    api=$(adb_sh "$dev" getprop ro.build.version.sdk)
    abi=$(adb_sh "$dev" getprop ro.product.cpu.abi)
    case $api in
    '' | *[!0-9]*)
        fail "$dev: could not read ro.build.version.sdk (device offline?)"
        return 1
        ;;
    esac
    if ! target=$(rust_target "$abi"); then
        fail "$dev: unsupported ABI '$abi'"
        return 1
    fi

    printf '\n%s==> %s  API %s  %s (%s)%s\n' \
        "$C_BOLD" "$dev" "$api" "$abi" "$target" "$C_OFF"

    build_target "$target" || return 1

    rldd=$RLDD_BIN
    if [ ! -f "$rldd" ]; then
        fail "$dev: $rldd is missing"
        return 1
    fi

    adb_sh "$dev" "mkdir -p $DEVICE_DIR"
    adb_push "$dev" "$rldd" "$DEVICE_DIR/rldd" || return 1
    adb_push "$dev" "$SCRIPT_DIR/device-sweep.sh" "$DEVICE_DIR/device-sweep.sh" || return 1
    adb_sh "$dev" "chmod 755 $DEVICE_DIR/rldd"

    # A failed push would otherwise show up as a suspiciously clean run.
    if [ -z "$(adb_sh "$dev" "$DEVICE_DIR/rldd -l /system/bin/ls")" ]; then
        fail "$dev: the rldd pushed to $DEVICE_DIR does not run"
        return 1
    fi

    check_sweep "$dev" "$api"
    check_options "$dev" "$api"

    $KEEP || adb_sh "$dev" "rm -rf $DEVICE_DIR"
}


if [ -z "$SERIALS" ]; then
    SERIALS=$("$ADB" devices </dev/null | awk '/^[^ \t]+[ \t]+device$/ { print $1 }')
fi
# Unquoted on purpose, to drop the leading space '--device' leaves behind and
# to count the serials.
SERIALS=$(echo $SERIALS)
[ -n "$SERIALS" ] || die "no device attached"

printf '%s%s device(s): %s%s\n' \
    "$C_BOLD" "$(printf '%s\n' $SERIALS | wc -l | tr -d ' ')" "$SERIALS" "$C_OFF"

for serial in $SERIALS; do
    run_device "$serial" || true
done

printf '\n%s%s passed, %s failed%s\n' "$C_BOLD" "$PASSED" "$FAILED" "$C_OFF"

[ "$FAILED" -eq 0 ]
