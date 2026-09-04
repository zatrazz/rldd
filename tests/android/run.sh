#!/bin/sh
#
# Run the rldd Android device test on every attached device.
#
# The Android backend is only compiled when cross building, and the search it
# does can only be checked against a real system image: the ld.config.txt of
# the release, the APEX layout and the translation trees all come from the
# device.  This builds rldd for the device ABI, pushes it, and resolves every
# object of the image with it.  Nothing may panic, and nothing may be left
# unresolved unless the device has no loader for it either.
#
# usage: tests/android/run.sh [-d SERIAL]... [-s] [-k]

set -u

# Invoked from PowerShell or cmd the script path is a Windows one, which
# dirname does not understand.
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

# The report.

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

info() { printf '        %s\n' "$*"; }

die() {
    printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: tests/android/run.sh [options]

  -d, --device SERIAL   only test this device (may be repeated)
  -s, --skip-build      use the binaries already under target/
  -k, --keep            leave the pushed files on the device
  -h, --help            this message

The ADB environment variable overrides the adb binary, and ANDROID_NDK_HOME
(or ANDROID_HOME) points at the NDK used to link the device binaries.
EOF
}

SERIALS=
SKIP_BUILD=false
KEEP=false

while [ $# -gt 0 ]; do
    case $1 in
    -d | --device)
        [ $# -ge 2 ] || die "$1 needs a device serial"
        SERIALS="$SERIALS $2"
        shift 2
        ;;
    -s | --skip-build) SKIP_BUILD=true; shift ;;
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
    MINGW* | MSYS* | CYGWIN*)
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
    MINGW* | MSYS* | CYGWIN*) printf 'windows-x86_64\n' ;;
    Darwin) printf 'darwin-x86_64\n' ;;
    *) printf 'linux-x86_64\n' ;;
    esac
}

# The cross build.

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

# The NDK clang wrapper that links a target.  The NDK names the arm one after
# the armv7a sub-architecture, ships each tool both as a shell script and as a
# .cmd wrapper, and only the wrapper is a program the Windows tools can run.
# The API level only selects the startup files, so the oldest one it ships is
# enough for a test binary.
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

BUILT_TARGETS=

build_target() {
    case " $BUILT_TARGETS " in
    *" $1 "*) return 0 ;;
    esac

    if linker=$(ndk_linker "$1"); then
        var=$(printf 'CARGO_TARGET_%s_LINKER' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')")
        export "$var=$(native_path "$linker")"
    fi

    printf '%s==> building %s%s\n' "$C_BOLD" "$1" "$C_OFF"
    if ! ( cd "$REPO_ROOT" && cargo build --quiet --target "$1" ); then
        fail "cargo build --target $1 failed (is the target installed?)"
        return 1
    fi

    BUILT_TARGETS="$BUILT_TARGETS $1"
}

# The device.

adb_sh() {
    adb_serial=$1
    shift
    # The device shell returns the exit status of the command, and the CRLF the
    # pty adds would end up inside the values the caller compares.
    "$ADB" -s "$adb_serial" shell "$@" </dev/null | tr -d '\r'
}

adb_push() {
    # adb reports the transfer rate on stderr, which is only of interest when
    # the push failed.
    out=$("$ADB" -s "$1" push "$(native_path "$2")" "$3" </dev/null 2>&1) || {
        fail "$1: could not push $2"
        printf '%s\n' "$out" | sed 's/^/        /' | head -3
        return 1
    }
}

# Resolve every object of the system image.  The roots stay unquoted through to
# the device shell, which expands them; a tree the image does not have simply
# matches nothing.
check_sweep() {
    roots="/system/bin/* /system/lib/*.so /system/lib64/*.so"
    roots="$roots /vendor/lib/*.so /vendor/lib64/*.so"
    roots="$roots /system/bin/arm/* /system/bin/arm64/*"
    roots="$roots /apex/com.android.art/bin/* /apex/com.android.runtime/bin/*"

    report=$(adb_sh "$1" "sh $DEVICE_DIR/device-sweep.sh $DEVICE_DIR/rldd '$roots'")

    files=$(printf '%s\n' "$report" | sed -n 's/^FILES //p')
    errors=$(printf '%s\n' "$report" | sed -n 's/^ERRORS //p')
    panics=$(printf '%s\n' "$report" | grep -c '^PANIC ' || true)
    unloadable=$(printf '%s\n' "$report" | grep -c '^UNRESOLVED .* no$' || true)
    unresolved=$(printf '%s\n' "$report" | grep -c '^UNRESOLVED .* yes$' || true)

    # An empty sweep means the device side script did not run, not a clean run.
    if [ -z "${files:-}" ] || [ "$files" -eq 0 ]; then
        fail "sweep: nothing was inspected"
        printf '%s\n' "$report" | sed 's/^/        /' | head -5
        return
    fi
    summary="$files objects, ${errors:-0} not readable"

    if [ "$panics" -gt 0 ]; then
        fail "sweep: $panics object(s) panicked"
        printf '%s\n' "$report" | grep '^PANIC ' | sed 's/^PANIC /        /'
    else
        pass "sweep: no panics ($summary)"
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
}

# One device.  Anything that goes wrong here is reported against the device and
# the run moves on to the next one, so an emulator that dropped off its adb
# connection, or an ABI with no Rust target installed, does not take the result
# of the other devices with it.
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

    $SKIP_BUILD || build_target "$target" || return 1

    rldd="$REPO_ROOT/target/$target/debug/rldd"
    if [ ! -f "$rldd" ]; then
        fail "$dev: $rldd is missing (drop --skip-build)"
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

    check_sweep "$dev"

    $KEEP || adb_sh "$dev" "rm -rf $DEVICE_DIR"
}

# The run.

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
