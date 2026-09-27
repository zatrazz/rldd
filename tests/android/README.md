# Android device test

The Android backend is only compiled when cross building, and the search it
does can only be checked against a real system image: the `ld.config.txt` of
the release, the APEX layout and the translation trees all come from the
device.  This builds rldd for the ABI of each attached device, pushes it, and
resolves every object of the image with it.

The `ld.config.txt` parsing itself is covered by the unit tests, which
`cargo test` runs on a Linux host: the tests set the system properties the
parsing depends on (the release and the VNDK version) instead of reading them
from the device.  They do not run on the other hosts.

## Running

```sh
tests/android/run.sh                     # every attached device
tests/android/run.sh -d emulator-5554    # just one
tests/android/run.sh -c                  # also compare with the device linker
```

On Windows the suite needs the Git Bash shell.  From PowerShell use the wrapper,
which finds it and passes every argument through:

```powershell
tests\android\run.ps1
tests\android\run.ps1 -d emulator-5554
```

NB: it does not work with a `bash` that starts a WSL shell. A WSL distribution 
does not reach the emulators nor the adb server running on the Windows side without
setting up Windows interop and the adb server for it first.

The run starts by printing the devices it found, and a device that fails is
reported and skipped rather than ending the run, so one emulator that dropped
off its adb connection does not hide the result of the others.

The exit status is non-zero when any check fails.  Options:

| Option | Meaning |
| --- | --- |
| `-d`, `--device SERIAL` | only test this device, may be repeated |
| `-c`, `--compare` | also compare the executables with the device linker (Android 11 and later) |
| `-k`, `--keep` | leave the pushed files in `/data/local/tmp/rldd-tests` |

rldd is always built for the device before it is pushed, and the binary pushed
is the one cargo reports, so a `CARGO_TARGET_DIR` elsewhere does not leave a
stale one behind.

Prerequisites:

* `adb`, on `PATH` or named by the `ADB` environment variable.
* The Rust target of every device ABI (`rustup target add` for `x86_64-linux-android`,
  `i686-linux-android`, `aarch64-linux-android` and `armv7-linux-androideabi`).
* An NDK, found through `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `NDK_HOME`, or
  the highest revision below `$ANDROID_HOME/ndk`.

An emulator of each API level the loader behaves differently on is the useful
set: 26 and 27 (the hardcoded configuration path), 28 (the abi and vndk paths,
and `/odm`), 29 (the per APEX configuration), 30 (the generated `/linkerconfig`),
and whatever is current.

## What is checked

Every object below `/system/bin`, `/system/lib*`, `/vendor/lib*`, the
translation trees and the ART and runtime APEX binaries is resolved on the
device with `rldd -l`, which prints the unique dependency list as one
`name => path` per line, in a single adb round trip:

| Check | What it covers |
| --- | --- |
| crashes | no object makes rldd panic or die from a signal |
| resolution | every dependency of every object resolves |
| compare (`-c`) | every executable resolves to the libraries the device linker loads |
| options | `-v -a -p` does not crash, and with `-c`, `--library-path` and `--preload` resolve like the device linker does with the same `LD_LIBRARY_PATH` and `LD_PRELOAD` |

The resolution check only catches a dependency that does not resolve at all.
An object that took the wrong section, APEX configuration or search path, but
still found a library of that name somewhere, passes it; the comparison is
what catches those.

### Comparing with the device linker

From Android 11 the linker lists what it loads for an executable
(`linker64 --list`, which `/system/bin/ldd` runs) as `soname => real path`.
With `-c` every executable the device can run is also listed that way, and the
`name => path` pairs of rldd, with each path resolved with `readlink -f`, must
be the same set.  An executable the linker fails to link because a library is
missing compares as that library not found.

The differences are grouped by entry, `+` for one only rldd reports and `-` for
one only the linker does, along with the number of executables it shows up on
and one of them, since a single search rule usually accounts for many.

What is not compared:

* A shared library: the linker lists it with the configuration section of its
  own directory (usually none, so the default directories), while rldd takes
  the one of the executables of its partition.
* An executable the linker can not list, the ones of the translation trees for
  another architecture: they are shown for information.
* `--platform`, which only sets the `$PLATFORM` of a search path, a variable
  the bionic loader does not expand.

Before Android 11 the comparison is skipped with a note.

### Unresolved dependencies that are correct

The sweep does not count an object the device has no loader for.  A 64 bit only
image still ships the 32 bit ART binaries (`dalvikvm32`, `dex2oat32`) but
neither `/system/bin/linker` nor a 32 bit `/system/lib`, so the device cannot
run them either and reporting their system dependencies as missing is the right
answer.  Those objects are listed for information instead of failing the run.

The ELF class of the object is read from the file header and matched against
the loader present on the device, so no list of known exceptions is kept.
