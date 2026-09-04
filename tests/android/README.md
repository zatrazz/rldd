# Android device test

The Android backend is only compiled when cross building, and the search it
does can only be checked against a real system image: the `ld.config.txt` of
the release, the APEX layout and the translation trees all come from the
device.  This builds rldd for the ABI of each attached device, pushes it, and
resolves every object of the image with it.

The `ld.config.txt` parsing itself is covered by the unit tests, which
`cargo test` runs on the host.

## Running

```sh
tests/android/run.sh                     # every attached device
tests/android/run.sh -d emulator-5554    # just one
tests/android/run.sh -s                  # reuse the binaries under target/
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
| `-s`, `--skip-build` | use the binaries already under `target/` |
| `-k`, `--keep` | leave the pushed files in `/data/local/tmp/rldd-tests` |

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

rldd is invoked one way only, `-l`, which prints the unique dependency list as
one `name => path` per line.  The remaining options (`--library-path`,
`--preload`, `--platform`, `-p`, `-a`, `-v`) change the search or the
presentation rather than what the device image makes it resolve, and belong to
the unit tests.

Every object below `/system/bin`, `/system/lib*`, `/vendor/lib*`, the
translation trees and the ART and runtime APEX binaries is resolved on the
device, in a single adb round trip:

| Check | What it covers |
| --- | --- |
| panics | no object makes rldd panic |
| resolution | every dependency of every object resolves |

Between them these cover the search rules the image drives, since an object
that reached the wrong section, the wrong APEX or the wrong translation
directory does not resolve at all: the ART APEX binaries only resolve when the
generated per-APEX configuration was picked, the `/system/bin/arm*` objects
only when the architecture specific `ld.config.<abi>.txt` was, and a shared
library only when it took the section of the executable directory of its
partition.

### Unresolved dependencies that are correct

The sweep does not count an object the device has no loader for.  A 64 bit only
image still ships the 32 bit ART binaries (`dalvikvm32`, `dex2oat32`) but
neither `/system/bin/linker` nor a 32 bit `/system/lib`, so the device cannot
run them either and reporting their system dependencies as missing is the right
answer.  Those objects are listed for information instead of failing the run.

The ELF class of the object is read from the file header and matched against
the loader present on the device, so no list of known exceptions is kept.
