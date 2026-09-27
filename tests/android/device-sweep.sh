#!/system/bin/sh
#
# Runs on the device: resolve every object below the given roots and print a
# machine readable report for run.sh to check.  Kept in one device side script
# so the whole sweep is a single adb round trip.
#
# usage: device-sweep.sh RLDD 'ROOT-GLOB...' [compare [LIBRARY_PATH [PRELOAD]]]
#
# With 'compare', each executable the device can run is also resolved by the
# device linker (linker[64] --list, Android 11 on) and the two results are
# compared.  A non empty LIBRARY_PATH and PRELOAD are then given to both, as
# rldd --library-path and --preload and as the LD_LIBRARY_PATH and LD_PRELOAD
# of the linker.
#
# The report lines are:
#
#   FILES n         objects inspected
#   ERRORS n        objects rldd refused (a shell script, or no read permission)
#   PANIC path      the object made rldd panic
#   CRASH path n    rldd was killed by signal n
#   UNRESOLVED path count loadable
#                   the object has unresolved dependencies; 'loadable' is no
#                   when the device has no loader for its ELF class, so it
#                   could not resolve them either
#
# and with 'compare':
#
#   SAME n          executables rldd resolves like the device linker
#   NOCMP path why  an executable the device linker could not list (one for
#                   another architecture, say), which is not compared
#   DIFF path       rldd resolves the executable differently, followed by
#   DIFF+ path dep  a 'name => real path' only rldd reports, and
#   DIFF- path dep  one only the device linker reports ('name => not found'
#                   when the linker could not find it)

rldd=$1
roots=$2
compare=${3:-}
library_path=${4:-}
preload=${5:-}

# Neither rldd nor the linker should see the environment of the adb shell.
unset LD_LIBRARY_PATH LD_PRELOAD

work=$(dirname "$rldd")

# Whether the device can load an object at all.  The class is the fifth byte
# of the ELF header (1 for ELFCLASS32, 2 for ELFCLASS64).
elf_class() {
    dd if="$1" bs=1 skip=4 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n'
}

loader() {
    case $1 in
    1) echo /system/bin/linker ;;
    2) echo /system/bin/linker64 ;;
    esac
}

loadable() {
    ldso=$(loader "$(elf_class "$1")")
    if [ -z "$ldso" ] || [ -e "$ldso" ]; then echo yes; else echo no; fi
}

# The 'name => path' lines of rldd -l, which reports the real path of each
# object the way the device linker does.
rldd_list() {
    printf '%s\n' "$1" | while read -r name arrow path; do
        [ "$arrow" = "=>" ] || continue
        case $path in
        "not found"*) echo "$name => not found" ;;
        *) echo "$name => $path" ;;
        esac
    done | sort -u
}

# The 'soname => real path' lines of linker --list, without the vDSO and the
# load addresses.  A library without a DT_SONAME is listed with an empty
# name, which is taken from the file name instead.
linker_list() {
    printf '%s\n' "$1" | sed -n -e '/=> \[vdso\]/d' \
        -e 's/^[[:space:]]*\(.*\) => \(.*\) (0x[0-9a-f]*)$/\1 => \2/p' |
        sed 's|^ => \(.*/\)\([^/]*\)$|\2 => \1\2|' | sort -u
}

files=0
errors=0
same=0

# Unquoted on purpose, the roots are globs for the device shell to expand,
# and more than one may match a file.
for f in $(printf '%s\n' $roots | sort -u); do
    [ -f "$f" ] || continue
    files=$((files + 1))

    if [ -n "$library_path$preload" ]; then
        out=$("$rldd" -l --library-path "$library_path" --preload "$preload" "$f" 2>&1)
    else
        out=$("$rldd" -l "$f" 2>&1)
    fi
    status=$?

    # A panic prints its message whether it unwinds or aborts (the release
    # build aborts), and any other fatal signal is a crash as well.
    case $out in
    *panicked*)
        echo "PANIC $f"
        continue
        ;;
    esac
    if [ "$status" -gt 128 ]; then
        echo "CRASH $f $((status - 128))"
        continue
    fi
    case $out in
    error:*)
        errors=$((errors + 1))
        continue
        ;;
    esac

    count=$(printf '%s\n' "$out" | grep -c 'not found')
    if [ "$count" -gt 0 ]; then
        echo "UNRESOLVED $f $count $(loadable "$f")"
    fi

    [ "$compare" = compare ] || continue

    # Only an executable (an object with an interpreter) the device has a
    # loader for: the linker lists a shared library with the configuration of
    # the library directory, while rldd uses the one of the executables of
    # its partition.
    case $(file -L "$f" 2>/dev/null) in
    *"dynamic ("*) ;;
    *) continue ;;
    esac
    ldso=$(loader "$(elf_class "$f")")
    if [ -z "$ldso" ] || [ ! -e "$ldso" ]; then
        continue
    fi

    device=$(LD_LIBRARY_PATH=$library_path LD_PRELOAD=$preload "$ldso" --list "$f" 2>&1)
    if [ $? -ne 0 ]; then
        # The linker stops at the first library it can not find, which rldd
        # should not find either.  Any other failure (an object for another
        # architecture, say) is not comparable.
        missing=$(printf '%s\n' "$device" | sed -n 's/.*library "\([^"]*\)" not found.*/\1/p' | head -1)
        if [ -z "$missing" ]; then
            echo "NOCMP $f $(printf '%s\n' "$device" | head -1)"
        elif rldd_list "$out" | grep -Fqx "$missing => not found"; then
            same=$((same + 1))
        else
            echo "DIFF $f"
            echo "DIFF- $f $missing => not found"
        fi
        continue
    fi

    rldd_list "$out" > "$work/rldd.list"
    linker_list "$device" > "$work/linker.list"
    if cmp -s "$work/rldd.list" "$work/linker.list"; then
        same=$((same + 1))
        continue
    fi
    echo "DIFF $f"
    grep -Fvx -f "$work/linker.list" "$work/rldd.list" | sed "s|^|DIFF+ $f |"
    grep -Fvx -f "$work/rldd.list" "$work/linker.list" | sed "s|^|DIFF- $f |"
done

rm -f "$work/rldd.list" "$work/linker.list"

echo "FILES $files"
echo "ERRORS $errors"
if [ "$compare" = compare ]; then
    echo "SAME $same"
fi
