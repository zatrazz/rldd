#!/system/bin/sh
#
# Runs on the device: resolve every object below the given roots and print a
# machine readable report for run.sh to check.  Kept in one device side script
# so the whole sweep is a single adb round trip.
#
# usage: device-sweep.sh RLDD 'ROOT-GLOB...'
#
# The report lines are:
#
#   FILES n         objects inspected
#   ERRORS n        objects rldd refused (a shell script, or no read permission)
#   PANIC path      the object made rldd panic
#   UNRESOLVED path count loadable
#                   the object has unresolved dependencies; 'loadable' is no
#                   when the device has no loader for its ELF class, so it
#                   could not resolve them either

rldd=$1
shift

# Whether the device can load an object at all. A 32 bit one needs
# /system/bin/linker and a 64 bit one /system/bin/linker64, and a 64 bit only
# image ships neither the 32 bit loader nor a 32 bit /system/lib.  The class is
# the fifth byte of the ELF header (1 for ELFCLASS32, 2 for ELFCLASS64).
loadable() {
    class=$(dd if="$1" bs=1 skip=4 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
    case $class in
    1) [ -e /system/bin/linker ] && echo yes || echo no ;;
    2) [ -e /system/bin/linker64 ] && echo yes || echo no ;;
    *) echo yes ;;
    esac
}

files=0
errors=0

# Unquoted on purpose, the roots are globs for the device shell to expand.
for f in $@; do
    [ -f "$f" ] || continue
    files=$((files + 1))

    out=$("$rldd" -l "$f" 2>&1)

    case $out in
    *panicked*)
        echo "PANIC $f"
        continue
        ;;
    error:*)
        errors=$((errors + 1))
        continue
        ;;
    esac

    count=$(printf '%s\n' "$out" | grep -c 'not found')
    if [ "$count" -gt 0 ]; then
        echo "UNRESOLVED $f $count $(loadable "$f")"
    fi
done

echo "FILES $files"
echo "ERRORS $errors"
