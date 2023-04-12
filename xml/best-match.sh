#!/bin/sh
#
# Find the (sub-)schema that best matches a desired version.
#
# Version numbers are assumed to be in the format X.Y,
# where X and Y are integers, and Y is no more than 3 digits,
# or the special value "next".
#

# (Sub-)schema name (e.g. "resources")
base="$1"; shift

# Desired version (e.g. "1.0" or "next")
target="$1"; shift

# If not empty, append the best match as an XML externalRef to this file
# (otherwise, just echo the best match). Using readlink allows building
# from a different directory.
destination="$(readlink -f "$1")"; shift

# Arbitrary text to print before XML (generally spaces to indent)
prefix="$1"; shift

# Allow building from a different directory
cd "$(dirname $0)"

list_candidates() {
    ls -1 "${1}.rng" "${1}"-[0-9]*.rng 2>/dev/null
}

version_from_filename() {
    vff_filename="$1"

    case "$vff_filename" in
        *-*.rng)
            echo "$vff_filename" | sed -e 's/.*-\(.*\).rng/\1/'
            ;;
        *)
            # special case for bare ${base}.rng, no -0.1's around anyway
            echo 0.1
            ;;
    esac
}

filename_from_version() {
    ffv_version="$1"
    ffv_base="$2"

    if [ "$ffv_version" = "0.1" ]; then
        echo "${ffv_base}.rng"
    else
        echo "${ffv_base}-${ffv_version}.rng"
    fi
}

# Convert version string (e.g. 2.10) into integer (e.g. 2010) for comparisons
int_version() {
    echo "$1" | awk -F. '{ printf("%d%03d\n", $1,$2); }';
}

best="0.0"
for rng in $(list_candidates "${base}"); do
    case ${rng} in
        ${base}-${target}.rng)
            # We found exactly what was requested
            best=${target}
            break
            ;;
        *-next.rng)
            # "Next" schemas cannot be a best match unless directly requested
            ;;
        *)
            v=$(version_from_filename "${rng}")
	    if [ $(int_version "${v}") -gt $(int_version "${best}") ]; then
                # This version beats the previous best match

                if [ "${target}" = "next" ]; then
                    best=${v}
                elif [ $(int_version "${v}") -lt $(int_version "${target}") ]; then
                    # This value is best only if it's still less than the target
                    best=${v}
                fi
            fi
            ;;
    esac
done

if [ "$best" != "0.0" ]; then
    found=$(filename_from_version "$best" "$base")
    if [ -z "$destination" ]; then
        echo "$(basename $found)"
    else
        echo "${prefix}<externalRef href=\"$(basename $found)\"/>" >> "$destination"
    fi
    exit 0
fi

exit 1
