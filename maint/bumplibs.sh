#!/bin/bash
#
# Copyright 2012-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

declare -A HEADERS
HEADERS[cib]="include/crm/cib.h include/crm/cib/*.h"
HEADERS[crmcommon]="include/crm/crm.h
                    include/crm/msg_xml.h
                    include/crm/common/*.h"
HEADERS[crmcluster]="include/crm/cluster.h include/crm/cluster/*.h"
HEADERS[crmservice]="include/crm/services*.h"
HEADERS[lrmd]="include/crm/lrmd*.h"
HEADERS[pacemaker]="include/pacemaker*.h"
HEADERS[pe_rules]="include/crm/pengine/ru*.h"
HEADERS[pe_status]="include/crm/pengine/[^r]*.h include/crm/pengine/r[^u]*.h"
HEADERS[stonithd]="include/crm/stonith-ng.h include/crm/fencing/*.h"

prompt_to_continue() {
    local RESPONSE

    read -p "Continue? " RESPONSE
    case "$RESPONSE" in
        y|Y|yes|ano|ja|si|oui) ;;
        *) exit 0 ;;
    esac
}

find_last_release() {
    if [ ! -z "$1" ]; then
        echo "$1"
    else
        git tag -l | grep Pacemaker | grep -v rc | sort -Vr | head -n 1
    fi
}

find_libs() {
    find lib -name "*.am" -exec grep "lib.*_la_LDFLAGS.*version-info" \{\} \; \
        | sed -e 's/lib\(.*\)_la_LDFLAGS.*/\1/'
}

find_makefile() {
    find lib -name Makefile.am -exec grep -l "lib${1}_la.*version-info" \{\} \;
}

find_sources() {
    local LIB="$1"
    local AMFILE="$2"
    local SOURCES

    # Library makefiles should use "+=" to break up long sources lines rather
    # than backslashed continuation lines, to allow this script to detect
    # source files correctly. Warn if that's not the case.
    if
        grep "lib${LIB}_la_SOURCES.*\\\\" $AMFILE
    then
        echo -e "\033[1;35m -- Sources list for lib$LIB is probably truncated! --\033[0m"
        echo "Edit to use '+=' rather than backslashed continuation lines"
        prompt_to_continue
    fi

    SOURCES=$(grep "^lib${LIB}_la_SOURCES" "$AMFILE" \
        | sed -e 's/.*=//' -e 's/\\//' -e 's:\.\./gnu/:lib/gnu/:')

    for SOURCE in $SOURCES; do
        if
            echo $SOURCE | grep -q "/"
        then
            echo "$SOURCE"
        else
            echo "$(dirname $AMFILE)/$SOURCE"
        fi
    done
}

extract_version() {
    grep "lib${1}_la.*version-info" | sed -e 's/.*version-info\s*\(\S*\)/\1/'
}

shared_lib_name() {
    local LIB="$1"
    local VERSION="$2"

    echo "lib${LIB}.so.$(echo $VERSION | cut -d: -f 1)"
}

process_lib() {
    local LIB="$1"
    local LAST_RELEASE="$2"
    local AMFILE
    local SOURCES
    local HEADERS_EXP
    local HEADERS_GONE
    local CHANGE
    local CHANGES

    if [ -z "${HEADERS[$LIB]}" ]; then
        echo "Can't check lib$LIB until this script is updated with its headers"
        prompt_to_continue
    fi

    for HEADER in $(ls ${HEADERS[$LIB]} 2>&1|sed -e 's/.* include/include/' -e 's/:.*//'); do
      if [ -f "$HEADER" ]; then
        HEADERS_EXP+=" $HEADER"
      else
        HEADERS_GONE+=" $HEADER"
      fi
    done

    AMFILE="$(find_makefile "$LIB")"

    # Get current shared library version
    VER_NOW=$(cat $AMFILE | extract_version $LIB)

    # Check whether library existed at last release
    git cat-file -e $LAST_RELEASE:$AMFILE 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "lib$LIB is new, not changing version ($VER_NOW)"
        prompt_to_continue
        echo ""
        return
    fi

    # Check whether there were any changes to headers or sources
    SOURCES="$(find_sources "$LIB" "$AMFILE")"
    CHANGES=$(git diff -w $LAST_RELEASE..HEAD $HEADERS_EXP $SOURCES | wc -l)
    if [ $CHANGES -eq 0 ]; then
        if [ -z "$HEADERS_GONE" ]; then
          echo "No changes to $LIB interface"
          prompt_to_continue
          echo ""
          return
        fi
    fi

    # Show all header changes since last release
    echo "- Changes in Headers ($HEADERS_EXP) since $LAST_RELEASE:"
    if [ ! -z "$HEADERS_GONE" ]; then
      for HEADER in $HEADERS_GONE; do
        echo "$HEADER not found in current release!"
      done
    fi
    git --no-pager diff --color -w $LAST_RELEASE..HEAD ${HEADERS_EXP}

    # Show commits touching lib since last release
    echo ""
    echo "- Commits (without Refactor & Build) touching lib$LIB since $LAST_RELEASE:"
    git log --color Pacemaker-2.0.3..HEAD -z ${HEADERS_EXP} $SOURCES $AMFILE|grep -vzE "Refactor:|Build:|Merge pull request"

    # Show merged PRs since last release touching this lib
    echo ""
    echo "- PRs merged touching lib$LIB since $LAST_RELEASE:"
    git log Pacemaker-2.0.3..HEAD -z ${HEADERS_EXP} $SOURCES $AMFILE|grep -z "Merge pull request"|sed -zr "s/.*#([0-9]+).*/#\1 /"
    echo ""

    # Show summary of source changes since last release
    echo ""
    echo "- Headers: ${HEADERS_EXP}"
    echo "- Changed sources since $LAST_RELEASE:"
    git --no-pager diff --color -w $LAST_RELEASE..HEAD --stat $SOURCES
    echo ""

    # Ask for human guidance
    # @TODO: change default based on intelligent analysis
    echo "Are the changes to lib$LIB:"
    read -p "[c]ompatible additions, [i]ncompatible additions/removals or [f]ixes? [None]: " CHANGE

    # Get (and show) shared library version at last release
    VER=$(git show $LAST_RELEASE:$AMFILE | extract_version $LIB)
    VER_1=$(echo $VER | awk -F: '{print $1}')
    VER_2=$(echo $VER | awk -F: '{print $2}')
    VER_3=$(echo $VER | awk -F: '{print $3}')
    echo "lib$LIB version at $LAST_RELEASE: $VER"

    # Show current shared library version if changed
    if [ $VER_NOW != $VER ]; then
        echo "lib$LIB version currently: $VER_NOW"
    fi

    # Calculate new library version
    case $CHANGE in
        i|I)
            echo "New backwards-incompatible version: x+1:0:0"
            VER_1=$(expr $VER_1 + 1)
            VER_2=0
            VER_3=0

            # Some headers define constants for shared library names,
            # update them if the name changed
            for H in $HEADERS_EXP; do
                sed -i -e "s/$(shared_lib_name "$LIB" "$VER_NOW")/$(shared_lib_name "$LIB" "$VER_1:0:0")/" $H
            done
            ;;
        c|C)
            echo "New version with backwards-compatible extensions: x+1:0:z+1"
            VER_1=$(expr $VER_1 + 1)
            VER_2=0
            VER_3=$(expr $VER_3 + 1)
            ;;
        F|f)
            echo "Code changed though interfaces didn't: x:y+1:z"
            VER_2=$(expr $VER_2 + 1)
            ;;
        *)
            echo "Not updating lib$LIB version"
            prompt_to_continue
            CHANGE=""
            ;;
    esac
    VER_NEW=$VER_1:$VER_2:$VER_3

    if [ ! -z $CHANGE ]; then
        if [ "$VER_NEW" != "$VER_NOW" ]; then
            echo "Updating lib$LIB version from $VER_NOW to $VER_NEW"
            prompt_to_continue
            sed -i "s/version-info\s*$VER_NOW/version-info $VER_NEW/" $AMFILE
        else
            echo "No version change needed for lib$LIB"
            prompt_to_continue
        fi
    fi
    echo ""
}

echo "Definitions:"
echo "- Compatible additions: new public API functions, structs, etc."
echo "- Incompatible additions/removals: new arguments to public API functions,"
echo "  new members added to the middle of public API structs,"
echo "  removal of any public API, etc."
echo "- Fixes: any other code changes at all"
echo ""
echo "When possible, improve backward compatibility first:"
echo "- move new members to the end of structs"
echo "- use bitfields instead of booleans"
echo "- when adding arguments, create a new function that the old one can wrap"
echo ""
prompt_to_continue

LAST_RELEASE=$(find_last_release "$1")
for LIB in $(find_libs); do
    process_lib "$LIB" "$LAST_RELEASE"
done

# Show all proposed changes
git --no-pager diff --color -w
