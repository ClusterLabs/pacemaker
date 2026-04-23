#!/bin/sh
#
# Copyright 2022-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

#
# Check public headers for C++ compatibility and consistent protection #ifdefs
#

: ${SRCDIR:-..}

INCLUDE_FILES="$(find "${SRCDIR}/include/" "${SRCDIR}/lib/" -name \*.h \
                      -a \! -name config.h            \
                      -a \! -name gettext.h)"

# *BSD mktemp supports X's only at end of name
TESTFILE="$(mktemp "${TMPDIR:-/tmp}/test-headers-XXXXXXXXXX")"
if [ $? -ne 0 ]; then
    echo "Could not create temporary file"
    exit 1
fi
mv "$TESTFILE" "${TESTFILE}.c"
TESTFILE="${TESTFILE}.c"

for i in $INCLUDE_FILES
do
    NAME="$(echo $i | sed -e 's#^.*/include/##' | sed -e 's#^.*/lib/##')"
    PROTECT="PCMK__$(echo "$NAME" | tr '[:lower:]/\-\.' '[:upper:]___' | sed 's/_H$/__H/')"

    cat >"$TESTFILE" <<EOF
#define PCMK__INCLUDED_PACEMAKER_INTERNAL_H
#define PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#include <$NAME>
#ifndef $PROTECT
#error no $PROTECT header protector in file $i
#endif
int main(void) {return 0;}
EOF

    # Not including ${CFLAGS} because it seems to break header detection. But we're not really building here
    ${CC} -I "${SRCDIR}/include" -I"${SRCDIR}/lib" \
        -DHAVE_CONFIG_H ${CPPFLAGS} ${LIBS} "$TESTFILE" -o /dev/null
    if [ $? -ne 0 ]
    then
        rm -f "$TESTFILE"
        exit 1
    fi
    if [ -n "$CXX" ] && [ command -v "$CXX" >/dev/null 2>&1 ]
    then
        ${CXX} ${CXXFLAGS} ${CPPFLAGS} ${LIBS} \
            -I "${SRCDIR}/include" -I"${SRCDIR}/lib" "$TESTFILE" -o /dev/null
        if [ $? -ne 0 ]
        then
            rm -f "$TESTFILE"
            exit 1
        fi
        echo -n
    fi
    rm -f "$TESTFILE"
done
