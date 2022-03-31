#!/bin/sh
#
# Check public headers for c++ compatibility and consistent protection #ifdefs
#
#

: ${SRCDIR:-..}

INCLUDE_FILES="$(find "${SRCDIR}/include/" -name \*.h \
                      -a \! -name \*internal.h        \
                      -a \! -name config.h            \
                      -a \! -name gettext.h)"

TESTFILE="$(mktemp "${TMPDIR:-/tmp}/test-headers-XXXXXXXXXX.c")"

for i in $INCLUDE_FILES
do
    NAME="$(echo $i | sed -e 's#^.*/include/##')"
    PROTECT="PCMK__$(echo "$NAME" | tr '[:lower:]/\-\.' '[:upper:]___' | sed 's/_H$/__H/')"

    cat >"$TESTFILE" <<EOF
#include <$NAME>
#ifndef $PROTECT
#error no header protector in file $i
#endif
int main(void) {return 0;}
EOF

    # Not including ${CFLAGS} because it seems to break header detection. But we're not really building here
    ${CC} -I "${SRCDIR}/include" -DHAVE_CONFIG_H ${CPPFLAGS} ${LIBS} "$TESTFILE" -o /dev/null
    if [ $? -ne 0 ]
    then
        rm -f "$TESTFILE"
        exit 1
    fi
    if [ "$CXX" ] && [ command -v "$CXX" >/dev/null 2>&1 ]
    then
        ${CXX} ${CXXFLAGS} ${CPPFLAGS} ${LIBS} -I "${SRCDIR}/include" "$TESTFILE" -o /dev/null
        if [ $? -ne 0 ]
        then
            rm -f "$TESTFILE"
            exit 1
        fi
        echo -n
    fi
    rm -f "$TESTFILE"
done
