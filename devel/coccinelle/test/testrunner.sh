#!/bin/sh
set -eu
_tmpdir=$(mktemp -d /tmp/coccicheck-XXXXXX)
_bname=$(basename "$1" .input.c)
_dname=$(dirname "$1")
spatch --very-quiet --sp-file "${_dname}/../${_bname}.cocci" "$1" \
  | tail -n+3 > "${_tmpdir}/out"
diff -u "${_dname}/${_bname}.output" "${_tmpdir}/out"

if [ -d "${_tmpdir}" ]; then
    rm "${_tmpdir}"/*
    rmdir "${_tmpdir}"
fi
