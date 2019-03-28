#!/usr/bin/env sh
set -eu
exec <&-
_tmpdir=$(mktemp -d /tmp/coccicheck-XXXXXX)
_bname=$(basename "$1")
_dname=$(dirname "$1")
sed -n '/#if 00/{n;:l;/#else/q;p;n;bl;}' "$1"> "${_tmpdir}/exp"
spatch --very-quiet --sp-file "${_dname}/../${_bname%.c}.cocci" "$1" \
  | tail -n+3 > "${_tmpdir}/out"
diff -u "${_tmpdir}/exp" "${_tmpdir}/out"
rm "${_tmpdir}"/*
rmdir "${_tmpdir}"
