#!/bin/sh
# Copyright 2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Substantial part carried over from:
# https://pagure.io/clufter/blob/master/f/misc/pacemaker-borrow-schemas

die() { echo; echo "$@"; exit 1; }

# $1 ... input directory with original pacemaker schemas
# $2 ... output directory with consolidated schemas
# $3 ... schemas to skip (as posix-egrep expression)
# $4 ... clobber existing files?  (true if set and non-null)
singularize() {
	inputdir="${1}"; outputdir="${2}"; skipschemas="${3}"
	test "${#}" -lt 4 || clobber="${4}"
	mkdir -p -- "${outputdir}"
	# for all the schema versions at the boundary of the "major" bump,
	# except for the lower boundary of the first one (i.e. pacemaker-1.0)
	# -- the versions in between are not interesting from validation POV
	for base in $(
	  find "${inputdir}" -type d -name helpers -prune \
	    -o -regextype posix-egrep -regex "${skipschemas}" -prune \
	    -o -name 'pacemaker-*.rng' -printf '%P\n' | sort -V \
	  | sed -e 'N;/^\(pacemaker-[0-9]\)\.\([0-9][0-9]*\)\.rng\n\1\.\([0-9][0-9]*\)\.rng$/!p;D'); do
		f="${inputdir}/${base}"
		printf "processing: ${f} ... "
		test -f "${f}" || continue
		sentinel=10; old=/dev/null; new="${f}"
		# until the jing output converged (simplification gets idempotent)
		# as prescribed by did-size-change heuristic (or sentinel is hit)
		while [ "$(stat -c '%s' "${old}")" != "$(stat -c '%s' "${new}")" ]; do
			[ "$((sentinel -= 1))" -gt 0 ] || break
			[ "${old}" = "${f}" ] && old="${outputdir}/${base}";
			[ "${new}" = "${f}" ] \
			  && { old="${f}"; new="${outputdir}/${base}.new"; } \
			  || cp -f "${new}" "${old}"
			jing -is "${old}" > "${new}"
			#printf "(%d -> %d) " "$(stat -c '%s' "${old}")" "$(stat -c '%s' "${new}")"
		done
		printf "%d iterations\n" "$((10 - ${sentinel}))"
		test -z "${clobber-}" && test -s "${old}" && die "file ${old} already exists" || :
		mv "${new}" "${old}"
	done
}

which jing >/dev/null 2>&1 || die "jing (from jing-trang project) required"

: "${INPUTDIR=$(dirname $0)/..}"
test -n "${INPUTDIR}" || die "Input dir with pacemaker schemas not known"

: "${OUTPUTDIR=schemas-consolidated}"
test -n "${OUTPUTDIR}" || die "Output dir for consolidated schemas not known"

# skip non-defaults of upstream releases
#: "${SKIPSCHEMAS=.*/pacemaker-(1\.0|2\.[126]).rng}"
: "${SKIPSCHEMAS=".*/pacemaker-next\.rng"}"  # only skip WIP schema by default

singularize "${INPUTDIR}" "${OUTPUTDIR}" "${SKIPSCHEMAS}" "${@}"
