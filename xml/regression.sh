#!/bin/sh
# Copyright 2018 Red Hat, Inc.
# Author: Jan Pokorny <jpokorny@redhat.com>
# Part of pacemaker project
# SPDX-License-Identifier: GPL-2.0-or-later

set -eu
# $1=reference (can be '-' for stdin), $2=investigated
# alt.: wdiff, colordiff, ...
DIFF=${DIFF:-diff}
DIFFOPTS=${DIFFOPTS--u}
DIFFPAGER=${DIFFPAGER:-less -LRX}
# $1=schema, $2=validated
# alt.: jing -i
RNGVALIDATOR=${RNGVALIDATOR:-xmllint --noout --relaxng}
tests=  # test* names (should go first) here will become preselected default

#
# commons
#

emit_result() {
	_er_howmany=${1:?}  # how many errors (0/anything else incl. strings)
	_er_subject=${2:?}
	_er_prefix=${3-}

	test -z "${_er_prefix}" || _er_prefix="${_er_prefix}: "

	if test "${_er_howmany}" = 0; then
		printf "%s%s finished OK\n" "${_er_prefix}" "${_er_subject}"
	else
		printf "%s%s encountered ${_er_howmany} errors\n" \
		       "${_er_prefix}" "${_er_subject}"
	fi
}

emit_error() {
	_ee_msg=${1:?}
	printf "%s\n" "${_ee_msg}" >&2
}

# returns 1 + floor of base 2 logaritm for _lo0r_i in 1...255,
# or 0 for _lo0r_i = 0
log2_or_0_return() {
	_lo0r_i=${1:?}
	return $(((!(_lo0r_i >> 1) && _lo0r_i) * 1 \
                + (!(_lo0r_i >> 2) && _lo0r_i & (1 << 1)) * 2 \
                + (!(_lo0r_i >> 3) && _lo0r_i & (1 << 2)) * 3 \
                + (!(_lo0r_i >> 4) && _lo0r_i & (1 << 3)) * 4 \
                + (!(_lo0r_i >> 5) && _lo0r_i & (1 << 4)) * 5 \
                + (!(_lo0r_i >> 6) && _lo0r_i & (1 << 5)) * 6 \
                + (!(_lo0r_i >> 7) && _lo0r_i & (1 << 6)) * 7 \
                + !!(_lo0r_i >> 7) * 7 ))
}

# rough addition of two base 2 logarithms
log2_or_0_add() {
	_lo0a_op1=${1:?}
	_lo0a_op2=${2:?}

	if test ${_lo0a_op1} -gt ${_lo0a_op2}; then
		return ${_lo0a_op1}
	elif test ${_lo0a_op2} -gt ${_lo0a_op1}; then
		return ${_lo0a_op2}
	elif test ${_lo0a_op1} -gt 0; then
		return $((_lo0a_op1 + 1))
	else
		return ${_lo0a_op1}
	fi
}

#
# test phases
#

# -r ... whether to remove referential files as well
# stdin: input file per line
test_cleaner() {
	_tc_cleanref=0

	while test $# -gt 0; do
		case "$1" in
		-r) _tc_cleanref=1;;
		esac
		shift
	done

	while read _tc_origin; do
		_tc_origin=${_tc_origin%.*}
		rm -f "${_tc_origin}.up" "${_tc_origin}.up.err"
		rm -f "$(dirname "${_tc_origin}")/.$(basename "${_tc_origin}").up"
		test ${_tc_cleanref} -eq 0 \
		  || rm -f "${_tc_origin}.ref" "${_tc_origin}.ref.err"
	done
}

test_selfcheck() {
	_tsc_template=
	_tsc_validator=

	while test $# -gt 0; do
		case "$1" in
		-o=*) _tsc_template="${1#-o=}";;
		esac
		shift
	done
	_tsc_validator="${_tsc_template:?}"
	_tsc_validator="cibtr-${_tsc_validator%%.*}.rng"
	_tsc_template="upgrade-${_tsc_template}.xsl"

	# check schema (sub-grammar) for custom transformation mapping alone
	${RNGVALIDATOR} 'http://relaxng.org/relaxng.rng' "${_tsc_validator}"
	# check the overall XSLT per the main grammar + said sub-grammar
	${RNGVALIDATOR} "xslt_${_tsc_validator}" "${_tsc_template}"
}

test_explanation() {
	_tsc_template=

	while test $# -gt 0; do
		case "$1" in
		-o=*) _tsc_template="upgrade-${1#-o=}.xsl";;
		esac
		shift
	done

	xsltproc upgrade-detail.xsl "${_tsc_template}"
}

# stdout: filename of the transformed file
test_runner_upgrade() {
	_tru_template=${1:?}
	_tru_source=${2:?}  # filename
	_tru_mode=${3:?}  # extra modes wrt. "referential" outcome, see below

	_tru_ref="${_tru_source%.*}.ref"
        { test "$((_tru_mode & (1 << 0)))" -ne 0 \
	  || test -f "${_tru_ref}.err"; } \
	  && _tru_ref_err="${_tru_ref}.err" || _tru_ref_err=/dev/null
	_tru_target="${_tru_source%.*}.up"
	_tru_target_err="${_tru_target}.err"

	if test $((_tru_mode & (1 << 2))) -eq 0; then
		xsltproc "${_tru_template}" "${_tru_source}" \
		  > "${_tru_target}" 2> "${_tru_target_err}" \
		  || { _tru_ref=$?; echo "${_tru_target_err}"
		       return ${_tru_ref}; }
	else
		# when -B (deblanked outcomes handling) requested, we:
		# - drop blanks from the source XML
		#   (effectively emulating pacemaker handling)
		# - re-drop blanks from the XSLT outcome,
		#   which is compared with referential outcome
		#   processed with even greedier custom deblanking
		#   (extraneous inter-element whitespace like blank
		#   lines will not get removed otherwise, see lower)
		xmllint --noblanks "${_tru_source}" \
		  | xsltproc "${_tru_template}" - \
		  > "${_tru_target}" 2> "${_tru_target_err}" \
		  || { _tru_ref=$?; echo "${_tru_target_err}"
		       return ${_tru_ref}; }
		# reusing variable no longer needed
		_tru_template="$(dirname "${_tru_target}")"
		_tru_template="${_tru_template}/.$(basename "${_tru_target}")"
		mv "${_tru_target}" "${_tru_template}"
		xsltproc - "${_tru_template}" > "${_tru_target}" <<-EOF
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="xml" encoding="UTF-8" omit-xml-declaration="yes"/>
	<xsl:template match="@*|*|comment()|processing-instruction()">
	  <xsl:copy>
	    <xsl:apply-templates select="@*|node()"/>
	  </xsl:copy>
	</xsl:template>
	<xsl:template match="text()">
	  <xsl:value-of select="normalize-space(.)"/>
	</xsl:template>
	</xsl:stylesheet>
EOF
	fi

	# only respond with the flags except for "-B", i.e., when both:
	# - _tru_mode non-zero
	# - "-B" in _tru_mode is zero (hence non-zero when flipped with XOR)
	if test "$((_tru_mode * ((_tru_mode ^ (1 << 2)) & (1 << 2))))" -ne 0; then
		if test $((_tru_mode & (1 << 0))) -ne 0; then
			cp -a "${_tru_target}" "${_tru_ref}"
			cp -a "${_tru_target_err}" "${_tru_ref_err}"
		fi
		if test $((_tru_mode & (1 << 1))) -ne 0; then
			"${DIFF}" ${DIFFOPTS} "${_tru_source}" "${_tru_ref}" \
			  | ${DIFFPAGER} >&2
			if test $? -ne 0; then
				printf "\npager failure\n" >&2
				return 1
			fi
			printf '\nIs comparison OK? ' >&2
			if read _tru_answer </dev/tty; then
				case "${_tru_answer}" in
				y|yes) ;;
				*) echo "Answer not 'y' nor 'yes'" >&2; return 1;;
				esac
			else
				return 1
			fi
		fi
	elif test -f "${_tru_ref}" && test -e "${_tru_ref_err}"; then
		{ test "$((_tru_mode & (1 << 2)))" -eq 0 && cat "${_tru_ref}" \
		    || xsltproc - "${_tru_ref}" <<-EOF
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="xml" encoding="UTF-8" omit-xml-declaration="yes"/>
	<xsl:template match="@*|*|comment()|processing-instruction()">
	  <xsl:copy>
	    <xsl:apply-templates select="@*|node()"/>
	  </xsl:copy>
	</xsl:template>
	<xsl:template match="text()">
	  <xsl:value-of select="normalize-space(.)"/>
	</xsl:template>
	</xsl:stylesheet>
EOF
		} \
		  | "${DIFF}" ${DIFFOPTS} - "${_tru_target}" >&2 \
		  && "${DIFF}" ${DIFFOPTS} "${_tru_ref_err}" \
		       "${_tru_target_err}" >&2
		if test $? -ne 0; then
			emit_error "Outputs differ from referential ones"
			echo "/dev/null"
			return 1
		fi
	else
		emit_error "Referential file(s) missing: ${_tru_ref}"
		echo "/dev/null"
		return 1
	fi

	echo "${_tru_target}"
}

test_runner_validate() {
	_trv_schema=${1:?}
	_trv_target=${2:?}  # filename

	if ! ${RNGVALIDATOR} "${_trv_schema}" "${_trv_target}" \
	    2>/dev/null; then
		${RNGVALIDATOR} "${_trv_schema}" "${_trv_target}"
	fi
}

# -o= ... which conventional version to deem as the transform origin
# -t= ... which conventional version to deem as the transform target
# -B
# -D
# -G  ... see usage
# stdin: input file per line
test_runner() {
	_tr_mode=0
	_tr_ret=0
	_tr_schema_o=
	_tr_schema_t=
	_tr_target=
	_tr_template=

	while test $# -gt 0; do
		case "$1" in
		-o=*) _tr_template="upgrade-${1#-o=}.xsl"
		      _tr_schema_o="pacemaker-${1#-o=}.rng";;
		-t=*) _tr_schema_t="pacemaker-${1#-t=}.rng";;
		-G) _tr_mode=$((_tr_mode | (1 << 0)));;
		-D) _tr_mode=$((_tr_mode | (1 << 1)));;
		-B) _tr_mode=$((_tr_mode | (1 << 2)));;
		esac
		shift
	done

	if ! test -f "${_tr_schema_o:?}" || ! test -f "${_tr_schema_t:?}"; then
		emit_error "Origin and/or target schema missing, rerun make"
		return 1
	fi

	while read _tr_origin; do
		printf '%-60s' "${_tr_origin}... "

		# pre-validate
		if ! test_runner_validate "${_tr_schema_o}" "${_tr_origin}"; then
			_tr_ret=$((_tr_ret + 1)); echo "E:pre-validate"; continue
		fi

		# upgrade
		if ! _tr_target=$(test_runner_upgrade "${_tr_template}" \
		                 "${_tr_origin}" "${_tr_mode}"); then
			_tr_ret=$((_tr_ret + 1));
			test -n "${_tr_target}" || break
			echo "E:upgrade"
			test -s "${_tr_target}" \
			  && { echo ---; cat "${_tr_target}" || :; echo ---; }
			continue
		fi

		# post-validate
		if ! test_runner_validate "${_tr_schema_t}" "${_tr_target}"; then
			_tr_ret=$((_tr_ret + 1)); echo "E:post-validate"; continue
		fi

		echo "OK"
	done

	log2_or_0_return ${_tr_ret}
}

#
# particular test variations
#

test2to3() {
	find test-2 -name '*.xml' -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) test_selfcheck -o=2.10;;
	      *\ -X\ *) test_explanation -o=2.10;;
	      *) test_runner -o=2.10 -t=3.0 "$@" || return $?;;
	      esac; }
}
tests="${tests} test2to3"

# -B
# -D
# -G  ... see usage
cts_scheduler() {
	_tcp_mode=0
	_tcp_ret=0
	_tcp_validatewith=
	_tcp_schema_o=
	_tcp_schema_t=
	_tcp_template=

	find ../cts/scheduler -name '*.xml' -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner -r;;
	      *\ -S\ *) emit_result "not implemented" "option -S";;
	      *\ -X\ *) emit_result "not implemented" "option -X";;
	      *)
		while test $# -gt 0; do
			case "$1" in
			-G) _tcp_mode=$((_tcp_mode | (1 << 0)));;
			-D) _tcp_mode=$((_tcp_mode | (1 << 1)));;
			-B) _tcp_mode=$((_tcp_mode | (1 << 2)));;
			esac
			shift
		done
		while read _tcp_origin; do
			_tcp_validatewith=$(xsltproc - "${_tcp_origin}" <<-EOF
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="text" encoding="UTF-8"/>
	<xsl:template match="/">
	  <xsl:choose>
	    <xsl:when test="starts-with(cib/@validate-with, 'pacemaker-')">
	      <xsl:variable name="Version" select="substring-after(cib/@validate-with, 'pacemaker-')"/>
	      <xsl:choose>
	        <xsl:when test="contains(\$Version, '.')">
	          <xsl:value-of select="substring-before(\$Version, '.')"/>
	        </xsl:when>
	        <xsl:otherwise>
	          <xsl:value-of select="cib/@validate-with"/>
	        </xsl:otherwise>
	      </xsl:choose>
	    </xsl:when>
	    <xsl:otherwise>
	     <xsl:value-of select="cib/@validate-with"/>
	    </xsl:otherwise>
	  </xsl:choose>
	</xsl:template>
	</xsl:stylesheet>
EOF
)
			_tcp_schema_t=${_tcp_validatewith}
			case "${_tcp_validatewith}" in
			1) _tcp_schema_o=1.3;;
			2) _tcp_schema_o=2.10;;
			# only for gradual refinement as upgrade-2.10.xsl under
			# active development, move to 3.x when schema v4 emerges
			3) _tcp_schema_o=2.10
			   _tcp_schema_t=2;;
			*) emit_error \
			   "need to skip ${_tcp_origin} (schema: ${_tcp_validatewith})"
			   continue;;
			esac
			_tcp_template="upgrade-${_tcp_schema_o}.xsl"
			_tcp_schema_t="pacemaker-$((_tcp_schema_t + 1)).0.rng"
			test "${_tcp_schema_o%%.*}" = "${_tcp_validatewith}" \
			  && _tcp_schema_o="pacemaker-${_tcp_schema_o}.rng" \
			  || _tcp_schema_o="${_tcp_schema_t}"

			# pre-validate
			if test "${_tcp_schema_o}" != "${_tcp_schema_t}" \
			  && ! test_runner_validate "${_tcp_schema_o}" "${_tcp_origin}"; then
				_tcp_ret=$((_tcp_ret + 1)); echo "E:pre-validate"; continue
			fi

			# upgrade
			test "$((_tcp_mode & (1 << 0)))" -ne 0 \
			  || ln -fs "$(pwd)/${_tcp_origin}" "${_tcp_origin%.*}.ref"
			if ! _tcp_target=$(test_runner_upgrade "${_tcp_template}" \
			                   "${_tcp_origin}" "${_tcp_mode}"); then
				_tcp_ret=$((_tcp_ret + 1));
				test -n "${_tcp_target}" || break
				echo "E:upgrade"
				test -s "${_tcp_target}" \
				  && { echo ---; cat "${_tcp_target}" || :; echo ---; }
				continue
			fi
			test "$((_tcp_mode & (1 << 0)))" -ne 0 \
			  || rm -f "${_tcp_origin%.*}.ref"

			# post-validate
			if ! test_runner_validate "${_tcp_schema_t}" "${_tcp_target}"; then
				_tcp_ret=$((_tcp_ret + 1)); echo "E:post-validate"; continue
			fi

			test "$((_tcp_mode & (1 << 0)))" -eq 0 \
			  || mv "${_tcp_target}" "${_tcp_origin}"
		done; log2_or_0_return ${_tcp_ret};;
	      esac; }
}
tests="${tests} cts_scheduler"

#
# "framework"
#

# option-likes ... options to be passed down
# argument-likes ... drives a test selection
test_suite() {
	_ts_pass=
	_ts_select=
	_ts_global_ret=0
	_ts_ret=0

	while test $# -gt 0; do
		case "$1" in
		-) while read _ts_spec; do _ts_select="${_ts_spec}@$1"; done;;
		-*) _ts_pass="${_ts_pass} $1";;
		*) _ts_select="${_ts_select}@$1";;
		esac
		shift
	done
	_ts_select="${_ts_select}@"

	for _ts_test in ${tests}; do

		case "${_ts_select}" in
		*@${_ts_test}@*)
		_ts_select="${_ts_select%@${_ts_test}@*}@${_ts_select#*@${_ts_test}@}"
		;;
		@) case "${_ts_test}" in test*) ;; *) continue;; esac
		;;
		*) continue;;
		esac

		"${_ts_test}" ${_ts_pass} || _ts_ret=$?
		test ${_ts_ret} = 0 \
		  && emit_result ${_ts_ret} "${_ts_test}" \
		  || emit_result "at least 2^$((_ts_ret - 1))" "${_ts_test}"
		log2_or_0_add ${_ts_global_ret} ${_ts_ret}
		_ts_global_ret=$?
	done
	if test "${_ts_select}" != @; then
		emit_error "Non-existing test(s):$(echo "${_ts_select}" \
		                                   | tr '@' ' ')"
		log2_or_0_add ${_ts_global_ret} 1 || _ts_global_ret=$?
	fi

	return ${_ts_global_ret}
}

# NOTE: big letters are dedicated for per-test-set behaviour,
#       small ones for generic/global behaviour
usage() {
	printf '%s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n' \
	    "usage: $0 [-{B,C,D,G,S,X}]* [-|{${tests## }}*]" \
	    "- when no suites (arguments) provided, \"test*\" ones get used" \
	    "- with '-' suite specification the actual ones grabbed on stdin" \
	    "- use '-B' to run validate-only check suppressing blanks first" \
	    "- use '-C' to only cleanup ephemeral byproducts" \
	    "- use '-D' to review originals vs. \"referential\" outcomes" \
	    "- use '-G' to generate \"referential\" outcomes" \
	    "- use '-S' for template self-check (requires net access)" \
	    "- use '-X' to show explanatory details about the upgrade"
}

main() {
	_main_pass=
	_main_bailout=0
	_main_ret=0

	while test $# -gt 0; do
		case "$1" in
		-h) usage; exit;;
		-C|-G|-S|-X) _main_bailout=1;;
		esac
		_main_pass="${_main_pass} $1"
		shift
	done

	test_suite ${_main_pass} || _main_ret=$?
	test ${_main_bailout} -eq 1 && return ${_main_ret} \
	  || test_suite -C ${_main_pass} >/dev/null || true
	test ${_main_ret} = 0 && emit_result ${_main_ret} "Overall suite" \
	  || emit_result "at least 2^$((_main_ret - 1))" "Overall suite"

	return ${_main_ret}
}

main "$@"
