#!/bin/sh
#
# Copyright 2018-2020 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.

set -eu
test -d assets && test -d test-2 \
  || { echo 'Run me from source-tree-like location'; exit 1; }
# $1=reference (can be '-' for stdin), $2=investigated
# alt.: wdiff, colordiff, ...
DIFF=${DIFF:-diff}
DIFFOPTS=${DIFFOPTS--u}
DIFFPAGER=${DIFFPAGER:-less -LRX}
# $1=schema, $2=validated
# alt.: jing -i
RNGVALIDATOR=${RNGVALIDATOR:-xmllint --noout --relaxng}
# $1=stylesheet, $2=source
# alt.: Xalan, saxon, sabcmd/Sablotron (note: only validates reliably with -B)
_xalan_wrapper() {
	{ ${_XSLTPROCESSOR} "$2" "$1" 2>&1 >&3 \
	  | sed -e '/^Source tree node.*$/d' \
	        -e 's|^XSLT message: \(.*\) (Occurred.*)|\1|'; } 3>&- 3>&1 >&2
}
# Sablotron doesn't translate '-' file specification to stdin
# and limits the length of the output message
_sabcmd_wrapper() {
	_sabw_sheet=${1:?}
	_sabw_source=${2:?}
	test "${_sabw_sheet}" != - || _sabw_sheet=/dev/stdin
	test "${_sabw_source}" != - || _sabw_source=/dev/stdin
	{ ${_XSLTPROCESSOR} "${_sabw_sheet}" "${_sabw_source}" 2>&1 >&3 \
	  | sed -e '/^Warning \[code:89\]/d' \
	        -e 's|^  xsl:message (\(.*\))$|\1|'; } 3>&- 3>&1 >&2
}
# filtered out message: https://bugzilla.redhat.com/show_bug.cgi?id=1577367
_saxon_wrapper() {
	{ ${_XSLTPROCESSOR} "-xsl:$1" "-s:$2" -versionmsg:off 2>&1 >&3 \
	  | sed -e '/^Cannot find CatalogManager.properties$/d'; } 3>&- 3>&1 >&2
}
XSLTPROCESSOR=${XSLTPROCESSOR:-xsltproc --nonet}
_XSLTPROCESSOR=${XSLTPROCESSOR}
case "${XSLTPROCESSOR}" in
[Xx]alan*|*/[Xx]alan*) XSLTPROCESSOR=_xalan_wrapper;;
sabcmd*|*/sabcmd*)     XSLTPROCESSOR=_sabcmd_wrapper;;
saxon*|*/saxon*)       XSLTPROCESSOR=_saxon_wrapper;;
esac
HTTPPORT=${HTTPPORT:-8000}  # Python's default
WEBBROWSER=${WEBBROWSER:-firefox}

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

# stdin: input file per line
test_browser() {
	_tb_cleanref=0
	_tb_serverpid=

	while test $# -gt 0; do
		case "$1" in
		-r) _tb_cleanref=1;;
		esac
		shift
	done

	if ! read _tb_first; then
		return 1
	fi
	cat >/dev/null 2>/dev/null  # read out the rest

	test -f assets/diffview.js \
	  || curl -SsLo assets/diffview.js \
	     'https://raw.githubusercontent.com/prettydiff/prettydiff/2.2.8/lib/diffview.js'

	{ which python3 >/dev/null 2>/dev/null \
	  && { python3 -m http.server "${HTTPPORT}" -b 127.0.0.1 \
	       || emit_error "Python3 HTTP server fail"; return; } \
	       || emit_error 'Cannot run Python-based HTTP server' ; } &
	_tb_serverpid=$!
	${WEBBROWSER} "http://localhost:${HTTPPORT}/${_tb_first}" &
	printf "When finished, just press Ctrl+C or kill %d, please\n" \
	       "${_tb_serverpid}"
	wait

	test "${_tb_cleanref}" -eq 0 || rm -f assets/diffview.js
}

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

# -a= ... action modifier to derive template name from (if any; enter/leave)
# -o= ... which conventional version to deem as the transform origin
test_selfcheck() {
	_tsc_cleanref=0
	_tsc_ret=0
	_tsc_action=
	_tsc_template=
	_tsc_validator=

	while test $# -gt 0; do
		case "$1" in
		-r) _tsc_cleanref=1;;
		-a=*) _tsc_action="${1#-a=}";;
		-o=*) _tsc_template="${1#-o=}";;
		esac
		shift
	done
	_tsc_validator="${_tsc_template:?}"
	_tsc_validator="cibtr-${_tsc_validator%%.*}.rng"
	_tsc_action=${_tsc_action:+-${_tsc_action}}
	_tsc_template="upgrade-${_tsc_template}${_tsc_action}.xsl"

	# alt. https://relaxng.org/relaxng.rng
        _tsc_rng_relaxng=https://raw.githubusercontent.com/relaxng/relaxng.org/master/relaxng.rng
	# alt. https://github.com/ndw/xslt-relax-ng/blob/master/1.0/xslt10.rnc
	_tsc_rng_xslt=https://raw.githubusercontent.com/relaxng/jing-trang/master/eg/xslt.rng

	case "${RNGVALIDATOR}" in
	*xmllint*)
		test -f "assets/$(basename "${_tsc_rng_relaxng}")" \
		  || curl -SsLo "assets/$(basename "${_tsc_rng_relaxng}")" \
		    "${_tsc_rng_relaxng}"
		test -f "assets/$(basename "${_tsc_rng_xslt}")" \
		  || curl -SsLo "assets/$(basename "${_tsc_rng_xslt}")" \
		    "${_tsc_rng_xslt}"
		test -f assets/xmlcatalog || >assets/xmlcatalog cat <<-EOF
	<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
	<rewriteURI uriStartString="$(dirname "${_tsc_rng_relaxng}")"
	            rewritePrefix="file://$(pwd)/assets"/>
	<rewriteURI uriStartString="$(dirname "${_tsc_rng_xslt}")"
	            rewritePrefix="file://$(pwd)/assets"/>
	</catalog>
EOF
		RNGVALIDATOR=\
"eval env \"XML_CATALOG_FILES=/etc/xml/catalog $(pwd)/assets/xmlcatalog\"
${RNGVALIDATOR}"
		# not needed
		#_tsc_rng_relaxng="assets/$(basename "${_tsc_rng_relaxng}")"
		#_tsc_rng_xslt="assets/$(basename "${_tsc_rng_xslt}")"
	;;
	esac

	# check schema (sub-grammar) for custom transformation mapping alone;
	if test -z "${_tsc_action}" \
	  && ! ${RNGVALIDATOR} "${_tsc_rng_relaxng}" "${_tsc_validator}"; then
		_tsc_ret=$((_tsc_ret + 1))
	fi

	# check the overall XSLT per the main grammar + said sub-grammar;
	test -f "${_tsc_validator}" && _tsc_validator="xslt_${_tsc_validator}" \
	  || _tsc_validator="${_tsc_rng_xslt}"
	if ! ${RNGVALIDATOR} "${_tsc_validator}" "${_tsc_template}"; then
		_tsc_ret=$((_tsc_ret + 1))
	fi

	test "${_tsc_cleanref}" -eq 0 \
	  || rm -f assets/relaxng.rng assets/xslt.rng assets/xmlcatalog

	log2_or_0_return ${_tsc_ret}
}

test_explanation() {
	_tsc_template=

	while test $# -gt 0; do
		case "$1" in
		-o=*) _tsc_template="upgrade-${1#-o=}.xsl";;
		esac
		shift
	done

	${XSLTPROCESSOR} upgrade-detail.xsl "${_tsc_template}"
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
		${XSLTPROCESSOR} "${_tru_template}" "${_tru_source}" \
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
		  | ${XSLTPROCESSOR} "${_tru_template}" - \
		  > "${_tru_target}" 2> "${_tru_target_err}" \
		  || { _tru_ref=$?; echo "${_tru_target_err}"
		       return ${_tru_ref}; }
		# reusing variable no longer needed
		_tru_template="$(dirname "${_tru_target}")"
		_tru_template="${_tru_template}/.$(basename "${_tru_target}")"
		mv "${_tru_target}" "${_tru_template}"
		${XSLTPROCESSOR} - "${_tru_template}" > "${_tru_target}" <<-EOF
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
	# - _tru_mode non-zero (drop internal-only ~ higher bits first)
	# - "-B" in _tru_mode is zero (hence non-zero when flipped with XOR)
	if test "$(((_tru_mode & ((1 << 3) - 1))
			* ((_tru_mode ^ (1 << 2)) & (1 << 2))))" -ne 0; then
		if test $((_tru_mode & (1 << 0))) -ne 0; then
			cp -a "${_tru_target}" "${_tru_ref}"
			cp -a "${_tru_target_err}" "${_tru_ref_err}"
		fi
		if test $((_tru_mode & (1 << 1))) -ne 0; then
			{ "${DIFF}" ${DIFFOPTS} "${_tru_source}" "${_tru_ref}" \
			  && printf '\n(files match)\n'; } | ${DIFFPAGER} >&2
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
		    || ${XSLTPROCESSOR} - "${_tru_ref}" <<-EOF
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

	if test $((_tru_mode & (1 << 3))) -ne 0; then
		# remove ANSI marks (assume no other customization)
		_tru_ref_err=$(mktemp)
		mv "${_tru_target}" "${_tru_ref_err}"
		sed 's/\\x1b[[0-9;]*m//g' "${_tru_ref_err}" > "${_tru_target}"
		rm -f "${_tru_ref_err}"
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

# -a= ... action modifier completing template name (e.g. 2.10-(enter|leave))
# -o= ... which conventional version to deem as the transform origin
# -t= ... which conventional version to deem as the transform target
# -B
# -D
# -G ... see usage
# stdin: input file per line
test_runner() {
	_tr_mode=0
	_tr_ret=0
	_tr_action=
	_tr_schema_o=
	_tr_schema_t=
	_tr_target=
	_tr_template=

	while test $# -gt 0; do
		case "$1" in
		-a=*) _tr_action="${1#-a=}";;
		-o=*) _tr_template="${1#-o=}"
		      _tr_schema_o="pacemaker-${1#-o=}.rng";;
		-t=*) _tr_schema_t="pacemaker-${1#-t=}.rng";;
		-G) _tr_mode=$((_tr_mode | (1 << 0)));;
		-D) _tr_mode=$((_tr_mode | (1 << 1)));;
		-B) _tr_mode=$((_tr_mode | (1 << 2)));;
		-@=*) _tr_mode=$((_tr_mode | ${1#-@=}));;
		esac
		shift
	done
	_tr_template="${_tr_action:-upgrade-${_tr_template:?}}.xsl"

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
# -C
# -S
# -X
# -W ... see usage
# stdin: granular test specification(s) if any
#

test2to3() {
	_t23_cleanopt=
	_t23_pattern=

	while read _t23_spec; do
		_t23_spec=${_t23_spec%.xml}
		_t23_spec=${_t23_spec%\*}
		_t23_pattern="${_t23_pattern} -name ${_t23_spec}*.xml -o"
	done
	test -z "${_t23_pattern}" || _t23_pattern="( ${_t23_pattern%-o} )"
	case " $* " in *\ -r\ *) _t23_cleanopt=-r; esac

	find test-2 -name test-2 -o -type d -prune \
	  -o -name '*.xml' ${_t23_pattern} -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) test_selfcheck -o=2.10 ${_t23_cleanopt};;
	      *\ -X\ *) test_explanation -o=2.10;;
	      *\ -W\ *) test_browser ${_t23_cleanopt};;
	      *) test_runner -o=2.10 -t=3.0 "$@" || return $?;;
	      esac; }
}
tests="${tests} test2to3"

test2to3enter() {
	_t23e_cleanopt=
	_t23e_pattern=

	while read _t23e_spec; do
		_t23e_spec=${_t23e_spec%.xml}
		_t23e_spec=${_t23e_spec%\*}
		_t23e_pattern="${_t23e_pattern} -name ${_t23e_spec}*.xml -o"
	done
	test -z "${_t23e_pattern}" || _t23e_pattern="( ${_t23e_pattern%-o} )"
	case " $* " in *\ -r\ *) _t23e_cleanopt=-r; esac

	find test-2-enter -name test-2-enter -o -type d -prune \
	  -o -name '*.xml' ${_t23e_pattern} -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) test_selfcheck -a=enter -o=2.10 ${_t23e_cleanopt};;
	      *\ -W\ *) emit_result "not implemented" "option -W";;
	      *\ -X\ *) emit_result "not implemented" "option -X";;
	      *) test_runner -a=upgrade-2.10-enter -o=2.10 -t=2.10 "$@" \
	          || return $?;;
	      esac; }
}
tests="${tests} test2to3enter"

test2to3leave() {
	_t23l_cleanopt=
	_t23l_pattern=

	while read _t23l_spec; do
		_t23l_spec=${_t23l_spec%.xml}
		_t23l_spec=${_t23l_spec%\*}
		_t23l_pattern="${_t23l_pattern} -name ${_t23l_spec}*.xml -o"
	done
	test -z "${_t23l_pattern}" || _t23l_pattern="( ${_t23l_pattern%-o} )"
	case " $* " in *\ -r\ *) _t23l_cleanopt=-r; esac

	find test-2-leave -name test-2-leave -o -type d -prune \
	  -o -name '*.xml' ${_t23l_pattern} -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) test_selfcheck -a=leave -o=2.10 ${_t23l_cleanopt};;
	      *\ -W\ *) emit_result "not implemented" "option -W";;
	      *\ -X\ *) emit_result "not implemented" "option -X";;
	      *) test_runner -a=upgrade-2.10-leave -o=3.0 -t=3.0 "$@" \
	          || return $?;;
	      esac; }
}
tests="${tests} test2to3leave"

test2to3roundtrip() {
	_t23rt_cleanopt=
	_t23rt_pattern=

	while read _t23tr_spec; do
		_t23rt_spec=${_t23rt_spec%.xml}
		_t23rt_spec=${_t23rt_spec%\*}
		_t23rt_pattern="${_t23rt_pattern} -name ${_t23rt_spec}*.xml -o"
	done
	test -z "${_t23rt_pattern}" || _t23rt_pattern="( ${_t23rt_pattern%-o} )"
	case " $* " in *\ -r\ *) _t23rt_cleanopt=-r; esac

	find test-2-roundtrip -name test-2-roundtrip -o -type d -prune \
	  -o -name '*.xml' ${_t23rt_pattern} -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) test_selfcheck -a=roundtrip -o=2.10 ${_t23rt_cleanopt};;
	      *\ -W\ *) test_browser ${_t23rt_cleanopt};;
	      *\ -X\ *) emit_result "not implemented" "option -X";;
	      *) test_runner -a=upgrade-2.10-roundtrip -o=2.10 -t=3.0 "$@" \
	          || return $?;;
	      esac; }
}
tests="${tests} test2to3roundtrip"

# just generated the singular + ACLs annotations aware schema clone
access_render_prep() {
	test -s pacemaker-access-3.0.rng || {
	    (
	    export OUTPUTDIR=test-access-render \
	        SKIPSCHEMAS=".*/test-2-render/.*|.*/pacemaker-(3\.[^0]|[^3].*)\.rng"
	    helpers/schema-singularize.sh --clobber
	    )
	    xsltproc helpers/access-render-convert-rng.xsl \
	      test-access-render/pacemaker-3.0.rng > pacemaker-access-3.0.rng
	}

	rm -f test-access-render/pacemaker-3.0.rng
}

# XXX only run with RNGVALIDATOR="jing -i" or xmllint with this patchset:
#     https://gitlab.gnome.org/GNOME/libxml2/merge_requests/31
# XXX also, only XML_CATALOG_FILES env. var. compatible XSLTPROCESSOR will work
access_render() {
	_ar_cleanopt=
	_ar_pattern=
	_ar_catalog=
	_ar_prev_catalog=
	_ar_ret=

	while read _ar_spec; do
		_ar_spec=${_ar_spec%.xml}
		_ar_spec=${_ar_spec%\*}
		_ar_pattern="${_ar_pattern} -name ${_ar_spec}*.xml -o"
	done
	test -z "${_ar_pattern}" || _ar_pattern="( ${_ar_pattern%-o} )"
	case " $* " in *\ -r\ *) _ar_cleanopt=-r; esac

	find test-access-render -name test-access-render -o -type d -prune \
	  -o -name '*.xml' ${_ar_pattern} -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner;;
	      *\ -S\ *) emit_result "not implemented" "option -S";;
	      *\ -W\ *) emit_result "not implemented" "option -W";;
	      *\ -X\ *) emit_result "not implemented" "option -X";;
	      *)
		access_render_prep
		_ar_catalog=$(mktemp)
	>${_ar_catalog} printf "%s\n%s%s\n%s\n%s\n" \
    "<catalog xmlns='urn:oasis:names:tc:entity:xmlns:xml:catalog'>" \
    "  <rewriteURI uriStartString='http://clusterlabs.org/nsredir/pacemaker/cfg'" \
         " rewritePrefix='file://$PWD/base'/>" \
      "'<nextCatalog catalog='file:///etc/xml/catalog'/>" \
    "</catalog>"
		_ar_prev_catalog="${XML_CATALOG_FILES-no}"
		export XML_CATALOG_FILES=${_ar_catalog}
		test_runner -a=base/access-render-2 -o=access-3.0 -t=3.0 \
		            -@=$((1 << 3)) "$@"
		_ar_ret=$?
		if test "${_ar_prev_catalog}" = no; then
			unset XML_CATALOG_FILES
		else
			export XML_CATALOG_FILES="${_ar_prev_catalog}"
		fi
		rm -f "${_ar_catalog}"
		return ${_ar_ret};;
	      esac; }
}
tests="${tests} access_render"

# -B
# -D
# -G ... see usage
cts_scheduler() {
	_tcp_mode=0
	_tcp_ret=0
	_tcp_validatewith=
	_tcp_schema_o=
	_tcp_schema_t=
	_tcp_template=

	find ../cts/scheduler -name scheduler -o -type d -prune \
	  -o -name '*.xml' -print | env LC_ALL=C sort \
	  | { case " $* " in
	      *\ -C\ *) test_cleaner -r;;
	      *\ -S\ *) emit_result "not implemented" "option -S";;
	      *\ -W\ *) emit_result "not implemented" "option -W";;
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
			_tcp_validatewith=$(${XSLTPROCESSOR} - "${_tcp_origin}" <<-EOF
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
	_ts_select_full=
	_ts_test_specs=
	_ts_global_ret=0
	_ts_ret=0

	while test $# -gt 0; do
		case "$1" in
		-) printf '%s\n' 'waiting for tests specified at stdin...';
		   while read _ts_spec; do _ts_select="${_ts_spec}@$1"; done;;
		-*) _ts_pass="${_ts_pass} $1";;
		*) _ts_select_full="${_ts_select_full}@$1"
		   _ts_select="${_ts_select}@${1%%/*}";;
		esac
		shift
	done
	_ts_select="${_ts_select}@"
	_ts_select_full="${_ts_select_full}@"

	for _ts_test in ${tests}; do

		_ts_test_specs=
		while true; do
			case "${_ts_select}" in
			*@${_ts_test}@*)
			_ts_test_specs="${_ts_select%%@${_ts_test}@*}"\
"@${_ts_select#*@${_ts_test}@}"
			if test "${_ts_test_specs}" = @; then
				_ts_select=  # nothing left
			else
				_ts_select="${_ts_test_specs}"
			fi
			continue
			;;
			@) case "${_ts_test}" in test*) break;; esac  # filter
			;;
			esac
			test -z "${_ts_test_specs}" || break
			continue 2  # move on to matching with next local test
		done

		_ts_test_specs=
		while true; do
			case "${_ts_select_full}" in
			*@${_ts_test}/*)
				_ts_test_full="${_ts_test}/${_ts_select_full#*@${_ts_test}/}"
				_ts_test_full="${_ts_test_full%%@*}"
				_ts_select_full="${_ts_select_full%%@${_ts_test_full}@*}"\
"@${_ts_select_full#*@${_ts_test_full}@}"
				_ts_test_specs="${_ts_test_specs} ${_ts_test_full#*/}"
			;;
			*)
			break
			;;
			esac
		done

		for _ts_test_spec in ${_ts_test_specs}; do
			printf '%s\n' "${_ts_test_spec}"
		done | "${_ts_test}" ${_ts_pass} || _ts_ret=$?

		test ${_ts_ret} = 0 \
		  && emit_result ${_ts_ret} "${_ts_test}" \
		  || emit_result "at least 2^$((_ts_ret - 1))" "${_ts_test}"
		log2_or_0_add ${_ts_global_ret} ${_ts_ret}
		_ts_global_ret=$?
	done
	if test -n "${_ts_select#@}"; then
		emit_error "Non-existing test(s):$(echo "${_ts_select}" \
		                                   | tr '@' ' ')"
		log2_or_0_add ${_ts_global_ret} 1 || _ts_global_ret=$?
	fi

	return ${_ts_global_ret}
}

# NOTE: big letters are dedicated for per-test-set behaviour,
#       small ones for generic/global behaviour
usage() {
	printf \
'%s\n%s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n' \
	  "usage: $0 [-{B,C,D,G,S,X}]* \\" \
          "       [-|{${tests## }}*]" \
	  "- when no suites (arguments) provided, \"test*\" ones get used" \
	  "- with '-' suite specification the actual ones grabbed on stdin" \
	  "- use '-B' to run validate-only check suppressing blanks first" \
	  "- use '-C' to only cleanup ephemeral byproducts" \
	  "- use '-D' to review originals vs. \"referential\" outcomes" \
	  "- use '-G' to generate \"referential\" outcomes" \
	  "- use '-S' for template self-check (requires net access)" \
	  "- use '-W' to run browser-based, on-the-fly diff'ing test drive" \
	  "- use '-X' to show explanatory details about the upgrade" \
	  "- some modes (e.g. -{S,W}) take also '-r' for cleanup afterwards" \
	  "- test specification can be granular, e.g. 'test2to3/022'"
	printf \
	  '\n%s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n  %s\n' \
	  'environment variables affecting the run + default/current values:' \
	  "- DIFF (${DIFF}): tool to compute and show differences of 2 files" \
	  "- DIFFOPTS (${DIFFOPTS}): options to the above tool" \
	  "- DIFFPAGER (${DIFFPAGER}): possibly accompanying the above tool" \
	  "- RNGVALIDATOR (${RNGVALIDATOR}): RelaxNG validator" \
	  "- XSLTPROCESSOR (${_XSLTPROCESSOR}): XSLT 1.0 capable processor" \
	  "- HTTPPORT (${HTTPPORT}): port used by test drive HTTP server run" \
	  "- WEBBROWSER (${WEBBROWSER}): used for in-browser test drive"
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
	test ${_main_bailout} -ne 0 \
	  || test_suite -C ${_main_pass} >/dev/null || true
	test ${_main_ret} = 0 && emit_result ${_main_ret} "Overall suite" \
	  || emit_result "at least 2^$((_main_ret - 1))" "Overall suite"

	return ${_main_ret}
}

main "$@"
