#
# Copyright 2008-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

ocfdir			= @OCF_RA_INSTALL_DIR@/pacemaker
dist_ocf_SCRIPTS	= attribute	\
			  controld	\
			  Dummy		\
			  HealthCPU	\
			  HealthIOWait	\
			  ping		\
			  remote	\
			  Stateful
ocf_SCRIPTS		= ClusterMon	\
			  HealthSMART	\
			  ifspeed	\
			  o2cb		\
			  SysInfo

if BUILD_XML_HELP

man7_MANS = $(ocf_SCRIPTS:%=ocf_pacemaker_%.7) $(dist_ocf_SCRIPTS:%=ocf_pacemaker_%.7)
DBOOK_OPTS = --stringparam command.prefix ocf_pacemaker_ --stringparam variable.prefix OCF_RESKEY_ --param man.vol 7

ocf_pacemaker_%.xml:  %
	$(AM_V_GEN)OCF_FUNCTIONS=/dev/null OCF_ROOT=$(OCF_ROOT_DIR) $(abs_builddir)/$< meta-data > $@

endif


# Pass correct local values to validate target manually
RNG		:= /dev/null
OCF_ROOT	:= /usr/lib/ocf

.PHONY: validate
validate: all
	@cat "$(RNG)" >/dev/null 2>/dev/null || { echo "Must specify valid RNG" && false; }
	@[ -x "$(OCF_ROOT)/lib/heartbeat" ] || { echo "Must specify valid OCF_ROOT" && false; }
	@for AGENT in $(dist_ocf_SCRIPTS) $(ocf_SCRIPTS); do		\
		echo -e "\n\n## $$AGENT:";				\
		OCF_ROOT="$(OCF_ROOT)" "$(builddir)/$$AGENT" meta-data	\
			| xmllint --noout --relaxng $(RNG) - || break;	\
	done

CLEANFILES = $(man7_MANS) $(ocf_SCRIPTS:%=%.xml) $(dist_ocf_SCRIPTS:%=%.xml)
