#
# Copyright 2008-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

EXTRA_DIST		= $(ocf_SCRIPTS)


isolationtechdir    = @OCF_RA_DIR@/.isolation

ocfdir			= @OCF_RA_DIR@/pacemaker
dist_ocf_SCRIPTS	= attribute	\
			  ClusterMon	\
			  controld	\
			  Dummy		\
			  HealthCPU	\
			  HealthSMART	\
			  ifspeed	\
			  o2cb		\
			  ping		\
			  pingd		\
			  remote	\
			  Stateful	\
			  SysInfo	\
			  SystemHealth

dist_isolationtech_SCRIPTS	= docker-wrapper

if BUILD_XML_HELP

man7_MANS = $(ocf_SCRIPTS:%=ocf_pacemaker_%.7) $(dist_ocf_SCRIPTS:%=ocf_pacemaker_%.7)
DBOOK_OPTS = --stringparam command.prefix ocf_pacemaker_ --stringparam variable.prefix OCF_RESKEY_ --param man.vol 7

ocf_pacemaker_%.xml:  %
	$(AM_V_GEN)OCF_FUNCTIONS=/dev/null OCF_ROOT=$(OCF_ROOT_DIR) $(abs_builddir)/$< meta-data > $@

endif

clean-generic:
	rm -f $(man7_MANS) $(ocf_SCRIPTS:%=%.xml) $(dist_ocf_SCRIPTS:%=%.xml) *~
