#
# Copyright 2021-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

configdir		= @CONFIGDIR@
CONFIGS			= crm_mon pacemaker

if !BUILD_SYSTEMD
initdir			= $(INITDIR)
init_SCRIPTS		= init.d/pacemaker
endif

logrotatedir		= $(sysconfdir)/logrotate.d
logrotate_DATA		= logrotate.d/pacemaker

EXTRA_DIST		= $(foreach f,$(CONFIGS),sysconfig/$(f))

# Don't overwrite user's existing config files
install-data-local:
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(configdir)
	$(AM_V_at)for f in $(CONFIGS); do				\
		dest="$(DESTDIR)$(configdir)/$$f";			\
		[ -e "$$dest" ] && dest="$$dest.new";			\
		$(INSTALL_DATA) "$(srcdir)/sysconfig/$$f" "$$dest";	\
	done

uninstall-local:
	$(AM_V_at)for f in $(CONFIGS); do		\
		dest="$(DESTDIR)$(configdir)/$$f";	\
		rm -f "$$dest" "$$dest.new";		\
	done
