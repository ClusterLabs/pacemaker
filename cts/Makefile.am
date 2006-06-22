#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
MAINTAINERCLEANFILES    = Makefile.in

harddir			= $(libdir)/heartbeat/cts

hard_SCRIPTS	=				\
			CM_fs.py		\
			CM_hb.py		\
			CM_LinuxHAv2.py		\
			CTS.py			\
			CTSaudits.py		\
			CTSlab.py		\
			CTSproxy.py		\
			CTStests.py		\
			extracttests.py		\
			OCFIPraTest.py		\
			CIB.py

hard_DATA =		README

ocfdir			=	$(libdir)/heartbeat/cts
ocf_SCRIPTS		=	OCFMSDummy

lsbdir			=	$(libdir)/heartbeat/cts
lsb_SCRIPTS		=	LSBDummy
			
## Python scripts *.py can generate *.pyc and *.pyo alongside.
## Should remove these on "uninstall".
##
## This code was copied, with adaptation, from the expansion in "Makefile.in"
## of the corresponding code to uninstall "hard_SCRIPTS".
uninstall-hook:
	@$(NORMAL_UNINSTALL)
	@list='$(hard_SCRIPTS)'; for p in $$list; do \
	  f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	  fc="$${f}c"; \
	  fo="$${f}o"; \
	  echo " rm -f '$(DESTDIR)$(harddir)/$$fc'"; \
	  rm -f "$(DESTDIR)$(harddir)/$$fc"; \
	  echo " rm -f '$(DESTDIR)$(harddir)/$$fo'"; \
	  rm -f "$(DESTDIR)$(harddir)/$$fo"; \
	done
