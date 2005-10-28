#
# Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

testdir			= $(libdir)/heartbeat/crmtest
test_SCRIPTS		= helper.sh testutils.pl stop.sh  cib_suite.sh \
			1node.sh 2node.sh 2node-fail.sh 2node-empty.sh \
			2node-fence.sh 3node.sh 3node-rapid.sh 3node-fail.sh \
			extract.logs

install-data-local:
	-chown $(HA_CCMUSER) $(DESTDIR)/$(testdir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(testdir)
	-chmod g+w $(DESTDIR)/$(testdir)
