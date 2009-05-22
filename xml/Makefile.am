#
# Copyright (C) 2004 Andrew Beekhof
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


dtddir			= $(CRM_DTD_DIRECTORY)

RNG_FILES		= pacemaker.rng constraints.rng nvset.rng resources.rng rule.rng 
VERSIONED_RNG_FILES	= $(RNG_FILES:%.rng=%-$(CRM_DTD_VERSION).rng)

EXTRA_DIST		= crm-1.0.dtd pacemaker.rng.in $(RNG_FILES)
dtd_SCRIPTS		= crm.dtd pacemaker.rng $(VERSIONED_RNG_FILES) score.rng upgrade06.xsl crm-transitional.dtd

crm.dtd: crm-1.0.dtd
	cp $(top_builddir)/xml/crm-1.0.dtd crm.dtd

%-$(CRM_DTD_VERSION).rng: %.rng
	cp $(top_builddir)/xml/$< $@

clean:
	rm -f crm.dtd $(VERSIONED_RNG_FILES)
