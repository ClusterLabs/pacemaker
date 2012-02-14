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

VERSIONED_RNG_FILES	= pacemaker.rng constraints.rng resources.rng 

RNG_FILES		= $(VERSIONED_RNG_FILES:%.rng=%-1.0.rng)	\
			  $(VERSIONED_RNG_FILES:%.rng=%-1.1.rng)	\
			  $(VERSIONED_RNG_FILES:%.rng=%-1.2.rng)	\
			  pacemaker.rng versions.rng score.rng rule.rng nvset.rng \
			  acls-1.1.rng acls-1.2.rng fencing.rng

EXTRA_DIST		= crm-1.0.dtd $(dtd_SCRIPTS)
dtd_SCRIPTS		= crm.dtd $(RNG_FILES) upgrade06.xsl crm-transitional.dtd

crm.dtd: crm-1.0.dtd
	cp $(top_srcdir)/xml/crm-1.0.dtd crm.dtd

pacemaker.rng: pacemaker-$(CRM_DTD_VERSION).rng
	cp $(top_builddir)/xml/$< $@

clean:
	rm -f crm.dtd pacemaker.rng
