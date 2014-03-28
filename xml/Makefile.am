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

VERSIONED_RNG_FILES	= pacemaker.rng constraints.rng resources.rng acls.rng

RNG_FILES		= $(VERSIONED_RNG_FILES:%.rng=%-1.0.rng)	\
			  $(VERSIONED_RNG_FILES:%.rng=%-1.2.rng)	\
			  $(VERSIONED_RNG_FILES:%.rng=%-next.rng)	\
			  pacemaker.rng versions.rng score.rng rule.rng nvset.rng \
			  fencing.rng

EXTRA_DIST		= crm-1.0.dtd $(dtd_SCRIPTS)
dtd_SCRIPTS		= crm.dtd $(RNG_FILES) upgrade06.xsl upgrade11.xsl crm-transitional.dtd

NEXT ?= $(shell echo $(CRM_DTD_VERSION) | awk -F. '/[0-9]+\./{$$2+=1;OFS=".";print $$1,$$2}')

next:
	echo $(NEXT)

diff:
	for c in `ls -1 *-$(CRM_DTD_VERSION).rng | sed 's/-$(CRM_DTD_VERSION).rng//'`; do diff -u $$c-$(CRM_DTD_VERSION).rng $$c-next.rng ; done 

clone:
	for c in `ls -1 *-$(CRM_DTD_VERSION).rng | sed 's/-$(CRM_DTD_VERSION).rng//'`; do cp $$c-$(CRM_DTD_VERSION).rng $$c-$(NEXT).rng; sed -i 's/$(CRM_DTD_VERSION).rng/$(NEXT).rng/g' $$c-$(NEXT).rng; git add $$c-$(NEXT).rng ; done 

sync:
	for c in `ls -1 *-$(CRM_DTD_VERSION).rng | sed 's/-$(CRM_DTD_VERSION).rng//'`; do cp $$c-$(CRM_DTD_VERSION).rng $$c-next.rng; sed -i 's/$(CRM_DTD_VERSION).rng/next.rng/g' $$c-next.rng; git add $$c-next.rng ; done 

# Fake versioned subschemas not used by anything...
acls-1.0.rng:
	touch $@

crm.dtd: crm-1.0.dtd
	cp $(top_srcdir)/xml/crm-1.0.dtd crm.dtd

pacemaker.rng: pacemaker-$(CRM_DTD_VERSION).rng
	cp $(top_builddir)/xml/$< $@

clean:
	rm -f crm.dtd pacemaker.rng
