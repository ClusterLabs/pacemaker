#
# Copyright 2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
#

#BASED_LDFLAGS = $$(pkgconf -libs glib-2.0) \
#	$$(pkgconf -libs libxml-2.0) \
#	$$(pkgconf -libs libqb) \
#	$$(pkgconf -libs pacemaker)
BASED_LDFLAGS = $$(pkgconf -libs glib-2.0) \
	$$(pkgconf -libs libxml-2.0) \
	$$(pkgconf -libs libqb) \
	-Wl,-rpath=$(CURDIR)/../../lib/common/.libs \
	  -L../../lib/common/.libs -lcrmcommon \
	  -L../../lib/pacemaker/.libs -lpacemaker

BASED_CPPFLAGS = $$(pkgconf -cflags glib-2.0) \
	$$(pkgconf -cflags libxml-2.0) \
	$$(pkgconf -cflags libqb) \
	-I ../.. -I ../../include -g

PROGRAMS = based

BASED_OBJECTS = based.o

# include or not the modules as you wish
BASED_OBJECTS += based-notifyfenced.o

all: ${PROGRAMS}

based: $(BASED_OBJECTS)
	$(CC) $(BASED_LDFLAGS) $^ -o $@

$(BASED_OBJECTS): %.o: %.c
	$(CC) $(BASED_CPPFLAGS) $(BASED_LDFLAGS) -c $< -o $@

clean:
	rm ${PROGRAMS} $(BASED_OBJECTS)
