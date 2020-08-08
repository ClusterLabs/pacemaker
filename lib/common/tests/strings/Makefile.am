AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
LDADD = $(top_builddir)/lib/common/libcrmcommon.la

include $(top_srcdir)/mk/glib-tap.mk

# Add each test program here.  Each test should be written as a little standalone
# program using the glib unit testing functions.  See the documentation for more
# information.
#
# https://developer.gnome.org/glib/unstable/glib-Testing.html
test_programs = pcmk__scan_double \
				pcmk__parse_ll_range \
				pcmk__str_any_of \
				pcmk__strcmp

# If any extra data needs to be added to the source distribution, add it to the
# following list.
dist_test_data =

# If any extra data needs to be used by tests but should not be added to the
# source distribution, add it to the following list.
test_data =
