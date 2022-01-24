# tap-test is copied from /usr/share/automake-*/tap-driver.sh.
EXTRA_DIST = tap-driver.sh \
	     tap-test \
	     test-headers.sh

check: check-headers

.PHONY: check-headers
check-headers:
	cd $(abs_srcdir); \
	CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" CC="$(CC)" CXX="$(CXX)" CPPFLAGS="$(CPPFLAGS)" LIBS="$(LIBS)" sh test-headers.sh
