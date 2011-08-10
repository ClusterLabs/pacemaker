bin_PROGRAMS = ccs_flatten disable_rgmanager ccs2cib
ccs_flatten_SOURCES = reslist.c resrules.c restree.c flatten.c \
		      xmlconf.c
disable_rgmanager_SOURCES = disable_rgmanager.c

dist_pkgdata_DATA = cluconf2cib.xsl

ccs2cib: ccs2cib.in
	echo "#!/bin/sh" > $@
	echo >> $@
	echo XSL_FILE=\"$(pkgdatadir)\" >> $@
	echo SAXON_JAR=\"$(datadir)/java/saxon.jar\" >> $@
	echo >> $@
	cat $^ >> $@
	chmod +X $@

