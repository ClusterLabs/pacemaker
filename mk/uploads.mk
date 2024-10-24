#
# Copyright 2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Variables useful for uploading files to a server

# toplevel rsync destination (without trailing slash)
RSYNC_DEST      ?= sites.clusterlabs.org:/var/www/html

RSYNC_PACKAGE_DEST	= $(RSYNC_DEST)/projects/$(PACKAGE)

# recursive, preserve symlinks, preserve permissions, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlpvzxS --progress
