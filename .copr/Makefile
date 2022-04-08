#
# Copyright 2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# This file is used by the ClusterLabs COPR project:
# https://copr.fedorainfracloud.org/coprs/g/ClusterLabs/devel/

# These should be provided by COPR, so these are just fallbacks
MAKE	?= make
outdir	?= .
spec	?= ..

LAST_RELEASE	=

srpm:
	dnf -y install git
	cd "$(spec)"/rpm			\
		&& echo "$$(git rev-list --count $$(git describe --tags --abbrev=0)..HEAD)"	\
			> build.counter		\
		&& $(MAKE) -f Makefile.am srpm	\
		&& cp SRPMS/*.src.rpm "$(outdir)"
