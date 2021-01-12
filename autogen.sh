#!/bin/sh
# Part of pacemaker project
# SPDX-License-Identifier: GPL-2.0-or-later

# We configure some build artifacts to go to libltdl/config. autotools will
# happily create it if it doesn't exist, but will still print an error and
# exit nonzero in that case. :-(
mkdir -p libltdl/config

autoreconf -fisv || exit $?
echo 'Now run ./configure and make'
