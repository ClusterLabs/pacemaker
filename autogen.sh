#!/bin/sh
# Part of pacemaker project
# SPDX-License-Identifier: GPL-2.0-or-later

autoreconf -fisv || exit $?
echo 'Now run ./configure and make'
