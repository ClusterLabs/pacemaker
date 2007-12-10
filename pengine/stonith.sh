#!/bin/bash

 # Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

. regression.core.sh

create_mode="false"

echo ""
do_test stopfail2 "Stop Failed - Block	"
do_test stopfail3 "Stop Failed - Ignore (1 node)"
do_test stopfail4 "Stop Failed - Ignore (2 node)"
do_test stopfail1 "Stop Failed - STONITH (block)"
do_test stopfail5 "Stop Failed - STONITH (pass)"
do_test stopfail6 "Stop Failed - STONITH (pass2)"
do_test stopfail7 "Stop Failed - STONITH (should fail)"

create_mode="true"

test_results

