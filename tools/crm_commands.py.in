#
#
#	pingd OCF Resource Agent
#	Records (in the CIB) the current number of ping nodes a 
#	   cluster node can connect to.
#
# Copyright (c) 2006 Andrew Beekhof
#                    All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Further, this software is distributed without any warranty that it is
# free of the rightful claim of any third person regarding infringement
# or the like.  Any license provided herein, whether implied or
# otherwise, applies only to this software file.  Patent licenses, if
# any, provided herein do not apply to combinations of this program with
# other software, or any other product whatsoever.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
#
#######################################################################

import crm_utils as utl

class HelpRequest(Exception):
    """Exception raised when a help listing is required."""

class ReparseRequest(Exception):
    """Exception raised when a command changed the command-line."""

def up(*args, **cmdoptions):
    l = len(utl.topic_stack)
    if l > 1:
	utl.topic_stack.pop()
	utl.set_topic(utl.topic_stack[-1])
    else:
	utl.log_debug("Already at the top of the stack")

def toggle_flag(*args, **cmdoptions):
    flag = cmdoptions["flag"]
    if utl.global_opts[flag]:
	utl.global_opts[flag] = 0
    else:
	utl.global_opts[flag] = 1

    return utl.global_opts[flag]

def cd_(*args, **cmdoptions):
    utl.log_dev("args: %s\nopts: %s" % (repr(args), repr(cmdoptions)))
    if not cmdoptions["topic"]:
	utl.log_err("No topic specified")
	return 1

    if cmdoptions["topic"]:
	utl.set_topic(cmdoptions["topic"])
    if args:
	raise ReparseRequest()
    if utl.crm_topic not in utl.topic_stack:
	utl.topic_stack.append(cmdoptions["topic"])
    if not utl.global_opts["interactive"]:
	help(cmdoptions["topic"])
    return 0

def exit(*args, **cmdoptions):
    sys.exit(0)

def help(*args, **cmdoptions):
    if args:
	raise HelpRequest(args[0])
    raise HelpRequest(utl.crm_topic)

def debugstate(*args, **cmdoptions):
    utl.log_info("Global Options: ")
    for opt in utl.global_opts.keys():
	utl.log_info(" * %s:\t%s" % (opt, utl.global_opts[opt]))
    utl.log_info("Stack: "+repr(utl.topic_stack))
    utl.log_info("Stack Head: "+utl.crm_topic)
    return 0

def do_list(*args, **cmdoptions):
    topic = utl.crm_topic
    if cmdoptions.has_key("topic") and cmdoptions["topic"]:
	topic = cmdoptions["topic"]

    utl.log_debug("Complete '%s' listing" % topic)
    if topic == "resources":
	utl.os_system("crm_resource -l", True)
    elif topic == "nodes":
	lines = utl.os_system("cibadmin -Q -o nodes", False)
	for line in lines:
	    if line.find("node ") >= 0:
		print line.rstrip()
    else:
	utl.log_err("%s: Topic %s is not (yet) supported" % ("list", topic))
	return 1
    return 0

def do_status(*args, **cmdoptions):
    topic = utl.crm_topic
    if cmdoptions.has_key("topic") and cmdoptions["topic"]:
	topic = cmdoptions["topic"]

    if topic == "resources":
	if not args:
	    utl.os_system("crm_resource -L", True)
	for rsc in args:
	    utl.os_system("crm_resource -W -r %s"%rsc, True)

    elif topic == "nodes":
	lines = utl.os_system("cibadmin -Q -o status", False)
	for line in lines:
	    line = line.rstrip()
	    utl.log_dev("status line: "+line)
	    if line.find("node_state ") >= 0:
		if not args:
		    print line 
		for node in args:
		    if line.find(node) >= 0:
			print line
    else:
	utl.log_err("Topic %s is not (yet) supported" % topic)
	return 1

    return 0
