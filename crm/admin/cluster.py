#!/bin/env python
#
#	$Id: cluster.py,v 1.1 2006/08/14 08:37:54 andrew Exp $
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

import os
import sys
import readline
import traceback
from popen2 import Popen3

# Module copied from Mercurial
import crm_utils as utl
import crm_commands as crm 

class ParseError(Exception):
    """Exception raised on errors in parsing the command line."""
class QuotingError(Exception):
    """Exception raised on errors in parsing the command line."""
class UnknownCommand(Exception):
    """Exception raised if command is not in the command table."""
class AmbiguousCommand(Exception):
    """Exception raised if command shortcut matches more than one command."""

table = {
    "^help": (
	crm.help, None, [('v', 'verbose', None, 'extra information')],
	"[-v]"),
    "^up": (crm.up, None, [], None, "Move up a level in the heirarchy"),
    "^crm": (crm.cd_, ["crm"], [], None),
    "^nodes": (crm.cd_, ["crm"], [], None),
    "^resources": (crm.cd_, ["crm"], [], None),
    "^config": (crm.cd_, ["crm"], [], None),
    "^list": (
	crm.do_list, ["nodes", "resources"], [('t', 'topic', "", '')],
	None),
    "^status": (
	crm.do_status, ["nodes", "resources"], [],
	"[list of objects]"),
    "^debug": (crm.toggle_flag, None, [('f', 'flag', 'debug', '')], None, "Toggle debugging information"),
    "^exit": (crm.exit, None, [], "exit"),
    "^debugstate": (
	crm.debugstate, None, [], 
	None,
	"Dump information about the internal state of the program"),
    }

global_opt_table = [
    ('q', 'quiet', None, 'suppress output'),
    ('v', 'verbose', None, 'enable additional output'),
    ('', 'debug', None, 'enable debugging output'),
    ('', 'devlog', None, 'enable developmental debugging output'),
    ('', 'debugger', None, 'start debugger'),
    ('', 'lsprof', None, 'print improved command execution profile'),
    ('', 'traceback', None, 'print traceback on exception'),
    ('', 'time', None, 'time how long the command takes'),
    ('', 'profile', None, 'print command execution profile'),
    ('', 'version', None, 'output version information and exit'),
    ('i', 'interactive', None, 'run in interactive mode'),
    ('h', 'help', None, 'display help and exit'),
    ]

def help_(text):
    if text == "short":
	utl.log_info("cluster.py [global options] [topic [topic...]] [command]")
	return
    if text:
	choice = findpossible(text)
	for key in choice.keys():
	    alias, e = choice[key]
	    if e:
		sub_cmd=""
		if len(e) > 4:
		    utl.log_info("\n"+e[4]+"\n")
		    possible = findpossible("", alias[0]).keys()
		    possible.remove("up")
		    possible.remove("help")
		    possible.remove("exit")
		    if possible:
			sub_cmd=' ('+'|'.join(possible)+')'
		if e[3]:
		    utl.log_info("Usage: %s %s%s" % (alias[0], e[3], sub_cmd))
		else:
		    utl.log_info("Usage: %s%s" % (alias[0], sub_cmd))
	if choice:
	    return;
    utl.log_err("No help text available for: %s" % text)


# Stolen from Mercurial commands.py

def findpossible(cmd, topic=None):
    """
    Return cmd -> (aliases, command table entry)
    for each matching command.
    Return debug commands (or their aliases) only if no normal command matches.
    """
    if not topic:
	topic = utl.crm_topic
	
    #utl.log_debug("Looking for completions in %s" % topic)
    choice = {}
    debugchoice = {}
    for e in table.keys():
	t = table[e]
	#utl.log_debug("Looking for "+topic +" in "+repr(t[1]))
	if t[1] and topic not in t[1]:
	    continue
        aliases = e.lstrip("^").split("|")
        found = None
        if cmd in aliases:
            found = cmd
        else:
            for a in aliases:
                if a.startswith(cmd):
                    found = a
                    break
        if found is not None:
            if aliases[0].startswith("debug"):
                debugchoice[found] = (aliases, table[e])
            else:
                choice[found] = (aliases, table[e])

    if not choice and debugchoice:
        choice = debugchoice

    return choice

def findcmd(cmd):
    """Return (aliases, command table entry) for command string."""
    choice = findpossible(cmd)

    if choice.has_key(cmd):
        return choice[cmd]

    if len(choice) > 1:
        clist = choice.keys()
        clist.sort()
        raise AmbiguousCommand(cmd, clist)

    if choice:
        return choice.values()[0]

    raise UnknownCommand(cmd)

def find_completer(start, i):
    choice = findpossible(start)
    if not choice:
	return None
    elif len(choice.keys()) < i:
	return None
    return choice.keys()[i]

def parse(args):
    options = {}
    cmdoptions = {}
    
    try:
	args = utl.fancyopts(args, global_opt_table, options)
    except utl.getopt.GetoptError, inst:
	raise ParseError(None, inst)

    if args:
	cmd, args = args[0], args[1:]
	aliases, i = findcmd(cmd)
	cmd = aliases[0]
	defaults = []
	if defaults:
	    args = defaults.split() + args
	c = list(i[2])
    else:
	cmd = None
	c = []

    # combine global options into local
    for o in global_opt_table:
	c.append((o[0], o[1], options[o[1]], o[3]))
	
    try:
	args = utl.fancyopts(args, c, cmdoptions)
    except utl.getopt.GetoptError, inst:
	raise ParseError(cmd, inst)

    # separate global options back out
    for o in global_opt_table:
	n = o[1]
	options[n] = cmdoptions[n]
	del cmdoptions[n]

    utl.log_dev("args: %s\ncmdoptions: %s" 
	      % (repr(args), repr(cmdoptions)))
    return (cmd, cmd and i[0] or None, args, options, cmdoptions)

def main_loop(args):
    global global_opts
    cmd = None
    cmd_args = []
    cmdoptions = {}

    if not args:
	return 0

    try:
	utl.log_dev("Loop Input: "+repr(args))
	cmd, func, new_args, ignore, new_cmdoptions = parse(args)

	cmd_args.extend(new_args)
	utl.log_dev(repr(cmd_args))
	cmdoptions.update(new_cmdoptions)

	if func == crm.cd_:
	    cmdoptions["topic"] = cmd
	    
	if not cmd:
	    utl.log_err(repr(args))
	    cmd = "_unknown_"
	    raise UnknownCommand(None, "")
	else:
	    d = lambda: func(*cmd_args, **cmdoptions)
	    return d()

    except crm.HelpRequest, inst:
	help_(inst.args[0])
	return 0

    except crm.ReparseRequest:
	return main_loop(cmd_args)

    except ParseError, inst:
	if inst.args[0]:
	    utl.log_err("%s: %s\n" % (inst.args[0], inst.args[1]))
	    help_(inst.args[0])
	else:
	    utl.log_err("%s\n" % inst.args[1])
	    help_('short')

    except AmbiguousCommand, inst:
	utl.log_info("%s: command '%s' is ambiguous:\n    %s\n" 
		 % (" ".join(utl.topic_stack), inst.args[0], " ".join(inst.args[1])))

    except UnknownCommand, inst:
	utl.log_err("%s: unknown command '%s'\n" % (" ".join(utl.topic_stack), inst.args[0]))
	help_(utl.crm_topic)

    except IOError, inst:
	if hasattr(inst, "code"):
	    utl.log_err("abort: %s\n" % inst)
	elif hasattr(inst, "reason"):
	    utl.log_err("abort: error: %s\n" % inst.reason[1])
	elif hasattr(inst, "args"):
	    utl.log_err("broken pipe\n")
	elif getattr(inst, "strerror", None):
	    if getattr(inst, "filename", None):
		utl.log_err("abort: %s - %s\n" % (inst.strerror, inst.filename))
	    else:
		utl.log_err("abort: %s\n" % inst.strerror)
	else:
	    raise
    except OSError, inst:
	if hasattr(inst, "filename"):
	    utl.log_err("abort: %s: %s\n" % (inst.strerror, inst.filename))
	else:
	    utl.log_err("abort: %s\n" % inst.strerror)
	    
    except TypeError, inst:
	# was this an argument error?
	tb = traceback.extract_tb(sys.exc_info()[2])
	if len(tb) > 2: # no
	    raise
	utl.log_err((inst, "\n"))
	utl.log_err(("%s: invalid arguments\n" % cmd))
	help_(cmd)
	raise
    except SystemExit, inst:
	# Exit gracefully 
	utl.exit_(inst.code)

    except:
	utl.log_err("** unknown exception encountered, details follow\n")
	raise
	
    return -1

args = sys.argv[1:]
utl.init_readline(find_completer)
try:
    cmd, f_ignore, a_ignore, utl.global_opts, o_ignore = parse(args)
except:
    pass

if len(sys.argv) == 1:
    utl.global_opts["interactive"] = 1
elif not utl.global_opts.has_key("interactive"):
    utl.global_opts["interactive"] = 0

while True:
    rc = 0
    if args:
	utl.set_topic(utl.topic_stack[-1])
	rc = main_loop(args)
	utl.log_debug("rc: %s" % (repr(rc)))

    if not utl.global_opts["interactive"]:
	utl.exit_(rc)

    try:
	text = raw_input(" ".join(utl.topic_stack) +" # ")
	args = utl.create_argv(text)

    except QuotingError, inst:
        if inst.args[1]:
            utl.log_err("%s.  Found tokens: %s\n" % (inst.args[0], inst.args[1]))
        else:
            utl.log_err("%s\n" % inst.args[0])

    except KeyboardInterrupt:
        utl.exit_(0)

    except EOFError:
        utl.exit_(0)



