#!/bin/env python
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

import os
import sys
import getopt
import readline
import traceback
from popen2 import Popen3

crm_topic = "crm"
topic_stack = [ crm_topic ]
hist_file  = os.environ.get('HOME')+"/.crm_history"
global_opts = {}

def exit_(code=0):
    if global_opts["interactive"]:
	log_info("Exiting... ")
    try:
	readline.write_history_file(hist_file)
	log_debug("Wrote history to: "+hist_file)
    except:
	log_debug("Couldnt write history to: "+hist_file)
    sys.exit(code)

def log_debug(log):
    if global_opts.has_key("debug") and global_opts["debug"]:
	print log

def log_dev(log):
    if global_opts.has_key("devlog") and global_opts["devlog"]:
	print log

def log_info(log):
    print log

def log_err(log):
    print "ERROR: "+log

def set_topic(name):
    global crm_topic
    if crm_topic != name:
    	log_dev("topic: %s->%s" % (crm_topic, name))
    crm_topic = name

def os_system(cmd, print_raw=False):
    log_debug("Performing command: "+cmd)
    p = Popen3(cmd, None)
    p.tochild.close()
    result = p.fromchild.readlines()
    p.fromchild.close()
    p.wait()
    if print_raw:
	for line in result:
	    print line.rstrip()
    return result

#
#  Creates an argv-style array (that preserves quoting) for use in shell-mode
#
def create_argv(text):
    args = []
    word = []
    index = 0
    total = len(text)
    
    in_word = False
    in_verbatum = False
    
    while index < total:
	finish_word = False
	append_word = False
	#log_debug("processing: "+text[index])
	if text[index] == '\\':
	    index = index +1
	    append_word = True
	    
	elif text[index].isspace():
	    if in_verbatum or in_word:
		append_word = True
	    else:
		finish_word = True
		
	elif text[index] == '"':
	    if in_verbatum:
		append_word = True
	    else:
		finish_word = True
		if in_word:
		    in_word = False
		else:
		    in_word = True
		    
	elif text[index] == '\'':
	    finish_word = True
	    if in_verbatum:
		in_verbatum = False
	    else:
		in_verbatum = True
	else:
	    append_word = True

	if finish_word:
	    if word:
		args.append(''.join(word))
		word = []
	elif append_word:
	    word.append(text[index])
	    #log_debug("Added %s to word: %s" % (text[index], str(word)))
	
	index = index +1

    if in_verbatum or in_word:
	text=""
	if word:
	    text=" after: '%s'"%''.join(word)
	    raise QuotingError("Un-matched quoting%s"%text, args)
	
    elif word:
	args.append(''.join(word))

    return args
	  
def init_readline(func):
    readline.set_completer(func)
    readline.parse_and_bind("tab: complete")
    readline.set_history_length(100)
    
    try:
	readline.read_history_file(hist_file)
    except:
	pass
	    
def fancyopts(args, options, state):
    long = []
    short = ''
    map = {}
    dt = {}

    for s, l, d, c in options:
        pl = l.replace('-', '_')
        map['-'+s] = map['--'+l] = pl
        state[pl] = d
        dt[pl] = type(d)
        if not d is None and not callable(d):
            if s: s += ':'
            if l: l += '='
        if s: short = short + s
        if l: long.append(l)

    opts, args = getopt.getopt(args, short, long)

    for opt, arg in opts:
        if dt[map[opt]] is type(fancyopts): state[map[opt]](state,map[opt],arg)
        elif dt[map[opt]] is type(1): state[map[opt]] = int(arg)
        elif dt[map[opt]] is type(''): state[map[opt]] = arg
        elif dt[map[opt]] is type([]): state[map[opt]].append(arg)
        elif dt[map[opt]] is type(None): state[map[opt]] = 1

    return args
