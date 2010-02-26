# Copyright (C) 2008 Dejan Muhamedagic <dmuhamedagic@suse.de>
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

import sys
import shlex
import readline
import getopt

from utils import *
from userprefs import Options, UserPrefs
from vars import Vars
from msg import *
from ui import cmd_exit, TopLevel, completer
from levels import Levels

def load_rc(rcfile):
    try: f = open(rcfile)
    except: return
    save_stdin = sys.stdin
    sys.stdin = f
    while True:
        inp = multi_input()
        if inp == None:
            break
        try: parse_line(levels,shlex.split(inp))
        except ValueError, msg:
            common_err(msg)
    f.close()
    sys.stdin = save_stdin

def multi_input(prompt = ''):
    """
    Get input from user
    Allow multiple lines using a continuation character
    """
    line = []
    while True:
        try:
            text = raw_input(prompt)
        except EOFError:
            return None
        err_buf.incr_lineno()
        if options.regression_tests:
            print ".INP:",text
            sys.stdout.flush()
            sys.stderr.flush()
        stripped = text.strip()
        if stripped.endswith('\\'):
            stripped = stripped.rstrip('\\')
            line.append(stripped)
            if prompt:
                prompt = '> '
        else:
            line.append(stripped)
            break
    return ''.join(line)

def check_args(args,argsdim):
    if not argsdim: return True
    if len(argsdim) == 1:
        minargs = argsdim[0]
        return len(args) >= minargs
    else:
        minargs,maxargs = argsdim
        return len(args) >= minargs and len(args) <= maxargs

#
# Note on parsing
#
# Parsing tables are python dictionaries.
#
# Keywords are used as keys and the corresponding values are
# lists (actually tuples, since they should be read-only) or
# classes. In the former case, the keyword is a terminal and
# in the latter, a new object for the class is created. The class
# must have the cmd_table variable.
#
# The list has the following content:
#
# function: a function to handle this command
# numargs_list: number of minimum/maximum arguments; for example,
#   (0,1) means one optional argument, (1,1) one required; if the
#   list is empty then the function will parse arguments itself
# required minimum skill level: operator, administrator, expert
#   (encoded as a small integer from 0 to 2)
# list of completer functions (optional)
# 

def show_usage(cmd):
    p = None
    try: p = cmd.__doc__
    except: pass
    if p:
        print >> sys.stderr, p
    else:
        syntax_err(cmd.__name__)

def parse_line(lvl,s):
    if not s: return True
    if s[0].startswith('#'): return True
    lvl.mark()
    pt = lvl.parse_root
    cmd = None
    i = 0
    for i in range(len(s)):
        token = s[i]
        if token in pt:
            if type(pt[token]) == type(object):
                lvl.new_level(pt[token],token)
                pt = lvl.parse_root # move to the next level
            else:
                cmd = pt[token] # terminal symbol
                break  # and stop parsing
        else:
            syntax_err(s[i:])
            lvl.release()
            return False
    if cmd: # found a terminal symbol
        if not user_prefs.check_skill_level(cmd[2]):
            lvl.release()
            skill_err(s[i])
            return False
        args = s[i+1:]
        if not check_args(args,cmd[1]):
            lvl.release()
            show_usage(cmd[0])
            return False
        args = s[i:]
        d = lambda: cmd[0](*args)
        rv = d() # execute the command
        lvl.release()
        return rv != False
    return True

def prereqs():
    proglist = "which cibadmin crm_resource crm_attribute crm_mon crm_standby crm_failcount"
    for prog in proglist.split():
        if not is_program(prog):
            print >> sys.stderr, "%s not available, check your installation"%prog
            sys.exit(1)

# three modes: interactive (no args supplied), batch (input from
# a file), half-interactive (args supplied, but not batch)
def cib_prompt():
    return vars.cib_in_use or "live"

def setup_readline():
    readline.set_history_length(100)
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)
    readline.set_completer_delims(\
        readline.get_completer_delims().replace('-','').replace('/','').replace('=',''))
    try: readline.read_history_file(vars.hist_file)
    except: pass

def usage():
    print >> sys.stderr, """
usage:
    crm [-D display_type] [-f file] [-hF] [args]

    Use crm without arguments for an interactive session.
    Supply one or more arguments for a "single-shot" use.
    Specify with -f a file which contains a script. Use '-' for
    standard input or use pipe/redirection.

    crm displays cli format configurations using a color scheme
    and/or in uppercase. Pick one of "color" or "uppercase", or
    use "-D color,uppercase" if you want colorful uppercase.
    Get plain output by "-D plain". The default may be set in
    user preferences (options).

    -F stands for force, if set all operations will behave as if
    force was specified on the line (e.g. configure commit).

Examples:

    # crm -f stopapp2.cli
    # crm < stopapp2.cli
    # crm resource stop global_www
    # crm status 

    """
    sys.exit(1)

user_prefs = UserPrefs.getInstance()
options = Options.getInstance()
err_buf = ErrorBuffer.getInstance()
vars = Vars.getInstance()
levels = Levels.getInstance()

def run():
    prereqs()
    inp_file = ''

    load_rc(vars.rc_file)

    if not sys.stdin.isatty():
        err_buf.reset_lineno()
        options.batch = True
    else:
        options.interactive = True

    try:
        opts, args = getopt.getopt(sys.argv[1:], \
            'hdf:FRD:', ("help","debug","file=",\
            "force","regression-tests","display="))
        for o,p in opts:
            if o in ("-h","--help"):
                usage()
            elif o == "-d":
                user_prefs.set_debug()
            elif o == "-R":
                options.regression_tests = True
            elif o in ("-D","--display"):
                user_prefs.set_output(p)
            elif o in ("-F","--force"):
                user_prefs.set_force()
            elif o in ("-f","--file"):
                options.batch = True
                err_buf.reset_lineno()
                inp_file = p
    except getopt.GetoptError,msg:
        print msg
        usage()

    if len(args) == 1 and args[0].startswith("conf"):
        parse_line(levels,["configure"])
        options.interactive = True
    elif len(args) > 0:
        err_buf.reset_lineno()
        options.interactive = False
        if parse_line(levels,shlex.split(' '.join(args))):
            # if the user entered a level, then just continue
            if levels.previous():
                if not inp_file and sys.stdin.isatty():
                    options.interactive = True
            else:
                sys.exit(0)
        else:
            sys.exit(1)

    if inp_file == "-":
        pass
    elif inp_file:
        try:
            f = open(inp_file)
        except IOError, msg:
            common_err(msg)
            usage()
        sys.stdin = f

    if options.interactive and not options.batch:
        setup_readline()

    while True:
        if options.interactive and not options.batch:
            vars.prompt = "crm(%s)%s# " % (cib_prompt(),levels.getprompt())
        inp = multi_input(vars.prompt)
        if inp == None:
            cmd_exit("eof")
        try: parse_line(levels,shlex.split(inp))
        except ValueError, msg:
            common_err(msg)

# vim:ts=4:sw=4:et:
