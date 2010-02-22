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

from os import getenv
from singletonmixin import Singleton
from term import TerminalController
from utils import *

class Options(Singleton):
    interactive = False
    batch = False
    regression_tests = False

options = Options.getInstance()
termctrl = TerminalController.getInstance()

def is_program(prog):
    return subprocess.call("which %s >/dev/null 2>&1"%prog, shell=True) == 0
def find_program(envvar,*args):
    if envvar and getenv(envvar):
        return getenv(envvar)
    for prog in args:
        if is_program(prog):
            return prog

def is_boolean_true(opt):
    return opt.lower() in ("yes","true","on")

class UserPrefs(Singleton):
    '''
    Keep user preferences here.
    '''
    dflt_colorscheme = "yellow,normal,cyan,red,green,magenta".split(',')
    skill_levels = {"operator":0, "administrator":1, "expert":2}
    output_types = ("plain", "color", "uppercase")
    check_frequencies = ("always", "on-verify", "never")
    check_modes = ("strict", "relaxed")
    def __init__(self):
        self.skill_level = 2 #TODO: set back to 0?
        self.editor = find_program("EDITOR","vim","vi","emacs","nano")
        self.pager = find_program("PAGER","less","more","pg")
        self.dotty = find_program("","dotty")
        if not self.editor:
            self.missing("editor")
        if not self.pager:
            self.missing("pager")
        self.crm_user = ""
        self.xmlindent = "  "  # two spaces
        # keywords,ids,attribute names,values
        self.colorscheme = self.dflt_colorscheme
        # plain or color
        self.output = ['color',]
        # the semantic checks preferences
        self.check_frequency = "always"
        self.check_mode = "strict"
        self.debug = False
        self.force = False
        self.sort_elems = "yes"
    def missing(self,n):
        print >> sys.stderr, "could not find any %s on the system"%n
    def check_skill_level(self,n):
        return self.skill_level >= n
    def set_skill_level(self,skill_level):
        if skill_level in self.skill_levels:
            self.skill_level = self.skill_levels[skill_level]
        else:
            common_err("no %s skill level"%skill_level)
            return False
    def get_skill_level(self):
        for s in self.skill_levels:
            if self.skill_level == self.skill_levels[s]:
                return s
    def set_editor(self,prog):
        if is_program(prog):
            self.editor = prog
        else:
            common_err("program %s does not exist"% prog)
            return False
    def set_pager(self,prog):
        if is_program(prog):
            self.pager = prog
        else:
            common_err("program %s does not exist"% prog)
            return False
    def set_crm_user(self,user = ''):
        self.crm_user = user
    def set_output(self,otypes):
        l = otypes.split(',')
        for otype in l:
            if not otype in self.output_types:
                common_err("no %s output type" % otype)
                return False
        self.output = l
    def set_colors(self,scheme):
        colors = scheme.split(',')
        if len(colors) != 6:
            common_err("bad color scheme: %s"%scheme)
            colors = UserPrefs.dflt_colorscheme
        rc = True
        for c in colors:
            if not termctrl.is_color(c):
                common_err("%s is not a recognized color" % c)
                rc = False
        if rc:
            self.colorscheme = colors
        else:
            self.output.remove("color")
        return rc
    def is_check_always(self):
        '''
        Even though the frequency may be set to always, it doesn't
        make sense to do that with non-interactive sessions.
        '''
        return options.interactive and self.check_frequency == "always"
    def get_check_rc(self):
        '''
        If the check mode is set to strict, then on errors we
        return 2 which is the code for error. Otherwise, we
        pretend that errors are warnings.
        '''
        return self.check_mode == "strict" and 2 or 1
    def set_check_freq(self,frequency):
        if frequency not in self.check_frequencies:
            common_err("no %s check frequency"%frequency)
            return False
        self.check_frequency = frequency
    def set_check_mode(self,mode):
        if mode not in self.check_modes:
            common_err("no %s check mode"%mode)
            return False
        self.check_mode = mode
    def set_debug(self):
        self.debug = True
    def get_debug(self):
        return self.debug
    def set_force(self):
        self.force = True
    def get_force(self):
        return self.force
    def set_sort_elems(self,opt):
        self.sort_elems = is_boolean_true(opt) and "yes" or "no"
    def get_sort_elems(self):
        return self.sort_elems == "yes"
    def write_rc(self,f):
        print >>f, '%s "%s"' % ("editor",self.editor)
        print >>f, '%s "%s"' % ("pager",self.pager)
        print >>f, '%s "%s"' % ("user",self.crm_user)
        print >>f, '%s "%s"' % ("skill-level",self.get_skill_level())
        print >>f, '%s "%s"' % ("output", ','.join(self.output))
        print >>f, '%s "%s"' % ("colorscheme", ','.join(self.colorscheme))
        print >>f, '%s "%s"' % ("sort-elements", self.sort_elems)
        print >>f, '%s "%s"' % ("check-frequency",self.check_frequency)
        print >>f, '%s "%s"' % ("check-mode",self.check_mode)
    def save_options(self,rc_file):
        try: f = open(rc_file,"w")
        except IOError,msg:
            common_err("open: %s"%msg)
            return
        print >>f, 'options'
        self.write_rc(f)
        print >>f, 'end'
        f.close()

# vim:ts=4:sw=4:et:
