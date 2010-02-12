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

from singletonmixin import Singleton
from userprefs import Options, UserPrefs
from vars import Vars
from cache import WCache
from utils import *
from msg import *
from term import TerminalController

class CliDisplay(Singleton):
    """
    Display output for various syntax elements.
    """
    def __init__(self):
        self.no_pretty = False
    def set_no_pretty(self):
        self.no_pretty = True
    def reset_no_pretty(self):
        self.no_pretty = False
    def colorstring(self, clrnum, s):
        if self.no_pretty:
            return s
        else:
            return termctrl.render("${%s}%s${NORMAL}" % \
                (user_prefs.colorscheme[clrnum].upper(), s))
    def keyword(self, kw):
        s = kw
        if "uppercase" in user_prefs.output:
            s = s.upper()
        if "color" in user_prefs.output:
            s = self.colorstring(0, s)
        return s
    def otherword(self, n, s):
        if "color" in user_prefs.output:
            return self.colorstring(n, s)
        else:
            return s
    def id(self, s):
        return self.otherword(1, s)
    def attr_name(self, s):
        return self.otherword(2, s)
    def attr_value(self, s):
        return self.otherword(3, s)
    def rscref(self, s):
        return self.otherword(4, s)
    def score(self, s):
        return self.otherword(5, s)

user_prefs = UserPrefs.getInstance()
vars = Vars.getInstance()
termctrl = TerminalController.getInstance()

# vim:ts=4:sw=4:et:
