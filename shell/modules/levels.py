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
import re
from singletonmixin import Singleton

def topics_dict(help_tab):
    if not help_tab:
        return {}
    topics = {}
    for topic in help_tab:
        if topic != '.':
            topics[topic] = None
    return topics

def mk_completion_tab(obj,ctab):
    cmd_table = obj.cmd_table
    for key,value in cmd_table.items():
        if key.startswith("_"):
            continue
        if type(value) == type(object):
            ctab[key] = {}
        elif key == "help":
            ctab[key] = topics_dict(obj.help_table)
        else:
            try:
                ctab[key] = value[3]
            except:
                ctab[key] = None
                pass

class Levels(Singleton):
    '''
    Keep track of levels and prompts.
    '''
    def __init__(self,start_level):
        self._marker = 0
        self._in_transit = False
        self.level_stack = []
        self.comp_stack = []
        self.current_level = start_level()
        self.parse_root = self.current_level.cmd_table
        self.prompts = []
        self.completion_tab = {}
        mk_completion_tab(self.current_level,self.completion_tab)
    def getprompt(self):
        return ' '.join(self.prompts)
    def mark(self):
        self._marker = len(self.level_stack)
        self._in_transit = False
    def release(self):
        while len(self.level_stack) > self._marker:
            self.droplevel()
    def new_level(self,level_obj,token):
        self.level_stack.append(self.current_level)
        self.comp_stack.append(self.completion_tab)
        self.prompts.append(token)
        self.current_level = level_obj()
        self.parse_root = self.current_level.cmd_table
        try:
            if not self.completion_tab[token]:
                mk_completion_tab(self.current_level,self.completion_tab[token])
            self.completion_tab = self.completion_tab[token]
        except:
            pass
        self._in_transit = True
    def previous(self):
        if self.level_stack:
            return self.level_stack[-1]
    def droplevel(self):
        if self.level_stack:
            self.current_level.end_game(self._in_transit)
            self.current_level = self.level_stack.pop()
            self.completion_tab = self.comp_stack.pop()
            self.parse_root = self.current_level.cmd_table
            self.prompts.pop()

# vim:ts=4:sw=4:et:
