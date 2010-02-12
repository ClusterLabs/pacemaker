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

import re
from vars import Vars
from utils import *
from msg import *

def get_var(l,key):
    for s in l:
        a = s.split()
        if len(a) == 2 and a[0] == key:
            return a[1]
    return ''
def chk_var(l,key):
    for s in l:
        a = s.split()
        if len(a) == 2 and a[0] == key and a[1]:
            return True
    return False
def chk_key(l,key):
    for s in l:
        a = s.split()
        if len(a) >= 1 and a[0] == key:
            return True
    return False
def validate_template(l):
    'Test for required stuff in a template.'
    if not chk_var(l,'%name'):
        common_err("invalid template: missing '%name'")
        return False
    if not chk_key(l,'%generate'):
        common_err("invalid template: missing '%generate'")
        return False
    g = l.index('%generate')
    if not (chk_key(l[0:g],'%required') or chk_key(l[0:g],'%optional')):
        common_err("invalid template: missing '%required' or '%optional'")
        return False
    return True
def fix_tmpl_refs(l,id,pfx):
    for i in range(len(l)):
        l[i] = l[i].replace(id,pfx)
def fix_tmpl_refs_re(l,regex,repl):
    for i in range(len(l)):
        l[i] = re.sub(regex,repl,l[i])
class LoadTemplate(object):
    '''
    Load a template and its dependencies, generate a
    configuration file which should be relatively easy and
    straightforward to parse.
    '''
    edit_instructions = '''# Edit instructions:
#
# Add content only at the end of lines starting with '%%'.
# Only add content, don't remove or replace anything.
# The parameters following '%required' are not optional,
# unlike those following '%optional'.
# You may also add comments for future reference.'''
    no_more_edit = '''# Don't edit anything below this line.'''
    def __init__(self,name):
        self.name = name
        self.all_pre_gen = []
        self.all_post_gen = []
        self.all_pfx = []
    def new_pfx(self,name):
        i = 1
        pfx = name
        while pfx in self.all_pfx:
            pfx = "%s_%d" % (name,i)
            i += 1
        self.all_pfx.append(pfx)
        return pfx
    def generate(self):
        return '\n'.join([ \
            "# Configuration: %s" % self.name, \
            '', \
            self.edit_instructions, \
            '', \
            '\n'.join(self.all_pre_gen), \
            self.no_more_edit, \
            '', \
            '%generate', \
            '\n'.join(self.all_post_gen)])
    def write_config(self,name):
        try:
            f = open("%s/%s" % (vars.tmpl_conf_dir, name),"w")
        except IOError,msg:
            common_err("open: %s"%msg)
            return False
        print >>f, self.generate()
        f.close()
        return True
    def load_template(self,tmpl):
        try:
            f = open("%s/%s" % (vars.tmpl_dir, tmpl))
        except IOError,msg:
            common_err("open: %s"%msg)
            return ''
        l = (''.join(f)).split('\n')
        if not validate_template(l):
            return ''
        common_info("pulling in template %s" % tmpl)
        g = l.index('%generate')
        pre_gen = l[0:g]
        post_gen = l[g+1:]
        name = get_var(pre_gen,'%name')
        for s in l[0:g]:
            if s.startswith('%depends_on'):
                a = s.split()
                if len(a) != 2:
                    common_warn("%s: wrong usage" % s)
                    continue
                tmpl_id = a[1]
                tmpl_pfx = self.load_template(a[1])
                if tmpl_pfx:
                    fix_tmpl_refs(post_gen,'%'+tmpl_id,'%'+tmpl_pfx)
        pfx = self.new_pfx(name)
        fix_tmpl_refs(post_gen, '%_:', '%'+pfx+':')
        # replace remaining %_, it may be useful at times
        fix_tmpl_refs(post_gen, '%_', pfx)
        v_idx = pre_gen.index('%required') or pre_gen.index('%optional')
        pre_gen.insert(v_idx,'%pfx ' + pfx)
        self.all_pre_gen += pre_gen
        self.all_post_gen += post_gen
        return pfx
    def post_process(self, params):
        pfx_re = '(%s)' % '|'.join(self.all_pfx)
        for n in params:
            fix_tmpl_refs(self.all_pre_gen, '%% '+n, "%% "+n+"  "+params[n])
        fix_tmpl_refs_re(self.all_post_gen, \
            '%'+pfx_re+'([^:]|$)', r'\1\2')
        # process %if ... [%else] ... %fi
        rmidx_l = []
        if_seq = False
        for i in range(len(self.all_post_gen)):
            s = self.all_post_gen[i]
            if if_seq:
                a = s.split()
                if len(a) >= 1 and a[0] == '%fi':
                    if_seq = False
                    rmidx_l.append(i)
                elif len(a) >= 1 and a[0] == '%else':
                    outcome = not outcome
                    rmidx_l.append(i)
                else:
                    if not outcome:
                        rmidx_l.append(i)
                continue
            if not s:
                continue
            a = s.split()
            if len(a) == 2 and a[0] == '%if':
                outcome = not a[1].startswith('%') # not replaced -> false
                if_seq = True
                rmidx_l.append(i)
        rmidx_l.reverse()
        for i in rmidx_l:
            del self.all_post_gen[i]

vars = Vars.getInstance()

# vim:ts=4:sw=4:et:
