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
from singletonmixin import Singleton
from userprefs import Options, UserPrefs

class ErrorBuffer(Singleton):
    '''
    Show error messages either immediately or buffered.
    '''
    def __init__(self):
        self.msg_list = []
        self.mode = "immediate"
        self.lineno = -1
    def buffer(self):
        self.mode = "keep"
    def release(self):
        if self.msg_list:
            print >> sys.stderr, '\n'.join(self.msg_list)
            if not options.batch:
                try:
                    raw_input("Press enter to continue... ")
                except EOFError:
                    pass
            self.msg_list = []
        self.mode = "immediate"
    def writemsg(self,msg):
        if self.mode == "immediate":
            if options.regression_tests:
                print msg
            else:
                print >> sys.stderr, msg
        else:
            self.msg_list.append(msg)
    def reset_lineno(self):
        self.lineno = 0
    def incr_lineno(self):
        if self.lineno >= 0:
            self.lineno += 1
    def start_tmp_lineno(self):
        self._save_lineno = self.lineno
        self.reset_lineno()
    def stop_tmp_lineno(self):
        self.lineno = self._save_lineno
    def add_lineno(self,s):
        if self.lineno > 0:
            return "%d: %s" % (self.lineno,s)
        else: return s
    def error(self,s):
        self.writemsg("ERROR: %s" % self.add_lineno(s))
    def warning(self,s):
        self.writemsg("WARNING: %s" % self.add_lineno(s))
    def info(self,s):
        self.writemsg("INFO: %s" % self.add_lineno(s))
    def debug(self,s):
        if user_prefs.get_debug():
            self.writemsg("DEBUG: %s" % self.add_lineno(s))

def common_err(s):
    err_buf.error(s)
def common_warn(s):
    err_buf.warning(s)
def common_info(s):
    err_buf.info(s)
def common_debug(s):
    err_buf.debug(s)
def no_prog_err(name):
    err_buf.error("%s not available, check your installation"%name)
def missing_prog_warn(name):
    err_buf.warning("could not find any %s on the system"%name)
def no_attribute_err(attr,obj_type):
    err_buf.error("required attribute %s not found in %s"%(attr,obj_type))
def bad_def_err(what,msg):
    err_buf.error("bad %s definition: %s"%(what,msg))
def unsupported_err(name):
    err_buf.error("%s is not supported"%name)
def no_such_obj_err(name):
    err_buf.error("%s object is not supported"%name)
def obj_cli_warn(name):
    err_buf.warning("object %s cannot be represented in the CLI notation"%name)
def missing_obj_err(node):
    err_buf.error("object %s:%s missing (shouldn't have happened)"% \
        (node.tagName,node.getAttribute("id")))
def constraint_norefobj_err(constraint_id,obj_id):
    err_buf.error("constraint %s references a resource %s which doesn't exist"% \
        (constraint_id,obj_id))
def obj_exists_err(name):
    err_buf.error("object %s already exists"%name)
def no_object_err(name):
    err_buf.error("object %s does not exist"%name)
def invalid_id_err(obj_id):
    err_buf.error("%s: invalid object id"%obj_id)
def id_used_err(node_id):
    err_buf.error("%s: id is already in use"%node_id)
def skill_err(s):
    err_buf.error("%s: this command is not allowed at this skill level"%' '.join(s))
def syntax_err(s,token = '',context = ''):
    pfx = "syntax"
    if context:
        pfx = "%s in %s" %(pfx,context)
    if type(s) == type(''):
        err_buf.error("%s near <%s>"%(pfx,s))
    elif token:
        err_buf.error("%s near <%s>: %s"%(pfx,token,' '.join(s)))
    else:
        err_buf.error("%s: %s"%(pfx,' '.join(s)))
def bad_usage(cmd,args):
    err_buf.error("bad usage: %s %s"%(cmd,args))
def empty_cib_err():
    err_buf.error("No CIB!")
def cib_parse_err(msg,s):
    err_buf.error("%s"%msg)
    err_buf.info("offending string: %s" % s)
def cib_no_elem_err(el_name):
    err_buf.error("CIB contains no '%s' element!"%el_name)
def cib_ver_unsupported_err(validator,rel):
    err_buf.error("CIB not supported: validator '%s', release '%s'"% (validator,rel))
    err_buf.error("You may try the upgrade command")
def update_err(obj_id,cibadm_opt,xml):
    if cibadm_opt == '-U':
        task = "update"
    elif cibadm_opt == '-D':
        task = "delete"
    else:
        task = "replace"
    err_buf.error("could not %s %s"%(task,obj_id))
    err_buf.info("offending xml: %s" % xml)
def not_impl_info(s):
    err_buf.info("%s is not implemented yet" % s)

user_prefs = UserPrefs.getInstance()
err_buf = ErrorBuffer.getInstance()
options = Options.getInstance()
# vim:ts=4:sw=4:et:
