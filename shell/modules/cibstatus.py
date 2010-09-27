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
import os
import re
import time
from singletonmixin import Singleton
from vars import Vars
from xmlutil import *
from msg import *

def get_tag_by_id(node,tag,id):
    "Find a doc node which matches tag and id."
    for n in node.getElementsByTagName(tag):
        if n.getAttribute("id") == id:
            return n
    return None
def get_status_node_id(n):
    try: n = n.parentNode
    except: return None
    if n.tagName != "node_state":
        return get_status_node_id(n)
    return n.getAttribute("id")
def get_status_node(status_node,node):
    for n in status_node.childNodes:
        if not is_element(n) or n.tagName != "node_state":
            continue
        if n.getAttribute("id") == node:
            return n
    return None
def get_status_ops(status_node,rsc,op,interval,node = ''):
    '''
    Find a doc node which matches the operation. interval set to
    "-1" means to lookup an operation with non-zero interval (for
    monitors). Empty interval means any interval is fine.
    '''
    l = []
    for n in status_node.childNodes:
        if not is_element(n) or n.tagName != "node_state":
            continue
        if node and n.getAttribute("id") != node:
            continue
        for r in n.getElementsByTagName("lrm_resource"):
            if r.getAttribute("id") != rsc:
                continue
            for o in r.getElementsByTagName("lrm_rsc_op"):
                if o.getAttribute("operation") != op:
                    continue
                if o.getAttribute("interval") == interval or \
                  (interval == "-1" and o.getAttribute("interval") != "0"):
                    l.append(o)
    return l

def split_op(op):
    if op == "probe":
        return "monitor","0"
    elif op == "monitor":
        return "monitor","-1"
    elif op[0:8] == "monitor:":
        return "monitor",op[8:]
    return op,"0"

def cib_path(source):
    return source[0:7] == "shadow:" and shadowfile(source[7:]) or source

class CibStatus(Singleton):
    '''
    CIB status management
    '''
    cmd_inject = "</dev/null >/dev/null 2>&1 crm_simulate -x %s -I %s"
    cmd_run = "2>&1 crm_simulate -R -x %s"
    cmd_simulate = "2>&1 crm_simulate -S -x %s"
    node_ops = {
        "online": "-u",
        "offline": "-d",
        "unclean": "-f",
    }
    def __init__(self):
        self.origin = "live"
        self.backing_file = "" # file to keep the live cib
        self.status_node = None
        self.doc = None
        self.cib = None
        self.reset_state()
    def _cib_path(self,source):
        if source[0:7] == "shadow:":
            return shadowfile(source[7:])
        else:
            return source
    def _load_cib(self,source):
        if source == "live":
            if not self.backing_file:
                self.backing_file = cib2tmp()
                if not self.backing_file:
                    return None,None
            else:
                cibdump2file(self.backing_file)
            f = self.backing_file
        else:
            f = cib_path(source)
        return read_cib(file2doc,f)
    def _load(self,source):
        doc,cib = self._load_cib(source)
        if not doc:
            return False
        status = get_conf_elem(doc, "status")
        if not status:
            return False
        self.doc,self.cib = doc,cib
        self.status_node = status
        self.reset_state()
        return True
    def reset_state(self):
        self.modified = False
        self.quorum = ''
        self.node_changes = {}
        self.op_changes = {}
        return True
    def source_file(self):
        if self.origin == "live":
            return self.backing_file
        else:
            return cib_path(self.origin)
    def status_node_list(self):
        if not self.get_status():
            return
        return [x.getAttribute("id") for x in self.doc.getElementsByTagName("node_state")]
    def status_rsc_list(self):
        if not self.get_status():
            return
        rsc_list = [x.getAttribute("id") for x in self.doc.getElementsByTagName("lrm_resource")]
        # how to uniq?
        d = {}
        for e in rsc_list:
            d[e] = 0
        return d.keys()
    def load(self,source):
        '''
        Load the status section from the given source. The source
        may be cluster ("live"), shadow CIB, or CIB in a file.
        '''
        if self.backing_file:
            os.unlink(self.backing_file)
            self.backing_file = ""
        if not self._load(source):
            common_err("the cib contains no status")
            return False
        self.origin = source
        return True
    def save(self,dest = None):
        '''
        Save the modified status section to a file/shadow. If the
        file exists, then it must be a cib file and the status
        section is replaced with our status section. If the file
        doesn't exist, then our section and some (?) configuration
        is saved.
        '''
        if not self.modified:
            common_info("apparently you didn't modify status")
            return False
        if (not dest and self.origin == "live") or dest == "live":
            common_warn("cannot save status to the cluster")
            return False
        doc,cib = self.doc,self.cib
        if dest:
            dest_path = cib_path(dest)
            if os.path.isfile(dest_path):
                doc,cib = self._load_cib(dest)
                if not doc or not cib:
                    common_err("%s exists, but no cib inside" % dest)
                    return False
        else:
            dest_path = cib_path(self.origin)
        if doc != self.doc:
            status = get_conf_elem(doc, "status")
            rmnode(status)
            cib.appendChild(doc.importNode(self.status_node,1))
        xml = doc.toprettyxml(user_prefs.xmlindent)
        try: f = open(dest_path,"w")
        except IOError, msg:
            common_err(msg)
            return False
        f.write(xml)
        f.close()
        return True
    def _crm_simulate(self, cmd, nograph, scores, utilization, verbosity):
        if verbosity:
            cmd = "%s -%s" % (cmd,verbosity.upper())
        if scores:
            cmd = "%s -s" % cmd
        if utilization:
            cmd = "%s -U" % cmd
        if user_prefs.dotty and not nograph:
            fd,dotfile = mkstemp()
            cmd = "%s -D %s" % (cmd,dotfile)
        else:
            dotfile = None
        rc = ext_cmd(cmd % self.source_file())
        if dotfile:
            show_dot_graph(dotfile)
            vars.tmpfiles.append(dotfile)
        return rc == 0
    # actions is ignored
    def run(self, nograph, scores, utilization, actions, verbosity):
        return self._crm_simulate(self.cmd_run, \
            nograph, scores, utilization, verbosity)
    # actions is ignored
    def simulate(self, nograph, scores, utilization, actions, verbosity):
        return self._crm_simulate(self.cmd_simulate, \
            nograph, scores, utilization, verbosity)
    def get_status(self):
        '''
        Return the status section node.
        '''
        if (not self.status_node or \
            (self.origin == "live" and not self.modified)) \
                and not self._load(self.origin):
            return None
        return self.status_node
    def list_changes(self):
        '''
        Dump a set of changes done.
        '''
        if not self.modified:
            return True
        for node in self.node_changes:
            print node,self.node_changes[node]
        for op in self.op_changes:
            print op,self.op_changes[op]
        if self.quorum:
            print "quorum:",self.quorum
        return True
    def show(self):
        '''
        Page the "pretty" XML of the status section.
        '''
        if not self.get_status():
            return False
        page_string(self.status_node.toprettyxml(user_prefs.xmlindent))
        return True
    def inject(self,opts):
        return ext_cmd("%s %s" % \
            (self.cmd_inject % (self.source_file(), self.source_file()), opts))
    def set_quorum(self, v):
        rc = self.inject("--quorum=%s" % (v and "true" or "false"))
        if rc != 0:
            return False
        self._load(self.origin)
        self.quorum = v and "true" or "false"
        self.modified = True
        return True
    def edit_node(self,node,state):
        '''
        Modify crmd, expected, and join attributes of node_state
        to set the node's state to online, offline, or unclean.
        '''
        if not self.get_status():
            return False
        if not state in self.node_ops:
            common_err("unknown state %s" % state)
            return False
        node_node = get_tag_by_id(self.status_node,"node_state",node)
        if not node_node:
            common_err("node %s not found" % node)
            return False
        rc = self.inject("%s %s" % (self.node_ops[state], node))
        if rc != 0:
            return False
        self._load(self.origin)
        self.node_changes[node] = state
        self.modified = True
        return True
    def edit_op(self,op,rsc,rc_code,op_status,node = ''):
        '''
        Set rc-code and op-status in the lrm_rsc_op status
        section element.
        '''
        if not self.get_status():
            return False
        l_op,l_int = split_op(op)
        op_nodes = get_status_ops(self.status_node,rsc,l_op,l_int,node)
        if l_int == "-1" and len(op_nodes) != 1:
            common_err("need interval for the monitor op")
            return False
        if node == '' and len(op_nodes) != 1:
            if op_nodes:
                nodelist = [get_status_node_id(x) for x in op_nodes]
                common_err("operation %s found at %s" % (op,' '.join(nodelist)))
            else:
                common_err("operation %s not found" % op)
            return False
        # either the op is fully specified (maybe not found)
        # or we found exactly one op_node
        if len(op_nodes) == 1:
            op_node = op_nodes[0]
            if not node:
                node = get_status_node_id(op_node)
            if not node:
                common_err("node not found for the operation %s" % op)
                return False
            if l_int == "-1":
                l_int = op_node.getAttribute("interval")
        op_op = op_status == "0" and "-i" or "-F"
        rc = self.inject("%s %s_%s_%s@%s=%s" % \
            (op_op, rsc, l_op, l_int, node, rc_code))
        if rc != 0:
            return False
        self.op_changes[node+":"+rsc+":"+op] = "rc="+rc_code
        if op_status:
            self.op_changes[node+":"+rsc+":"+op] += "," "op-status="+op_status
        self._load(self.origin)
        self.modified = True
        return True

vars = Vars.getInstance()
# vim:ts=4:sw=4:et:
