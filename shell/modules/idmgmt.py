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

from vars import Vars
from xmlutil import *
from msg import *

class IdMgmt(Singleton):
    '''
    Make sure that ids are unique.
    '''
    def __init__(self):
        self._id_store = {}
        self.ok = True # error var
    def new(self,node,pfx):
        '''
        Create a unique id for the xml node.
        '''
        name = node.getAttribute("name")
        if node.tagName == "nvpair":
            node_id = "%s-%s" % (pfx,name)
        elif node.tagName == "op":
            interval = node.getAttribute("interval")
            if interval:
                node_id = "%s-%s-%s" % (pfx,name,interval)
            else:
                node_id = "%s-%s" % (pfx,name)
        else:
            try:
                subpfx = vars.subpfx_list[node.tagName]
            except: subpfx = ''
            if subpfx:
                node_id = "%s-%s" % (pfx,subpfx)
            else:
                node_id = "%s" % pfx
        if self.is_used(node_id):
            for cnt in range(99): # shouldn't really get here
                try_id = "%s-%d" % (node_id,cnt)
                if not self.is_used(try_id):
                    node_id = try_id
                    break
        self.save(node_id)
        return node_id
    def check_node(self,node,lvl):
        node_id = node.getAttribute("id")
        if not node_id:
            return
        if self.id_in_use(node_id):
            common_error("id_store: id %s is in use" % node_id)
            self.ok = False
            return
    def _store_node(self,node,lvl):
        self.save(node.getAttribute("id"))
    def _drop_node(self,node,lvl):
        self.remove(node.getAttribute("id"))
    def check_xml(self,node):
        self.ok = True
        xmltraverse_thin(node,self.check_node)
        return self.ok
    def store_xml(self,node):
        if not self.check_xml(node):
            return False
        xmltraverse_thin(node,self._store_node)
        return True
    def remove_xml(self,node):
        xmltraverse_thin(node,self._drop_node)
    def replace_xml(self,oldnode,newnode):
        self.remove_xml(oldnode)
        if not self.store_xml(newnode):
            self.store_xml(oldnode)
            return False
        return True
    def is_used(self,node_id):
        return node_id in self._id_store
    def id_in_use(self,obj_id):
        if self.is_used(obj_id):
            id_used_err(obj_id)
            return True
        return False
    def save(self,node_id):
        if not node_id: return
        common_debug("id_store: saved %s" % node_id)
        self._id_store[node_id] = 1
    def rename(self,old_id,new_id):
        if not old_id or not new_id: return
        if not self.is_used(old_id): return
        if self.is_used(new_id): return
        self.remove(old_id)
        self.save(new_id)
    def remove(self,node_id):
        if not node_id: return
        try:
            del self._id_store[node_id]
            common_debug("id_store: removed %s" % node_id)
        except KeyError:
            pass
    def clear(self):
        self._id_store = {}

vars = Vars.getInstance()

# vim:ts=4:sw=4:et:
