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

import os
import subprocess
import xml.dom.minidom

from userprefs import Options, UserPrefs
from vars import Vars
from cache import WCache
from msg import *
from utils import *

def xmlparse(f):
    try:
        doc = xml.dom.minidom.parse(f)
    except xml.parsers.expat.ExpatError,msg:
        common_err("cannot parse xml: %s" % msg)
        return None
    return doc
def file2doc(s):
    try: f = open(s,'r')
    except IOError, msg:
        common_err(msg)
        return None
    doc = xmlparse(f)
    f.close()
    return doc

cib_dump = "cibadmin -Ql"
def cibdump2doc(section = None):
    doc = None
    if section:
        cmd = "%s -o %s" % (cib_dump,section)
    else:
        cmd = cib_dump
    cmd = add_sudo(cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    try:
        doc = xmlparse(p.stdout)
        p.wait()
    except IOError, msg:
        common_err(msg)
        return None
    return doc

def get_conf_elem(doc, tag):
    try:
        return doc.getElementsByTagName(tag)[0]
    except:
        return None
def read_cib(fun, params = None):
    doc = fun(params)
    if not doc:
        return doc,None
    cib = doc.childNodes[0]
    if not is_element(cib) or cib.tagName != "cib":
        cib_no_elem_err("cib")
        return doc,None
    return doc,cib

def get_interesting_nodes(node,nodes):
    for c in node.childNodes:
        if is_element(c) and c.tagName in vars.cib_cli_map:
            nodes.append(c)
        get_interesting_nodes(c,nodes)
    return nodes

def resources_xml():
    if wcache.is_cached("rsc_xml"):
        return wcache.retrieve("rsc_xml")
    doc = cibdump2doc("resources")
    if not doc:
        return []
    return wcache.store("rsc_xml",doc)
def rsc2node(id):
    if wcache.is_cached("rsc_%s_node" % id):
        return wcache.retrieve("rsc_%s_node" % id)
    doc = resources_xml()
    if not doc:
        return []
    nodes = get_interesting_nodes(doc,[])
    for n in nodes:
        if is_resource(n) and n.getAttribute("id") == id:
            return wcache.store("rsc_%s_node" % id, n)
def get_meta_param(id,param):
    rsc_meta_show = "crm_resource --meta -r '%s' -g '%s'"
    return get_stdout(rsc_meta_show % (id,param), stderr_on = False)
def is_live_cib():
    '''We working with the live cluster?'''
    return not vars.cib_in_use and not os.getenv("CIB_file")
def is_rsc_running(id):
    if not is_live_cib():
        return False
    rsc_node = rsc2node(id)
    if not rsc_node:
        return False
    if not is_resource(rsc_node):
        return False
    rsc_status = "crm_resource -W -r '%s'"
    test_id = rsc_clone(id) or id
    outp = get_stdout(rsc_status % test_id, stderr_on = False)
    return outp.find("running") > 0 and outp.find("NOT") == -1
def is_rsc_clone(rsc_id):
    rsc_node = rsc2node(rsc_id)
    return is_clone(rsc_node)
def is_rsc_ms(rsc_id):
    rsc_node = rsc2node(rsc_id)
    return is_ms(rsc_node)
def rsc_clone(rsc_id):
    '''Get a clone of a resource.'''
    rsc_node = rsc2node(rsc_id)
    if not rsc_node or not rsc_node.parentNode:
        return None
    pnode = rsc_node.parentNode
    if is_group(pnode):
        pnode = pnode.parentNode
    if is_clonems(pnode):
        return pnode.getAttribute("id")
def get_cloned_rsc(rsc_id):
    rsc_node = rsc2node(rsc_id)
    if not rsc_node:
        return ""
    for c in rsc_node.childNodes:
        if is_child_rsc(c):
            return c.getAttribute("id")
    return ""
def get_max_clone(id):
    v = get_meta_param(id,"clone-max")
    try:
        cnt = int(v)
    except:
        cnt = len(listnodes())
    return cnt
attr_defaults_missing = {
}
def add_missing_attr(node):
    try:
        for defaults in attr_defaults_missing[node.tagName]:
            if not node.hasAttribute(defaults[0]):
                node.setAttribute(defaults[0],defaults[1])
    except: pass
attr_defaults = {
    "rule": (("boolean-op","and"),),
    "expression": (("type","string"),),
}
def drop_attr_defaults(node, ts = 0):
    try:
        for defaults in attr_defaults[node.tagName]:
            if node.getAttribute(defaults[0]) == defaults[1]:
                node.removeAttribute(defaults[0])
    except: pass

def is_element(xmlnode):
    return xmlnode and xmlnode.nodeType == xmlnode.ELEMENT_NODE

def nameandid(xmlnode,level):
    if xmlnode.nodeType == xmlnode.ELEMENT_NODE:
        print level*' ',xmlnode.tagName,xmlnode.getAttribute("id"),xmlnode.getAttribute("name")

def xmltraverse(xmlnode,fun,ts=0):
    for c in xmlnode.childNodes:
        if is_element(c):
            fun(c,ts)
            xmltraverse(c,fun,ts+1)

def xmltraverse_thin(xmlnode,fun,ts=0):
    '''
    Skip elements which may be resources themselves.
    NB: Call this only on resource (or constraint) nodes, but
    never on cib or configuration!
    '''
    for c in xmlnode.childNodes:
        if is_element(c) and not c.tagName in ('primitive','group'):
            xmltraverse_thin(c,fun,ts+1)
    fun(xmlnode,ts)

def xml_processnodes(xmlnode,node_filter,proc):
    '''
    Process with proc all nodes that match filter.
    '''
    node_list = []
    for child in xmlnode.childNodes:
        if node_filter(child):
            node_list.append(child)
        if child.hasChildNodes():
            xml_processnodes(child,node_filter,proc)
    if node_list:
        proc(node_list)

# filter the cib
def is_whitespace(node):
    return node.nodeType == node.TEXT_NODE and not node.data.strip()
def is_comment(node):
    return node.nodeType == node.COMMENT_NODE
def is_status_node(node):
    return is_element(node) and node.tagName == "status"

def is_emptynvpairs(node):
    if is_element(node) and node.tagName in vars.nvpairs_tags:
        for a in vars.precious_attrs:
            if node.getAttribute(a):
                return False
        for n in node.childNodes:
            if is_element(n):
                return False
        return True
    else:
        return False
def is_group(node):
    return is_element(node) \
        and node.tagName == "group"
def is_ms(node):
    return is_element(node) \
        and node.tagName in ("master","ms")
def is_clone(node):
    return is_element(node) \
        and node.tagName == "clone"
def is_clonems(node):
    return is_element(node) \
        and node.tagName in vars.clonems_tags
def is_container(node):
    return is_element(node) \
        and node.tagName in vars.container_tags
def is_primitive(node):
    return is_element(node) \
        and node.tagName == "primitive"
def is_resource(node):
    return is_element(node) \
        and node.tagName in vars.resource_tags
def is_child_rsc(node):
    return is_element(node) \
        and node.tagName in vars.children_tags
def is_constraint(node):
    return is_element(node) \
        and node.tagName in vars.constraint_tags
def is_defaults(node):
    return is_element(node) \
        and node.tagName in vars.defaults_tags
def rsc_constraint(rsc_id,cons_node):
    if not is_element(cons_node):
        return False
    for attr in cons_node.attributes.keys():
        if attr in vars.constraint_rsc_refs \
                and rsc_id == cons_node.getAttribute(attr):
            return True
    for rref in cons_node.getElementsByTagName("resource_ref"):
        if rsc_id == rref.getAttribute("id"):
            return True
    return False

def sort_container_children(node_list):
    '''
    Make sure that attributes's nodes are first, followed by the
    elements (primitive/group). The order of elements is not
    disturbed, they are just shifted to end!
    '''
    for node in node_list:
        children = []
        for c in node.childNodes:
            if is_element(c) and c.tagName in vars.children_tags:
                children.append(c)
        for c in children:
            node.removeChild(c)
        for c in children:
            node.appendChild(c)
def rmnode(node):
    if node and node.parentNode:
        if node.parentNode:
            node.parentNode.removeChild(node)
        node.unlink()
def rmnodes(node_list):
    for node in node_list:
        rmnode(node)
def printid(node_list):
    for node in node_list:
        id = node.getAttribute("id")
        if id: print "node id:",id
def sanitize_cib(doc):
    xml_processnodes(doc,is_status_node,rmnodes)
    #xml_processnodes(doc,is_element,printid)
    xml_processnodes(doc,is_emptynvpairs,rmnodes)
    xml_processnodes(doc,is_whitespace,rmnodes)
    #xml_processnodes(doc,is_comment,rmnodes)
    xml_processnodes(doc,is_container,sort_container_children)
    xmltraverse(doc,drop_attr_defaults)

def is_simpleconstraint(node):
    return len(node.getElementsByTagName("resource_ref")) == 0

match_list = {
    "node": ("uname"),
    "crm_config": (),
    "rsc_defaults": (),
    "op_defaults": (),
    "cluster_property_set": (),
    "instance_attributes": (),
    "meta_attributes": (),
    "operations": (),
    "nvpair": ("name",),
    "op": ("name","interval"),
    "rule": ("score","score-attribute","role"),
    "expression": ("attribute","operation","value"),
}
def add_comment(doc,node,s):
    '''
    Add comment s to node from doc.
    '''
    if not s:
        return
    comm_node = doc.createComment(s)
    if node.hasChildNodes():
        node.insertBefore(comm_node, node.firstChild)
    else:
        node.appendChild(comm_node)
def set_id_used_attr(node):
    node.setAttribute("__id_used", "Yes")
def is_id_used_attr(node):
    return node.getAttribute("__id_used") == "Yes"
def remove_id_used_attr(node,lvl):
    if is_element(node) and is_id_used_attr(node):
        node.removeAttribute("__id_used")
def remove_id_used_attributes(node):
    if node:
        xmltraverse(node, remove_id_used_attr)
def lookup_node(node,oldnode,location_only = False):
    '''
    Find a child of oldnode which matches node.
    '''
    #print "lookup:",node.tagName,node.getAttribute("id"),oldnode.tagName,oldnode.getAttribute("id")
    if not oldnode:
        return None
    try:
        attr_list = match_list[node.tagName]
    except KeyError:
        attr_list = []
    for c in oldnode.childNodes:
        if not is_element(c):
            continue
        if not location_only and is_id_used_attr(c):
            continue
        #print "checking:",c.tagName,c.getAttribute("id")
        if node.tagName == c.tagName:
            failed = False
            for a in attr_list:
                if node.getAttribute(a) != c.getAttribute(a):
                    failed = True
                    break
            if not failed:
                #print "found:",c.tagName,c.getAttribute("id")
                return c
    return None

def nvpairs2list(node, add_id = False):
    '''
    Convert nvpairs to a list of pairs.
    The id attribute is normally skipped, since they tend to be
    long and therefore obscure the relevant content. For some
    elements, however, they are included (e.g. properties).
    '''
    pl = []
    # if there's id-ref, there can be then _only_ id-ref
    value = node.getAttribute("id-ref")
    if value:
        pl.append(["$id-ref",value])
        return pl
    if add_id or \
            (not node.childNodes and len(node.attributes) == 1):
        value = node.getAttribute("id")
        if value:
            pl.append(["$id",value])
    for c in node.childNodes:
        if not is_element(c):
            continue
        if c.tagName == "attributes":
            pl = nvpairs2list(c)
        name = c.getAttribute("name")
        if "value" in c.attributes.keys():
            value = c.getAttribute("value")
        else:
            value = None
        pl.append([name,value])
    return pl

vars = Vars.getInstance()
wcache = WCache.getInstance()
# vim:ts=4:sw=4:et:
