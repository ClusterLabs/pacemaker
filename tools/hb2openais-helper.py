#!/usr/bin/env python

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

import os,sys
import getopt
import xml.dom.minidom

def usage():
    print "usage: %s [-T] [-c ha_cf] {zap_nodes|ignore_quorum|analyze_cib|convert_cib}"%sys.argv[0]
    sys.exit(1)

TEST = False
try:
    optlist, arglist = getopt.getopt(sys.argv[1:], "hTc:")
except getopt.GetoptError:
    usage()
for opt,arg in optlist:
    if opt == '-h':
        usage()
    elif opt == '-c':
        HA_CF = arg
    elif opt == '-T':
        TEST = True
if len(arglist) != 1:
    usage()

def load_cib():
    doc = xml.dom.minidom.parse(sys.stdin)
    return doc
def is_whitespace(node):
    return node.nodeType == node.TEXT_NODE and not node.data.strip()
def rmnodes(node_list):
    for node in node_list:
        node.parentNode.removeChild(node)
        node.unlink()
def is_element(xmlnode):
    return xmlnode.nodeType == xmlnode.ELEMENT_NODE
def xml_processnodes(xmlnode,filter,proc):
    '''
    Process with proc all nodes that match filter.
    '''
    node_list = []
    for child in xmlnode.childNodes:
        if filter(child):
            node_list.append(child)
        elif child.hasChildNodes():
            xml_processnodes(child,filter,proc)
    if node_list:
        proc(node_list)
def skip_first(s):
    l = s.split('\n')
    return '\n'.join(l[1:])
def get_attribute(tag,node,p):
    attr_set = node.getElementsByTagName(tag)
    if not attr_set:
        return ''
    attributes = attr_set[0].getElementsByTagName("attributes")
    if not attributes:
        return ''
    attributes = attributes[0]
    for nvpair in attributes.getElementsByTagName("nvpair"):
        if p == nvpair.getAttribute("name"):
            return nvpair.getAttribute("value")
    return ''
def get_param(node,p):
    return get_attribute("instance_attributes",node,p)
def mknvpair(id,name,value):
    nvpair = doc.createElement("nvpair")
    nvpair.setAttribute("id",id + "-" + name)
    nvpair.setAttribute("name",name)
    nvpair.setAttribute("value",value)
    return nvpair
def set_attribute(tag,node,p,value):
    id = node.getAttribute("id")
    attr_set = node.getElementsByTagName(tag)
    if not attr_set:
        return
    attributes = attr_set[0].getElementsByTagName("attributes")
    if not attributes:
        attributes = doc.createElement("attributes")
        attr_set.appendChild(attributes)
    else:
        attributes = attributes[0]
    for nvp in attributes.getElementsByTagName("nvpair"):
        if p == nvp.getAttribute("name"):
            nvp.setAttribute("value",value)
            return
    attributes.appendChild(mknvpair(id,p,value))

doc = load_cib()
xml_processnodes(doc,is_whitespace,rmnodes)
resources = doc.getElementsByTagName("resources")[0]
constraints = doc.getElementsByTagName("constraints")[0]
nodes = doc.getElementsByTagName("nodes")[0]
crm_config = doc.getElementsByTagName("crm_config")[0]
if not resources:
    print >> sys.stderr, "ERROR: sorry, no resources section in the CIB, cannot proceed"
    sys.exit(1)
if not constraints:
    print >> sys.stderr, "ERROR: sorry, no constraints section in the CIB, cannot proceed"
    sys.exit(1)
if not nodes:
    print >> sys.stderr, "ERROR: sorry, no nodes section in the CIB, cannot proceed"
    sys.exit(1)

if arglist[0] == "zap_nodes":
    xml_processnodes(nodes,lambda x:1,rmnodes)
    s = skip_first(doc.toprettyxml())
    print s
    sys.exit(0)

if arglist[0] == "ignore_quorum":
    set_attribute("cluster_property_set",crm_config,"no-quorum-policy","ignore")
    s = skip_first(doc.toprettyxml())
    print s
    sys.exit(0)

if arglist[0] == "analyze_cib":
    rc = 0
    for rsc in doc.getElementsByTagName("primitive"):
        rsc_type = rsc.getAttribute("type")
        if rsc_type == "EvmsSCC":
            print >> sys.stderr, "INFO: evms configuration found; conversion required"
            rc = 1
        elif rsc_type == "Filesystem":
            if get_param(rsc,"fstype") == "ocfs2":
                print >> sys.stderr, "INFO: ocfs2 configuration found; conversion required"
                rc = 1
    sys.exit(rc)

def rm_attribute(tag,node,p):
    attr_set = node.getElementsByTagName(tag)
    if not attr_set:
        return ''
    attributes = attr_set[0].getElementsByTagName("attributes")
    if not attributes:
        return ''
    attributes = attributes[0]
    for nvpair in attributes.getElementsByTagName("nvpair"):
        if p == nvpair.getAttribute("name"):
            nvpair.parentNode.removeChild(nvpair)
def set_param(node,p,value):
    set_attribute("instance_attributes",node,p,value)
def rm_param(node,p):
    rm_attribute("instance_attributes",node,p)
def rmnodes(node_list):
    for node in node_list:
        node.parentNode.removeChild(node)
        node.unlink()
def evms2lvm(node,a):
    v = node.getAttribute(a)
    if v:
        v = v.replace("EVMS","LVM")
        v = v.replace("Evms","LVM")
        v = v.replace("evms","lvm")
        node.setAttribute(a,v)
def replace_evms_strings(node_list):
    for node in node_list:
        evms2lvm(node,"id")
        if node.tagName in ("rsc_colocation","rsc_order"):
            evms2lvm(node,"to")
            evms2lvm(node,"from")

def get_input(msg):
    if TEST:
        print >> sys.stderr, "%s: setting to /dev/null" % msg
        return "/dev/null"
    while True:
        ans = raw_input(msg)
        if ans:
            if os.access(ans,os.F_OK):
                return ans
            else:
                print >> sys.stderr, "Cannot read %s" % ans
        print >> sys.stderr, "We do need this input to continue."
def mk_lvm(rsc_id,volgrp):
    node = doc.createElement("primitive")
    node.setAttribute("id",rsc_id)
    node.setAttribute("type","LVM")
    node.setAttribute("provider","heartbeat")
    node.setAttribute("class","ocf")
    operations = doc.createElement("operations")
    node.appendChild(operations)
    mon_op = doc.createElement("op")
    operations.appendChild(mon_op)
    mon_op.setAttribute("id", rsc_id + "_mon")
    mon_op.setAttribute("name","monitor")
    interval = "120s"
    timeout = "60s"
    mon_op.setAttribute("interval", interval)
    mon_op.setAttribute("timeout", timeout)
    instance_attributes = doc.createElement("instance_attributes")
    instance_attributes.setAttribute("id", rsc_id + "_inst_attr")
    node.appendChild(instance_attributes)
    attributes = doc.createElement("attributes")
    instance_attributes.appendChild(attributes)
    attributes.appendChild(mknvpair(rsc_id,"volgrpname",volgrp))
    return node
def mk_clone(id,ra_type,ra_class,prov):
    c = doc.createElement("clone")
    c.setAttribute("id",id + "-clone")
    meta = doc.createElement("meta_attributes")
    c.appendChild(meta)
    meta.setAttribute("id",id + "_meta")
    attributes = doc.createElement("attributes")
    meta.appendChild(attributes)
    attributes.appendChild(mknvpair(id,"globally-unique","false"))
    attributes.appendChild(mknvpair(id,"interleave","true"))
    p = doc.createElement("primitive")
    c.appendChild(p)
    p.setAttribute("id",id)
    p.setAttribute("type",ra_type)
    if prov:
        p.setAttribute("provider",prov)
    p.setAttribute("class",ra_class)
    operations = doc.createElement("operations")
    p.appendChild(operations)
    mon_op = doc.createElement("op")
    operations.appendChild(mon_op)
    mon_op.setAttribute("id", id + "_mon")
    mon_op.setAttribute("name","monitor")
    interval = "60s"
    timeout = "30s"
    mon_op.setAttribute("interval", interval)
    mon_op.setAttribute("timeout", timeout)
    return c
def add_ocfs_clones(id):
    c1 = mk_clone("o2cb","o2cb","lsb","")
    c2 = mk_clone("dlm","controld","ocf","pacemaker")
    resources.appendChild(c1)
    resources.appendChild(c2)
    c1 = mk_order("dlm-clone","o2cb-clone")
    c2 = mk_colocation("dlm-clone","o2cb-clone")
    constraints.appendChild(c1)
    constraints.appendChild(c2)
def mk_order(r1,r2):
    rsc_order = doc.createElement("rsc_order")
    rsc_order.setAttribute("id","rsc_order_"+r1+"_"+r2)
    rsc_order.setAttribute("from",r1)
    rsc_order.setAttribute("to",r2)
    rsc_order.setAttribute("type","before")
    rsc_order.setAttribute("symmetrical","true")
    return rsc_order
def mk_colocation(r1,r2):
    rsc_colocation = doc.createElement("rsc_colocation")
    rsc_colocation.setAttribute("id","rsc_colocation_"+r1+"_"+r2)
    rsc_colocation.setAttribute("from",r1)
    rsc_colocation.setAttribute("to",r2)
    rsc_colocation.setAttribute("score","INFINITY")
    return rsc_colocation
def add_ocfs_constraints(rsc,id):
    node = rsc.parentNode
    if node.tagName != "clone":
        node = rsc
    clone_id = node.getAttribute("id")
    c1 = mk_order("o2cb-clone",clone_id)
    c2 = mk_colocation("o2cb-clone",clone_id)
    constraints.appendChild(c1)
    constraints.appendChild(c2)
def change_ocfs2_device(rsc):
    print >> sys.stderr, "The current device for ocfs2 depends on evms: %s"%get_param(rsc,"device")
    dev = get_input("Please supply the device where %s ocfs2 resource resides: "%rsc.getAttribute("id"))
    set_param(rsc,"device",dev)
def stop_ocfs2(rsc):
    node = rsc.parentNode
    if node.tagName != "clone":
        node = rsc
    id = node.getAttribute("id")
    l = rsc.getElementsByTagName("meta_attributes")
    if l:
        meta = l[0]
    else:
        meta = doc.createElement("meta_attributes")
        meta.setAttribute("id",id + "_meta")
        node.appendChild(meta)
        attributes = doc.createElement("attributes")
        meta.appendChild(attributes)
    rm_param(rsc,"target_role")
    set_attribute("meta_attributes",node,"target_role","Stopped")
def new_pingd_rsc(options,host_list):
    rsc_id = "pingd"
    c = mk_clone(rsc_id,"pingd","ocf","pacemaker")
    node = c.getElementsByTagName("primitive")[0]
    instance_attributes = doc.createElement("instance_attributes")
    instance_attributes.setAttribute("id", rsc_id + "_inst_attr")
    node.appendChild(instance_attributes)
    attributes = doc.createElement("attributes")
    instance_attributes.appendChild(attributes)
    attributes.appendChild(mknvpair(rsc_id,"options",options))
    return c
def replace_evms_ids():
    return c
def handle_pingd_respawn():
    f = open(HA_CF or "/etc/ha.d/ha.cf", 'r')
    opts = ''
    ping_list = []
    for l in f:
        s = l.split()
        if not s:
            continue
        if s[0] == "respawn" and s[2].find("pingd") > 0:
            opts = ' '.join(s[3:])
        elif s[0] == "ping":
            ping_list.append(s[1])
    f.close()
    return opts,' '.join(ping_list)
def process_cib():
    ocfs_clones = []
    evms_present = False

    for rsc in doc.getElementsByTagName("primitive"):
        rsc_id = rsc.getAttribute("id")
        rsc_type = rsc.getAttribute("type")
        if rsc_type == "Evmsd":
            print >> sys.stderr, "INFO: removing the Evmsd resource"
            resources.removeChild(rsc)
        elif rsc_type == "EvmsSCC":
            evms_present = True
            print >> sys.stderr, "INFO: EvmsSCC resource is going to be replaced by LVM"
            vg = get_input("Please supply the VG name corresponding to %s: "%rsc_id)
            node = mk_lvm(rsc_id,vg)
            parent = rsc.parentNode
            parent.removeChild(rsc)
            parent.appendChild(node)
            rsc.unlink()
        elif rsc_type == "pingd":
            if pingd_host_list:
                set_param(rsc,"host_list",pingd_host_list)
        elif rsc_type == "Filesystem":
            if get_param(rsc,"fstype") == "ocfs2":
                if get_param(rsc,"device").find("evms") > 0:
                    change_ocfs2_device(rsc)
                ocfs_clones.append(rsc)
                id = rsc.getAttribute("id")
                print >> sys.stderr, "INFO: adding constraints for %s"%id
                add_ocfs_constraints(rsc,id)
                print >> sys.stderr, "INFO: adding target_role=Stopped to %s"%id
                stop_ocfs2(rsc)
    if ocfs_clones:
        print >> sys.stderr, "INFO: adding required cloned resources for ocfs2"
        add_ocfs_clones(id)
    if evms_present:
        xml_processnodes(doc,lambda x:1,replace_evms_strings)

if arglist[0] == "convert_cib":
    opts,pingd_host_list = handle_pingd_respawn()
    if opts:
        clone = new_pingd_rsc(opts,pingd_host_list)
        resources.appendChild(clone)
    process_cib()
    s = skip_first(doc.toprettyxml())
    print s
    sys.exit(0)

# shouldn't get here
usage()

# vim:ts=4:sw=4:et:
