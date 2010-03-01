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
from clidisplay import CliDisplay
from xmlutil import *
from utils import *
from msg import *

#
# CLI format generation utilities (from XML)
#
def cli_format(pl,format):
    if format > 0:
        return ' \\\n\t'.join(pl)
    else:
        return ' '.join(pl)
def cli_operations(node,format = 1):
    l = []
    node_id = node.getAttribute("id")
    s = ''
    if node_id:
        s = '$id="%s"' % node_id
    idref = node.getAttribute("id-ref")
    if idref:
        s = '%s $id-ref="%s"' % (s,idref)
    if s:
        l.append("%s %s" % (cli_display.keyword("operations"),s))
    for c in node.childNodes:
        if is_element(c) and c.tagName == "op":
            l.append(cli_op(c))
    return cli_format(l,format)
def nvpair_format(n,v):
    return v == None and cli_display.attr_name(n) \
        or '%s="%s"'%(cli_display.attr_name(n),cli_display.attr_value(v))
def cli_pairs(pl):
    'Return a string of name="value" pairs (passed in a list of pairs).'
    l = []
    for n,v in pl:
        l.append(nvpair_format(n,v))
    return ' '.join(l)

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
        elif c.tagName != "nvpair":
            node_err("expected nvpair got", c)
            continue
        name = c.getAttribute("name")
        if "value" in c.attributes.keys():
            value = c.getAttribute("value")
        else:
            value = None
        pl.append([name,value])
    return pl

def op2list(node):
    pl = []
    action = ""
    for name in node.attributes.keys():
        if name == "name":
            action = node.getAttribute(name)
        elif name != "id": # skip the id
            pl.append([name,node.getAttribute(name)])
    if not action:
        common_err("op is invalid (no name)")
    return action,pl
def op_instattr(node):
    pl = []
    for c in node.childNodes:
        if not is_element(c):
            continue
        if c.tagName != "instance_attributes":
            common_err("only instance_attributes are supported in operations")
        else:
            pl += nvpairs2list(c)
    return pl
def cli_op(node):
    action,pl = op2list(node)
    if not action:
        return ""
    pl += op_instattr(node)
    return "%s %s %s" % (cli_display.keyword("op"),action,cli_pairs(pl))
def date_exp2cli(node):
    l = []
    operation = node.getAttribute("operation")
    l.append(cli_display.keyword("date"))
    l.append(cli_display.keyword(operation))
    if operation in olist(vars.simple_date_ops):
        value = node.getAttribute(keyword_cmp(operation,'lt') and "end" or "start")
        l.append('"%s"' % cli_display.attr_value(value))
    else:
        if operation == 'in_range':
            for name in vars.in_range_attrs:
                v = node.getAttribute(name)
                if v:
                    l.append(nvpair_format(name,v))
        for c in node.childNodes:
            if is_element(c) and c.tagName in ("duration","date_spec"):
                pl = []
                for name in c.attributes.keys():
                    if name != "id":
                        pl.append([name,c.getAttribute(name)])
                l.append(cli_pairs(pl))
    return ' '.join(l)
def binary_op_format(op):
    l = op.split(':')
    if len(l) == 2:
        return "%s:%s" % (l[0], cli_display.keyword(l[1]))
    else:
        return cli_display.keyword(op)
def exp2cli(node):
    operation = node.getAttribute("operation")
    type = node.getAttribute("type")
    if type:
        operation = "%s:%s" % (type, operation)
    attribute = node.getAttribute("attribute")
    value = node.getAttribute("value")
    if not value:
        return "%s %s" % (binary_op_format(operation),attribute)
    else:
        return "%s %s %s" % (attribute,binary_op_format(operation),value)
def get_score(node):
    score = node.getAttribute("score")
    if not score:
        score = node.getAttribute("score-attribute")
    else:
        if score.find("INFINITY") >= 0:
            score = score.replace("INFINITY","inf")
    return score + ":"
def cli_rule(node):
    s = []
    node_id = node.getAttribute("id")
    if node_id:
        s.append('$id="%s"' % node_id)
    else:
        idref = node.getAttribute("id-ref")
        if idref:
            return '$id-ref="%s"' % idref
    rsc_role = node.getAttribute("role")
    if rsc_role:
        s.append('$role="%s"' % rsc_role)
    s.append(cli_display.score(get_score(node)))
    bool_op = node.getAttribute("boolean-op")
    if not bool_op:
        bool_op = "and"
    exp = []
    for c in node.childNodes:
        if not is_element(c):
            continue
        if c.tagName == "date_expression":
            exp.append(date_exp2cli(c))
        elif c.tagName == "expression":
            exp.append(exp2cli(c))
    expression = (" %s "%cli_display.keyword(bool_op)).join(exp)
    return "%s %s" % (' '.join(s),expression)
def cli_add_description(node,l):
    desc = node.getAttribute("description")
    if desc:
        l.append(nvpair_format("description",desc))

def mkrscrole(node,n):
    rsc = cli_display.rscref(node.getAttribute(n))
    rsc_role = node.getAttribute(n + "-role")
    if rsc_role:
        return "%s:%s"%(rsc,rsc_role)
    else:
        return rsc
def mkrscaction(node,n):
    rsc = cli_display.rscref(node.getAttribute(n))
    rsc_action = node.getAttribute(n + "-action")
    if rsc_action:
        return "%s:%s"%(rsc,rsc_action)
    else:
        return rsc
def rsc_set_constraint(node,obj_type):
    col = []
    cnt = 0
    for n in node.getElementsByTagName("resource_set"):
        sequential = True
        if n.getAttribute("sequential") == "false":
            sequential = False
        if not sequential:
            col.append("(")
        role = n.getAttribute("role")
        action = n.getAttribute("action")
        for r in n.getElementsByTagName("resource_ref"):
            rsc = cli_display.rscref(r.getAttribute("id"))
            q = (obj_type == "colocation") and role or action
            col.append(q and "%s:%s"%(rsc,q) or rsc)
            cnt += 1
        if not sequential:
            col.append(")")
    if cnt <= 2: # a degenerate thingie
        col.insert(0,"_rsc_set_")
    return col
def two_rsc_constraint(node,obj_type):
    col = []
    if obj_type == "colocation":
        col.append(mkrscrole(node,"rsc"))
        col.append(mkrscrole(node,"with-rsc"))
    else:
        col.append(mkrscaction(node,"first"))
        col.append(mkrscaction(node,"then"))
    return col
#
################################################################

vars = Vars.getInstance()
cli_display = CliDisplay.getInstance()

# vim:ts=4:sw=4:et:
