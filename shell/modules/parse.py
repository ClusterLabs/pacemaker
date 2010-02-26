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

import shlex
import re
import xml.dom.minidom
from utils import *
from vars import Vars
from msg import *
from ra import disambiguate_ra_type, ra_type_validate

#
# CLI parsing utilities
# WARNING: ugly code ahead (to be replaced some day by a proper
# yacc parser, if there's such a thing)
#
def cli_parse_rsctype(s, pl):
    '''
    Parse the resource type.
    '''
    ra_class,provider,rsc_type = disambiguate_ra_type(s)
    if not ra_type_validate(s,ra_class,provider,rsc_type):
        return None
    pl.append(["class",ra_class])
    if ra_class == "ocf":
        pl.append(["provider",provider])
    pl.append(["type",rsc_type])
def is_attribute(p,a):
    return p.startswith(a + '=')
def cli_parse_attr_strict(s,pl):
    '''
    Parse attributes in the 'p=v' form.
    '''
    if s and '=' in s[0]:
        n,v = s[0].split('=',1)
        if not n:
            return
        pl.append([n,v])
        cli_parse_attr_strict(s[1:],pl)
def cli_parse_attr(s,pl):
    '''
    Parse attributes in the 'p=v' form.
    Allow also the 'p' form (no value) unless p is one of the
    attr_list_keyw words.
    '''
    attr_lists_keyw = olist(["params","meta","operations","op","attributes"])
    if s:
        if s[0] in attr_lists_keyw:
            return
        if '=' in s[0]:
            n,v = s[0].split('=',1)
        else:
            n = s[0]; v = None
        if not n:
            return
        pl.append([n,v])
        cli_parse_attr(s[1:],pl)
def is_only_id(pl,keyw):
    if len(pl) > 1:
        common_err("%s: only single $id or $id-ref attribute is allowed" % keyw)
        return False
    if len(pl) == 1 and pl[0][0] not in ("$id","$id-ref"):
        common_err("%s: only single $id or $id-ref attribute is allowed" % keyw)
        return False
    return True
def check_operation(pl):
    op_name = find_value(pl,"name")
    if not op_name in olist(vars.op_cli_names):
        common_warn("%s: operation not recognized" % op_name)
    if op_name == "monitor" and not find_value(pl,"interval"):
        common_err("monitor requires interval")
        return False
    return True
def parse_resource(s):
    el_type = s[0].lower()
    if el_type == "master": # ugly kludge :(
        el_type = "ms"
    attr_lists_keyw = olist(["params","meta"])
    cli_list = []
    # the head
    head = []
    head.append(["id",s[1]])
    i = 3
    if el_type == "primitive":
        cli_parse_rsctype(s[2],head)
        if not find_value(head,"type"):
            syntax_err(s[2:], context = "primitive")
            return False
    else:
        cl = []
        cl.append(s[2])
        if el_type == "group":
            while i < len(s):
                if s[i] in attr_lists_keyw:
                    break
                elif is_attribute(s[i],"description"):
                    break
                else:
                    cl.append(s[i])
                    i += 1 # skip to the next token
        head.append(["$children",cl])
    try:  # s[i] may be out of range
        if is_attribute(s[i],"description"):
            cli_parse_attr(s[i:i+1],head)
            i += 1 # skip to the next token
    except: pass
    cli_list.append([el_type,head])
    # the rest
    state = 0 # 1: reading operations; 2: operations read
    while len(s) > i+1:
        pl = []
        keyw = s[i].lower()
        if keyw in attr_lists_keyw:
            if state == 1:
                state = 2
        elif el_type == "primitive" and state == 0 and keyword_cmp(keyw, "operations"):
            state = 1
        elif el_type == "primitive" and state <= 1 and keyword_cmp(keyw, "op"):
            if state == 0:
                state = 1
            pl.append(["name",s[i+1]])
        else:
            syntax_err(s[i:], context = 'primitive')
            return False
        if keyword_cmp(keyw, "op"):
            if len(s) > i+2:
                cli_parse_attr(s[i+2:],pl)
            if not check_operation(pl):
                return False
        else:
            cli_parse_attr(s[i+1:],pl)
            if len(pl) == 0:
                syntax_err(s[i:], context = 'primitive')
                return False
        if keyword_cmp(keyw, "operations") and not is_only_id(pl,keyw):
            return False
        i += len(pl)+1
        # interval is obligatory for ops, supply 0 if not there
        if keyword_cmp(keyw, "op") and not find_value(pl,"interval"):
            pl.append(["interval","0"])
        cli_list.append([keyw,pl])
    if len(s) > i:
        syntax_err(s[i:], context = 'primitive')
        return False
    return cli_list
def parse_op(s):
    if len(s) != 3:
        syntax_err(s, context = s[0])
        return False
    cli_list = []
    head_pl = []
    # this is an op
    cli_list.append(["op",head_pl])
    if not cli_parse_rsc_role(s[1],head_pl):
        return False
    if not cli_parse_op_times(s[2],head_pl):
        return False
    # rename rsc-role to role
    for i in range(len(head_pl)):
        if head_pl[i][0] == "rsc-role":
            head_pl[i][0] = "role"
            break
    # add the operation name
    head_pl.append(["name",s[0]])
    return cli_list

def cli_parse_score(score,pl,noattr = False):
    if score.endswith(':'):
        score = score.rstrip(':')
    else:
        syntax_err(score, context = 'score')
        return False
    if score in vars.score_types:
        pl.append(["score",vars.score_types[score]])
    elif re.match("^[+-]?(inf|infinity|INFINITY|[[0-9]+)$",score):
        score = score.replace("infinity","INFINITY")
        score = score.replace("inf","INFINITY")
        pl.append(["score",score])
    elif score:
        if noattr:
            common_err("attribute not allowed for score in orders")
            return False
        else:
            pl.append(["score-attribute",score])
    return True
def is_binary_op(s):
    l = s.split(':')
    if len(l) == 2:
        return l[0] in vars.binary_types and l[1] in olist(vars.binary_ops)
    elif len(l) == 1:
        return l[0] in olist(vars.binary_ops)
    else:
        return False
def cli_parse_binary_op(s,pl):
    l = s.split(':')
    if len(l) == 2:
        pl.append(["type",l[0]])
        pl.append(["operation",l[1]])
    else:
        pl.append(["operation",l[0]])
def cli_parse_expression(s,pl):
    if len(s) > 1 and s[0] in olist(vars.unary_ops):
        pl.append(["operation",s[0]])
        pl.append(["attribute",s[1]])
    elif len(s) > 2 and is_binary_op(s[1]):
        pl.append(["attribute",s[0]])
        cli_parse_binary_op(s[1],pl)
        pl.append(["value",s[2]])
    else:
        return False
    return True
def cli_parse_dateexpr(s,pl):
    if len(s) < 3:
        return False
    if s[1] not in olist(vars.date_ops):
        return False
    pl.append(["operation",s[1]])
    if s[1] in olist(vars.simple_date_ops):
        pl.append([keyword_cmp(s[1], 'lt') and "end" or "start",s[2]])
        return True
    cli_parse_attr_strict(s[2:],pl)
    return True
def parse_rule(s):
    if not keyword_cmp(s[0], "rule"):
        syntax_err(s,context = "rule")
        return 0,None
    rule_list = []
    head_pl = []
    rule_list.append([s[0].lower(),head_pl])
    i = 1
    cli_parse_attr_strict(s[i:],head_pl)
    i += len(head_pl)
    if find_value(head_pl,"$id-ref"):
        return i,rule_list
    if not cli_parse_score(s[i],head_pl):
        return i,None
    i += 1
    bool_op = ''
    while len(s) > i+1:
        pl = []
        if keyword_cmp(s[i], "date"):
            fun = cli_parse_dateexpr
            elem = "date_expression"
        else:
            fun = cli_parse_expression
            elem = "expression"
        if not fun(s[i:],pl):
            syntax_err(s[i:],context = "rule")
            return i,None
        rule_list.append([elem,pl])
        i += len(pl)
        if find_value(pl, "type"):
            i -= 1 # reduce no of tokens by one if there was "type:op"
        if elem == "date_expression":
            i += 1 # increase no of tokens by one if it was date expression
        if len(s) > i and s[i] in olist(vars.boolean_ops):
            if bool_op and not keyword_cmp(bool_op, s[i]):
                common_err("rule contains different bool operations: %s" % ' '.join(s))
                return i,None
            else:
                bool_op = s[i].lower()
                i += 1
        if len(s) > i and keyword_cmp(s[i], "rule"):
            break
    if bool_op and not keyword_cmp(bool_op, 'and'):
        head_pl.append(["boolean-op",bool_op])
    return i,rule_list
def parse_location(s):
    cli_list = []
    head_pl = []
    head_pl.append(["id",s[1]])
    head_pl.append(["rsc",s[2]])
    cli_list.append([s[0].lower(),head_pl])
    if len(s) == 5 and not keyword_cmp(s[3], "rule"): # the short node preference form
        if not cli_parse_score(s[3],head_pl):
            return False
        head_pl.append(["node",s[4]])
        return cli_list
    i = 3
    while i < len(s):
        numtoks,l = parse_rule(s[i:])
        if not l:
            return False
        cli_list += l
        i += numtoks
    if len(s) < i:
        syntax_err(s[i:],context = "location")
        return False
    return cli_list

def cli_opt_symmetrical(p,pl):
    if not p:
        return True
    pl1 = []
    cli_parse_attr([p],pl1)
    if len(pl1) != 1 or not find_value(pl1,"symmetrical"):
        syntax_err(p,context = "order")
        return False
    pl += pl1
    return True
def cli_parse_rsc_role(s,pl,attr_pfx = ''):
    l = s.split(':')
    pl.append([attr_pfx+"rsc",l[0]])
    if len(l) == 2:
        if l[1] not in vars.roles_names:
            bad_def_err("resource role",s)
            return False
        pl.append([attr_pfx+"rsc-role",l[1]])
    elif len(l) > 2:
        bad_def_err("resource role",s)
        return False
    return True
def cli_parse_op_times(s,pl):
    l = s.split(':')
    pl.append(["interval",l[0]])
    if len(l) == 2:
        pl.append(["timeout",l[1]])
    elif len(l) > 2:
        bad_def_err("op times",s)
        return False
    return True

class ResourceSet(object):
    '''
    Constraint resource set parser. Parses sth like:
    a ( b c:start ) d:Master e ...
    Appends one or more lists to cli_list.
    Lists are in form:
        list :: ["resource_set",set_pl]
        set_pl :: [["sequential","false"], ["action"|"role",action|role],
            ["resource_ref",["id",rsc]], ...]
        (the first two elements of set_pl are optional)
    Action/role change makes a new resource set.
    '''
    def __init__(self,type,s,cli_list):
        self.type = type
        self.valid_q = (type == "order") and vars.actions_names or vars.roles_names
        self.q_attr = (type == "order") and "action" or "role"
        self.tokens = s
        self.cli_list = cli_list
        self.reset_set()
        self.sequential = True
        self.fix_parentheses()
    def fix_parentheses(self):
        newtoks = []
        for p in self.tokens:
            if p.startswith('(') and len(p) > 1:
                newtoks.append('(')
                newtoks.append(p[1:])
            elif p.endswith(')') and len(p) > 1:
                newtoks.append(p[0:len(p)-1])
                newtoks.append(')')
            else:
                newtoks.append(p)
        self.tokens = newtoks
    def reset_set(self):
        self.set_pl = []
        self.prev_q = ''  # previous qualifier (action or role)
        self.curr_attr = ''  # attribute (action or role)
    def save_set(self):
        if not self.set_pl:
            return
        if self.curr_attr:
            self.set_pl.insert(0,[self.curr_attr,self.prev_q])
        if not self.sequential:
            self.set_pl.insert(0,["sequential","false"])
        self.cli_list.append(["resource_set",self.set_pl])
        self.reset_set()
    def splitrsc(self,p):
        l = p.split(':')
        return (len(l) == 1) and [p,''] or l
    def parse(self):
        tokpos = -1
        for p in self.tokens:
            tokpos += 1
            if p == "_rsc_set_":
                continue # a degenerate resource set
            if p == '(':
                if self.set_pl: # save the set before
                    self.save_set()
                self.sequential = False
                continue
            if p == ')':
                if self.sequential:  # no '('
                    syntax_err(self.tokens[tokpos:],context = self.type)
                    return False
                if not self.set_pl:  # empty sets not allowed
                    syntax_err(self.tokens[tokpos:],context = self.type)
                    return False
                self.save_set()
                self.sequential = True
                continue
            rsc,q = self.splitrsc(p)
            if q != self.prev_q: # one set can't have different roles/actions
                self.save_set()
                self.prev_q = q
            if q:
                if q not in self.valid_q:
                    common_err("%s: invalid %s in %s" % (q,self.q_attr,self.type))
                    return False
                if not self.curr_attr:
                    self.curr_attr = self.q_attr
            else:
                self.curr_attr = ''
            self.set_pl.append(["resource_ref",["id",rsc]])
        if not self.sequential: # no ')'
            syntax_err(self.tokens[tokpos:],context = self.type)
            return False
        if self.set_pl: # save the final set
            self.save_set()
        return True

def parse_colocation(s):
    cli_list = []
    head_pl = []
    type = s[0]
    if type == "collocation": # another ugly :(
        type = "colocation"
    cli_list.append([type,head_pl])
    if len(s) < 5:
        syntax_err(s,context = "colocation")
        return False
    head_pl.append(["id",s[1]])
    if not cli_parse_score(s[2],head_pl):
        return False
    if len(s) == 5:
        if not cli_parse_rsc_role(s[3],head_pl):
            return False
        if not cli_parse_rsc_role(s[4],head_pl,'with-'):
            return False
    else:
        resource_set_obj = ResourceSet(type,s[3:],cli_list)
        if not resource_set_obj.parse():
            return False
    return cli_list
def cli_parse_rsc_action(s,pl,rsc_pos):
    l = s.split(':')
    pl.append([rsc_pos,l[0]])
    if len(l) == 2:
        if l[1] not in vars.actions_names:
            bad_def_err("resource action",s)
            return False
        pl.append([rsc_pos+"-action",l[1]])
    elif len(l) > 1:
        bad_def_err("resource action",s)
        return False
    return True

def parse_order(s):
    cli_list = []
    head_pl = []
    type = "order"
    cli_list.append([s[0],head_pl])
    if len(s) < 5:
        syntax_err(s,context = "order")
        return False
    head_pl.append(["id",s[1]])
    if not cli_parse_score(s[2],head_pl,noattr = True):
        return False
    # save symmetrical for later (if it exists)
    symm = ""
    if is_attribute(s[len(s)-1],"symmetrical"):
        symm = s.pop()
    if len(s) == 5:
        if not cli_parse_rsc_action(s[3],head_pl,'first'):
            return False
        if not cli_parse_rsc_action(s[4],head_pl,'then'):
            return False
    else:
        resource_set_obj = ResourceSet(type,s[3:],cli_list)
        if not resource_set_obj.parse():
            return False
    if not cli_opt_symmetrical(symm,head_pl):
        return False
    return cli_list

def parse_constraint(s):
    if keyword_cmp(s[0], "location"):
        return parse_location(s)
    elif s[0] in olist(["colocation","collocation"]):
        return parse_colocation(s)
    elif keyword_cmp(s[0], "order"):
        return parse_order(s)
def parse_property(s):
    cli_list = []
    head_pl = []
    cli_list.append([s[0],head_pl])
    cli_parse_attr(s[1:],head_pl)
    if len(head_pl) < 0 or len(s) > len(head_pl)+1:
        syntax_err(s, context = s[0])
        return False
    return cli_list
def cli_parse_uname(s, pl):
    l = s.split(':')
    if not l or len(l) > 2:
        return None
    pl.append(["uname",l[0]])
    if len(l) == 2:
        pl.append(["type",l[1]])
def parse_node(s):
    cli_list = []
    # the head
    head = []
    # optional $id
    id = ''
    opt_id_l = []
    i = 1
    cli_parse_attr_strict(s[i:],opt_id_l)
    if opt_id_l:
        id = find_value(opt_id_l,"$id")
        i += 1
    # uname[:type]
    cli_parse_uname(s[i],head)
    uname = find_value(head,"uname")
    if not uname:
        return False
    head.append(["id",id and id or uname])
    # drop type if default
    type = find_value(head,"type")
    if type == vars.node_default_type:
        head.remove(["type",type])
    cli_list.append([s[0],head])
    if len(s) == i:
        return cli_list
    # the rest
    i += 1
    try:  # s[i] may be out of range
        if is_attribute(s[i],"description"):
            cli_parse_attr(s[i:i+1],head)
            i += 1 # skip to the next token
    except: pass
    while len(s) > i+1:
        if not s[i] in olist(vars.node_attributes_keyw):
            syntax_err(s[i:], context = 'node')
            return False
        pl = []
        cli_parse_attr(s[i+1:],pl)
        if len(pl) == 0:
            syntax_err(s[i:], context = 'node')
            return False
        cli_list.append([s[i],pl])
        i += len(pl)+1
    if len(s) > i:
        syntax_err(s[i:], context = 'node')
        return False
    return cli_list
def parse_xml(s):
    cli_list = []
    head = []
    try:
        xml_s = ' '.join(s[1:])
    except:
        syntax_err(s, context = 'xml')
        return False
    # strip spaces between elements
    # they produce text elements
    xml_s = re.sub(r">\s+<", "><", xml_s)
    try:
        doc = xml.dom.minidom.parseString(xml_s)
    except xml.parsers.expat.ExpatError, msg:
        common_err("cannot parse xml chunk: %s" % xml_s)
        common_err(msg)
        return False
    try:
        elnode = doc.childNodes[0]
    except:
        common_err("no elements in %s" % xml_s)
        return False
    try:
        el_type = vars.cib_cli_map[elnode.tagName]
    except:
        common_err("element %s not recognized" % elnode.tagName)
        return False
    id = elnode.getAttribute("id")
    head.append(["id",id])
    cli_list.append([el_type,head])
    cli_list.append(["raw",xml_s])
    return cli_list

def xml_lex(s):
    l = lines2cli(s)
    a = []
    for p in l:
        a += p.split()
    return a

class CliParser(object):
    parsers = {
        "primitive": (3,parse_resource),
        "group": (3,parse_resource),
        "clone": (3,parse_resource),
        "ms": (3,parse_resource),
        "master": (3,parse_resource),
        "location": (3,parse_constraint),
        "colocation": (3,parse_constraint),
        "collocation": (3,parse_constraint),
        "order": (3,parse_constraint),
        "monitor": (3,parse_op),
        "node": (2,parse_node),
        "property": (2,parse_property),
        "rsc_defaults": (2,parse_property),
        "op_defaults": (2,parse_property),
        "xml": (3,parse_xml),
    }
    def __init__(self):
        self.comments = []
    def parse(self,s):
        '''
        Input: a list of tokens (or a CLI format string).
        Return: a list of items; each item is a tuple
            with two members: a string (tag) and a nvpairs or
            attributes dict.
        '''
        cli_list = ''
        if type(s) == type(u''):
            s = s.encode('ascii')
        if type(s) == type(''):
            if s and s.startswith('#'):
                #self.comments.append(s)
                return None
            if s.startswith('xml'):
                s = xml_lex(s)
            else:
                try:
                    s = shlex.split(s)
                except ValueError, msg:
                    common_err(msg)
                    return False
        # but there shouldn't be any newlines (?)
        while '\n' in s:
            s.remove('\n')
        if not s:
            return None
        if s[0] not in self.parsers.keys():
            syntax_err(s)
            return False
        mintoks,parser_fn = self.parsers[s[0]]
        if len(s) < mintoks:
            syntax_err(s)
            return False
        cli_list = parser_fn(s)
        if not cli_list:
            return False
        if self.comments:
            cli_list.append(["comments",self.comments])
            self.comments = []
        return cli_list

vars = Vars.getInstance()
# vim:ts=4:sw=4:et:
