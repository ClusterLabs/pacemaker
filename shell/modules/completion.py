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
import time
import copy
import readline

from cibconfig import CibFactory
from cibstatus import CibStatus
from levels import Levels
from ra import *
from vars import Vars
from utils import *
from xmlutil import *

class CompletionHelp(object):
    '''
    Print some help on whatever last word in the line.
    '''
    timeout = 60  # don't print again and again
    def __init__(self):
        self.laststamp = 0
        self.lastitem = ''
    def help(self,f,*args):
        words = readline.get_line_buffer().split()
        if not words:
            return
        key = words[-1]
        if key.endswith('='):
            key = key[0:-1]
        if self.lastitem == key and \
                time.time() - self.laststamp < self.timeout:
            return
        help_s = f(key,*args)
        if help_s:
            print "\n%s" % help_s
            print "%s%s" % (vars.prompt,readline.get_line_buffer()),
            self.laststamp = time.time()
            self.lastitem = key

def attr_cmds(idx,delimiter = False):
    if delimiter:
        return ' '
    return ["delete","set","show"]
def nodes_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return listnodes()
def shadows_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return listshadows()
def listtemplates():
    l = []
    for f in os.listdir(vars.tmpl_dir):
        if os.path.isfile("%s/%s" % (vars.tmpl_dir,f)):
            l.append(f)
    return l
def listconfigs():
    l = []
    for f in os.listdir(vars.tmpl_conf_dir):
        if os.path.isfile("%s/%s" % (vars.tmpl_conf_dir,f)):
            l.append(f)
    return l
def templates_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return listtemplates()
def config_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return listconfigs()
def config_list_method(idx,delimiter = False):
    if delimiter:
        return ' '
    return listconfigs() + ["replace","update"]
def shadows_live_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return listshadows() + ['live']
def rsc_list(idx,delimiter = False):
    if delimiter:
        return ' '
    doc = resources_xml()
    if not doc:
        return []
    nodes = get_interesting_nodes(doc,[])
    return [x.getAttribute("id") for x in nodes if is_resource(x)]
def null_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return []
def loop(idx,delimiter = False):
    "just a marker in a list"
    pass
def id_xml_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.id_list() + ['xml','changed']
def id_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.id_list()
def f_prim_id_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.f_prim_id_list()
def f_children_id_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.f_children_id_list()
def rsc_id_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.rsc_id_list()
def node_id_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_factory.node_id_list()
def node_attr_keyw_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return vars.node_attributes_keyw
def status_node_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_status.status_node_list()
def status_rsc_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return cib_status.status_rsc_list()
def node_states_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return vars.node_states
def ra_operations_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return vars.ra_operations
def lrm_exit_codes_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return vars.lrm_exit_codes.keys()
def lrm_status_codes_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return vars.lrm_status_codes.keys()
def skills_list(idx,delimiter = False):
    if delimiter:
        return ' '
    return user_prefs.skill_levels.keys()
def ra_classes_list(idx,delimiter = False):
    if delimiter:
        return ':'
    return ra_classes()

#
# completion for primitives including help for parameters
# (help also available for properties)
#
def get_primitive_type(words):
    try:
        idx = words.index("primitive") + 2
        type_word = words[idx]
    except: type_word = ''
    return type_word
def ra_type_list(toks,idx,delimiter):
    if idx == 2:
        if toks[0] == "ocf":
            dchar = ':'
            l = ra_providers_all()
        else:
            dchar = ' '
            l = ra_types(toks[0])
    elif idx == 3:
        dchar = ' '
        if toks[0] == "ocf":
            l = ra_types(toks[0],toks[1])
        else:
            l = ra_types(toks[0])
    if delimiter:
        return dchar
    return l
def prim_meta_attr_list(idx,delimiter = False):
    if delimiter:
        return '='
    return vars.rsc_meta_attributes
def op_attr_list(idx,delimiter = False):
    if delimiter:
        return '='
    return vars.op_attributes
def operations_list():
    return vars.op_cli_names
def prim_complete_meta(ra,delimiter = False):
    if delimiter:
        return '='
    return prim_meta_attr_list(0,delimiter)
def prim_complete_op(ra,delimiter):
    words = split_buffer()
    if (readline.get_line_buffer()[-1] == ' ' and words[-1] == "op") \
            or (readline.get_line_buffer()[-1] != ' ' and words[-2] == "op"):
        dchar = ' '
        l = operations_list()
    else:
        if readline.get_line_buffer()[-1] == '=':
            dchar = ' '
            l = []
        else:
            dchar = '='
            l = op_attr_list()
    if delimiter:
        return dchar
    return l
def prim_complete_params(ra,delimiter):
    if readline.get_line_buffer()[-1] == '=':
        dchar = ' '
        l = []
    else:
        dchar = '='
        l = ra.completion_params()
    if delimiter:
        return dchar
    return l
def prim_params_info(key,ra):
    return ra.meta_parameter(key)
def meta_attr_info(key,ra):
    pass
def op_attr_info(key,ra):
    pass
def get_lastkeyw(words,keyw):
    revwords = copy.copy(words)
    revwords.reverse()
    for w in revwords:
        if w in keyw:
            return w
def primitive_complete_complex(idx,delimiter = False):
    '''
    This completer depends on the content of the line, i.e. on
    previous tokens, in particular on the type of the RA.
    '''
    completers_set = {
        "params": (prim_complete_params, prim_params_info),
        "meta": (prim_complete_meta, meta_attr_info),
        "op": (prim_complete_op, op_attr_info),
    }
    # manage the resource type
    words = readline.get_line_buffer().split()
    type_word = get_primitive_type(words)
    toks = type_word.split(':')
    if toks[0] != "ocf":
        idx += 1
    if idx in (2,3):
        return ra_type_list(toks,idx,delimiter)
    # create an ra object
    ra = None
    ra_class,provider,rsc_type = disambiguate_ra_type(type_word)
    if ra_type_validate(type_word,ra_class,provider,rsc_type):
        ra = RAInfo(ra_class,rsc_type,provider)
    keywords = completers_set.keys()
    if idx == 4:
        if delimiter:
            return ' '
        return keywords
    lastkeyw = get_lastkeyw(words,keywords)
    if '=' in words[-1] and readline.get_line_buffer()[-1] != ' ':
        if not delimiter and lastkeyw and \
                readline.get_line_buffer()[-1] == '=' and len(words[-1]) > 1:
            compl_help.help(completers_set[lastkeyw][1],ra)
        if delimiter:
            return ' '
        return ['*']
    else:
        if lastkeyw:
            return completers_set[lastkeyw][0](ra,delimiter)
def property_complete(idx,delimiter = False):
    '''
    This completer depends on the content of the line, i.e. on
    previous tokens.
    '''
    ra = get_properties_meta()
    words = readline.get_line_buffer().split()
    if '=' in words[-1] and readline.get_line_buffer()[-1] != ' ':
        if not delimiter and \
                readline.get_line_buffer()[-1] == '=' and len(words[-1]) > 1:
            compl_help.help(prim_params_info,ra)
        if delimiter:
            return ' '
        return ['*']
    else:
        return prim_complete_params(ra,delimiter)

#
# core completer stuff
#
def lookup_dynamic(fun_list,idx,f_idx,words):
    if not fun_list:
        return []
    if fun_list[f_idx] == loop:
        f_idx -= 1
    f = fun_list[f_idx]
    w = words[0]
    wordlist = f(idx)
    delimiter = f(idx,1)
    if len(wordlist) == 1 and wordlist[0] == '*':
        return lookup_dynamic(fun_list,idx+1,f_idx+1,words[1:])
    elif len(words) == 1:
        return [x+delimiter for x in wordlist if x.startswith(w)]
    return lookup_dynamic(fun_list,idx+1,f_idx+1,words[1:])
def lookup_words(ctab,words):
    if not ctab:
        return []
    if type(ctab) == type(()):
        return lookup_dynamic(ctab,0,0,words)
    if len(words) == 1:
        return [x+' ' for x in ctab if x.startswith(words[0])]
    elif words[0] in ctab.keys():
        return lookup_words(ctab[words[0]],words[1:])
    return []
def split_buffer():
    p = readline.get_line_buffer()
    p = p.replace(':',' ').replace('=',' ')
    return p.split()

def completer(txt,state):
    levels = Levels.getInstance()
    words = split_buffer()
    if readline.get_begidx() == readline.get_endidx():
        words.append('')
    matched = lookup_words(levels.completion_tab,words)
    matched.append(None)
    return matched[state]
def setup_readline():
    readline.set_history_length(100)
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)
    readline.set_completer_delims(\
        readline.get_completer_delims().replace('-','').replace('/','').replace('=',''))
    try: readline.read_history_file(vars.hist_file)
    except: pass

#
# a dict of completer functions
# (feel free to add more completers)
#
completer_lists = {
    "options" : {
        "skill-level" : (skills_list,),
        "editor" : None,
        "pager" : None,
        "user" : None,
        "output" : None,
        "colorscheme" : None,
        "check-frequency" : None,
        "check-mode" : None,
        "sort-elements" : None,
        "save" : None,
        "show" : None,
    },
    "cib" : {
        "new" : None,
        "delete" : (shadows_list,),
        "reset" : (shadows_list,),
        "commit" : (shadows_list,),
        "use" : (shadows_live_list,),
        "diff" : None,
        "list" : None,
        "import" : None,
        "cibstatus" : None,
    },
    "template" : {
        "new" : (null_list,templates_list,loop),
        "load" : (config_list,),
        "edit" : (config_list,),
        "delete" : (config_list,),
        "show" : (config_list,),
        "apply" : (config_list_method,config_list),
        "list" : None,
    },
    "resource" : {
        "status" : (rsc_list,),
        "start" : (rsc_list,),
        "stop" : (rsc_list,),
        "restart" : (rsc_list,),
        "promote" : (rsc_list,),
        "demote" : (rsc_list,),
        "manage" : (rsc_list,),
        "unmanage" : (rsc_list,),
        "migrate" : (rsc_list,nodes_list),
        "unmigrate" : (rsc_list,),
        "param" : (rsc_list,attr_cmds),
        "meta" : (rsc_list,attr_cmds),
        "utilization" : (rsc_list,attr_cmds),
        "failcount" : (rsc_list,attr_cmds,nodes_list),
        "cleanup" : (rsc_list,nodes_list),
        "refresh" : (nodes_list,),
        "reprobe" : (nodes_list,),
    },
    "node" : {
        "status" : (nodes_list,),
        "show" : (nodes_list,),
        "standby" : (nodes_list,),
        "online" : (nodes_list,),
        "fence" : (nodes_list,),
        "delete" : (nodes_list,),
        "clearstate" : (nodes_list,),
        "attribute" : (nodes_list,attr_cmds),
        "utilization" : (nodes_list,attr_cmds),
        "status-attr" : (nodes_list,attr_cmds),
    },
    "ra" : {
        "classes" : None,
        "list" : None,
        "providers" : None,
        "meta" : None,
    },
    "cibstatus" : {
        "show" : None,
        "save" : None,
        "load" : None,
        "origin" : None,
        "node" : (status_node_list,node_states_list),
        "op" : (ra_operations_list,status_rsc_list,lrm_exit_codes_list,lrm_status_codes_list,status_node_list),
        "run" : None,
        "simulate" : None,
        "quorum" : None,
    },
    "configure" : {
        "erase" : None,
        "verify" : None,
        "refresh" : None,
        "ptest" : None,
        "commit" : None,
        "upgrade" : None,
        "show" : (id_xml_list,id_list,loop),
        "edit" : (id_xml_list,id_list,loop),
        "filter" : (null_list,id_xml_list,id_list,loop),
        "delete" : (id_list,loop),
        "default-timeouts" : (id_list,loop),
        "rename" : (id_list,id_list),
        "save" : None,
        "load" : None,
        "node" : (node_id_list,node_attr_keyw_list),
        "primitive" : (null_list,ra_classes_list,primitive_complete_complex,loop),
        "group" : (null_list,f_prim_id_list,loop),
        "clone" : (null_list,f_children_id_list),
        "ms" : (null_list,f_children_id_list),
        "location" : (null_list,rsc_id_list),
        "colocation" : (null_list,null_list,rsc_id_list,loop),
        "order" : (null_list,null_list,rsc_id_list,loop),
        "property" : (property_complete,loop),
        "rsc_defaults" : (prim_complete_meta,loop),
        "op_defaults" : (op_attr_list,loop),
        "xml" : None,
        "monitor" : None,
        "ra" : None,
        "cib" : None,
        "cibstatus" : None,
        "template" : None,
        "_test" : None,
        "_regtest" : None,
        "_objects" : None,
    },
}
def get_completer_list(level,cmd):
    'Return a list of completer functions.'
    try: return completer_lists[level][cmd]
    except: return None

compl_help = CompletionHelp()
user_prefs = UserPrefs.getInstance()
vars = Vars.getInstance()
cib_status = CibStatus.getInstance()
cib_factory = CibFactory.getInstance()

# vim:ts=4:sw=4:et:
