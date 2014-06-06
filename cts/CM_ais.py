'''CTS: Cluster Testing System: AIS dependent modules...
'''

__copyright__ = '''
Copyright (C) 2007 Andrew Beekhof <andrew@suse.de>

'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

import os, sys, warnings
from cts.CTSvars import *
from cts.CM_lha  import crm_lha
from cts.CTS     import Process
from cts.patterns    import PatternSelector

#######################################################################
#
#  LinuxHA v2 dependent modules
#
#######################################################################


class crm_ais(crm_lha):
    '''
    The crm version 3 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of openais
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-ais"
        crm_lha.__init__(self, Environment, randseed=randseed, name=name)

        self.fullcomplist = {}
        self.templates = PatternSelector(self.name)

    def NodeUUID(self, node):
        return node

    def ais_components(self):

        complist = []
        if not len(self.fullcomplist.keys()):
            for c in ["cib", "lrmd", "crmd", "attrd" ]:
               self.fullcomplist[c] = Process(
                   self, c, 
                   pats = self.templates.get_component(self.name, c),
                   badnews_ignore = self.templates.get_component(self.name, "%s-ignore"%c),
                   common_ignore = self.templates.get_component(self.name, "common-ignore"))

               self.fullcomplist["pengine"] = Process(
                   self, "pengine", 
                   dc_pats = self.templates.get_component(self.name, "pengine"),
                   badnews_ignore = self.templates.get_component(self.name, "pengine-ignore"),
                   common_ignore = self.templates.get_component(self.name, "common-ignore"))

               self.fullcomplist["stonith-ng"] = Process(
                   self, "stonith-ng", process="stonithd", 
                   pats = self.templates.get_component(self.name, "stonith"),
                   badnews_ignore = self.templates.get_component(self.name, "stonith-ignore"),
                   common_ignore = self.templates.get_component(self.name, "common-ignore"))

        vgrind = self.Env["valgrind-procs"].split()
        for key in self.fullcomplist.keys():
            if self.Env["valgrind-tests"]:
               if key in vgrind:
               # Processes running under valgrind can't be shot with "killall -9 processname"
                    self.log("Filtering %s from the component list as it is being profiled by valgrind" % key)
                    continue
            if key == "stonith-ng" and not self.Env["DoFencing"]:
                continue

            complist.append(self.fullcomplist[key])

        #self.complist = [ fullcomplist["pengine"] ]
        return complist


class crm_cs_v0(crm_ais):
    '''
    The crm version 3 cluster manager class.
    It implements the things we need to talk to and manipulate

    crm clusters running against version 0 of our plugin
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-plugin-v0"
        crm_ais.__init__(self, Environment, randseed=randseed, name=name)

    def Components(self):
        self.ais_components()
        c = "corosync"

        self.fullcomplist[c] = Process(
            self, c, 
            pats = self.templates.get_component(self.name, c),
            badnews_ignore = self.templates.get_component(self.name, "%s-ignore"%c),
            common_ignore = self.templates.get_component(self.name, "common-ignore")
        )

        return self.ais_components()


class crm_cs_v1(crm_cs_v0):
    '''
    The crm version 3 cluster manager class.
    It implements the things we need to talk to and manipulate

    crm clusters running on top of version 1 of our plugin
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-plugin-v1"
        crm_cs_v0.__init__(self, Environment, randseed=randseed, name=name)


class crm_mcp(crm_cs_v0):
    '''
    The crm version 4 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of native corosync (no plugins)
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-mcp"
        crm_cs_v0.__init__(self, Environment, randseed=randseed, name=name)

        if self.Env["have_systemd"]:
            self.update({
                # When systemd is in use, we can look for this instead
                "Pat:We_stopped"   : "%s.*Stopped Corosync Cluster Engine",
            })


class crm_cman(crm_cs_v0):
    '''
    The crm version 3 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of openais
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-cman"
        crm_cs_v0.__init__(self, Environment, randseed=randseed, name=name)
