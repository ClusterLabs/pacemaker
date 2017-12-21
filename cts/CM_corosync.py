'''CTS: Cluster Testing System: Corosync-dependent modules...
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

from cts.CTSvars import *
from cts.CM_common  import crm_common
from cts.CTS     import Process
from cts.patterns    import PatternSelector

#######################################################################
#
#  Corosync-dependent modules
#
#######################################################################

class crm_corosync(crm_common):
    '''
    Corosync version 2 cluster manager class
    '''
    def __init__(self, Environment, randseed=None, name=None):
        if not name: name="crm-corosync"
        crm_common.__init__(self, Environment, randseed=randseed, name=name)

        self.fullcomplist = {}
        self.templates = PatternSelector(self.name)

        if self.Env["have_systemd"]:
            self.update({
                # When systemd is in use, we can look for this instead
                "Pat:We_stopped"   : "%s.*Corosync Cluster Engine exiting normally",
            })

    def Components(self):
        complist = []
        if not len(list(self.fullcomplist.keys())):
            for c in ["cib", "lrmd", "crmd", "attrd" ]:
                self.fullcomplist[c] = Process(
                    self, c, 
                    pats = self.templates.get_component(self.name, c),
                    badnews_ignore = self.templates.get_component(self.name, "%s-ignore" % c),
                    common_ignore = self.templates.get_component(self.name, "common-ignore"))

            # pengine uses dc_pats instead of pats
            self.fullcomplist["pengine"] = Process(
                self, "pengine", 
                dc_pats = self.templates.get_component(self.name, "pengine"),
                badnews_ignore = self.templates.get_component(self.name, "pengine-ignore"),
                common_ignore = self.templates.get_component(self.name, "common-ignore"))

            # stonith-ng's process name is different from its component name
            self.fullcomplist["stonith-ng"] = Process(
                self, "stonith-ng", process="stonithd", 
                pats = self.templates.get_component(self.name, "stonith"),
                badnews_ignore = self.templates.get_component(self.name, "stonith-ignore"),
                common_ignore = self.templates.get_component(self.name, "common-ignore"))

            # add (or replace) extra components
            self.fullcomplist["corosync"] = Process(
                self, "corosync", 
                pats = self.templates.get_component(self.name, "corosync"),
                badnews_ignore = self.templates.get_component(self.name, "corosync-ignore"),
                common_ignore = self.templates.get_component(self.name, "common-ignore")
            )

        # Processes running under valgrind can't be shot with "killall -9 processname",
        # so don't include them in the returned list
        vgrind = self.Env["valgrind-procs"].split()
        for key in list(self.fullcomplist.keys()):
            if self.Env["valgrind-tests"]:
                if key in vgrind:
                    self.log("Filtering %s from the component list as it is being profiled by valgrind" % key)
                    continue
            if key == "stonith-ng" and not self.Env["DoFencing"]:
                continue
            complist.append(self.fullcomplist[key])

        return complist
