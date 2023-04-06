""" Corosync-specific class for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2007-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from cts.ClusterManager import ClusterManager

from pacemaker._cts.CTS import Process
from pacemaker._cts.patterns import PatternSelector

class crm_corosync(ClusterManager):
    '''
    Corosync version 2 cluster manager class
    '''
    def __init__(self, name=None):
        if not name: name="crm-corosync"
        ClusterManager.__init__(self)

        self.fullcomplist = {}
        self.templates = PatternSelector(self.name)

    def Components(self):
        complist = []
        if not len(list(self.fullcomplist.keys())):
            for c in [ "pacemaker-based", "pacemaker-controld", "pacemaker-attrd", "pacemaker-execd", "pacemaker-fenced" ]:
                self.fullcomplist[c] = Process(
                    self, c, 
                    pats = self.templates.get_component(c),
                    badnews_ignore = self.templates.get_component("%s-ignore" % c) +
                                     self.templates.get_component("common-ignore"))

            # the scheduler uses dc_pats instead of pats
            self.fullcomplist["pacemaker-schedulerd"] = Process(
                self, "pacemaker-schedulerd", 
                dc_pats = self.templates.get_component("pacemaker-schedulerd"),
                badnews_ignore = self.templates.get_component("pacemaker-schedulerd-ignore") +
                                 self.templates.get_component("common-ignore"))

            # add (or replace) extra components
            self.fullcomplist["corosync"] = Process(
                self, "corosync", 
                pats = self.templates.get_component("corosync"),
                badnews_ignore = self.templates.get_component("corosync-ignore") +
                                 self.templates.get_component("common-ignore")
            )

        # Processes running under valgrind can't be shot with "killall -9 processname",
        # so don't include them in the returned list
        vgrind = self.Env["valgrind-procs"].split()
        for key in list(self.fullcomplist.keys()):
            if self.Env["valgrind-tests"]:
                if key in vgrind:
                    self.log("Filtering %s from the component list as it is being profiled by valgrind" % key)
                    continue
            if key == "pacemaker-fenced" and not self.Env["DoFencing"]:
                continue
            complist.append(self.fullcomplist[key])

        return complist
