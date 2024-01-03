"""Corosync-specific class for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["Corosync2"]
__copyright__ = "Copyright 2007-2024 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.CTS import Process
from pacemaker._cts.clustermanager import ClusterManager
from pacemaker._cts.patterns import PatternSelector

# Throughout this file, pylint has trouble understanding that EnvFactory
# is a singleton instance that can be treated as a subscriptable object.
# Various warnings are disabled because of this.  See also a comment about
# self._rsh in environment.py.
# pylint: disable=unsubscriptable-object

class Corosync2(ClusterManager):
    """A subclass of ClusterManager specialized to handle corosync2 and later based clusters."""

    def __init__(self):
        """Create a new Corosync2 instance."""
        ClusterManager.__init__(self)

        self._fullcomplist = {}
        self.templates = PatternSelector(self.name)

    @property
    def components(self):
        """Return a list of patterns that should be ignored for the cluster's components."""
        complist = []

        if not self._fullcomplist:
            common_ignore = self.templates.get_component("common-ignore")

            daemons = [
                "pacemaker-based",
                "pacemaker-controld",
                "pacemaker-attrd",
                "pacemaker-execd",
                "pacemaker-fenced"
            ]
            for c in daemons:
                badnews = self.templates.get_component("%s-ignore" % c) + common_ignore
                proc = Process(self, c, pats=self.templates.get_component(c),
                               badnews_ignore=badnews)
                self._fullcomplist[c] = proc

            # the scheduler uses dc_pats instead of pats
            badnews = self.templates.get_component("pacemaker-schedulerd-ignore") + common_ignore
            proc = Process(self, "pacemaker-schedulerd",
                           dc_pats=self.templates.get_component("pacemaker-schedulerd"),
                           badnews_ignore=badnews)
            self._fullcomplist["pacemaker-schedulerd"] = proc

            # add (or replace) extra components
            badnews = self.templates.get_component("corosync-ignore") + common_ignore
            proc = Process(self, "corosync", pats=self.templates.get_component("corosync"),
                           badnews_ignore=badnews)
            self._fullcomplist["corosync"] = proc

        # Processes running under valgrind can't be shot with "killall -9 processname",
        # so don't include them in the returned list
        vgrind = self.env["valgrind-procs"].split()
        for (key, val) in self._fullcomplist.items():
            if self.env["valgrind-tests"] and key in vgrind:
                self.log("Filtering %s from the component list as it is being profiled by valgrind" % key)
                continue

            if key == "pacemaker-fenced" and not self.env["DoFencing"]:
                continue

            complist.append(val)

        return complist
