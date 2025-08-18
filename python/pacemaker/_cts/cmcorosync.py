"""Corosync-specific class for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["Corosync2"]
__copyright__ = "Copyright 2007-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.CTS import Process
from pacemaker._cts.clustermanager import ClusterManager

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
        self._components = {}

    @property
    def components(self):
        """Return a list of patterns that should be ignored for the cluster's components."""
        if not self._components:
            common_ignore = self.templates.get_component("common-ignore")

            daemons = [
                "corosync",
                "pacemaker-based",
                "pacemaker-controld",
                "pacemaker-attrd",
                "pacemaker-execd",
                "pacemaker-fenced"
            ]
            for c in daemons:
                badnews = self.templates.get_component(f"{c}-ignore") + common_ignore
                proc = Process(self, c, pats=self.templates.get_component(c),
                               badnews_ignore=badnews)
                self._components[c] = proc

        if self.env["DoFencing"]:
            return list(self._components.values())

        return [v for k, v in self._components.items() if k != "pacemaker-fenced"]
