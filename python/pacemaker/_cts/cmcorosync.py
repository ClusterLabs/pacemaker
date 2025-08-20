"""Corosync-specific class for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["Corosync2"]
__copyright__ = "Copyright 2007-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.CTS import Process
from pacemaker._cts.clustermanager import ClusterManager


class Corosync2(ClusterManager):
    """A subclass of ClusterManager specialized to handle corosync2 and later based clusters."""

    @property
    def components(self):
        """Return a list of patterns that should be ignored for the cluster's components."""
        comps = [
            "corosync",
            "pacemaker-attrd",
            "pacemaker-based",
            "pacemaker-controld",
            "pacemaker-execd",
            "pacemaker-fenced"
        ]
        return [
            Process(self, c, pats=self.templates.get_component(c),
                    badnews_ignore=self.templates.get_component(f"{c}-ignore"))
            for c in comps
        ]
