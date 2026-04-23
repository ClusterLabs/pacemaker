"""Simultaneously start stopped nodes."""

__all__ = ["SimulStartLite"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.tests.ctstest import CTSTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class SimulStartLite(CTSTest):
    """
    A pseudo-test that sets up conditions before running some other test.

    This class starts any stopped nodes more or less simultaneously.  Other test
    classes should not use this one as a superclass.
    """

    def __init__(self, cm):
        """
        Create a new SimulStartLite instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.name = "SimulStartLite"

    def __call__(self, dummy):
        """Return whether starting all stopped nodes more or less simultaneously succeeds."""
        self.incr("calls")
        self.debug(f"Setup: {self.name}")

        # We ignore the "node" parameter...
        node_list = []
        for node in self._env["nodes"]:
            if self._cm.expected_status[node] == "down":
                self.incr("WasStopped")
                node_list.append(node)

        self.set_timer()
        while len(node_list) > 0:
            # Repeat until all nodes come up
            uppat = self._cm.templates["Pat:NonDC_started"]
            if self._cm.upcount() == 0:
                uppat = self._cm.templates["Pat:Local_started"]

            watchpats = [
                self._cm.templates["Pat:DC_IDLE"]
            ]
            for node in node_list:
                watchpats.extend([uppat % node,
                                  self._cm.templates["Pat:InfraUp"] % node,
                                  self._cm.templates["Pat:PacemakerUp"] % node])

            #   Start all the nodes - at about the same time...
            watch = self.create_watch(watchpats, self._env["dead_time"] + 10)
            watch.set_watch()

            stonith = self._cm.prepare_fencing_watcher()

            for node in node_list:
                self._cm.start_cm_async(node)

            watch.look_for_all()

            node_list = self._cm.fencing_cleanup(self.name, stonith)

            if node_list is None:
                return self.failure("Cluster did not stabilize")

            # Remove node_list messages from watch.unmatched
            for node in node_list:
                logging.debug(f"Dealing with stonith operations for {node_list}")
                if watch.unmatched:
                    try:
                        watch.unmatched.remove(uppat % node)
                    except ValueError:
                        self.debug(f"Already matched: {uppat % node}")

                    try:
                        watch.unmatched.remove(self._cm.templates["Pat:InfraUp"] % node)
                    except ValueError:
                        self.debug(f"Already matched: {self._cm.templates['Pat:InfraUp'] % node}")

                    try:
                        watch.unmatched.remove(self._cm.templates["Pat:PacemakerUp"] % node)
                    except ValueError:
                        self.debug(f"Already matched: {self._cm.templates['Pat:PacemakerUp'] % node}")

            if watch.unmatched:
                for regex in watch.unmatched:
                    logging.log(f"Warn: Startup pattern not found: {regex}")

            if not self._cm.cluster_stable():
                return self.failure("Cluster did not stabilize")

        did_fail = False
        unstable = []
        for node in self._env["nodes"]:
            if not self._cm.stat_cm(node):
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure(f"Unstarted nodes exist: {unstable}")

        unstable = []
        for node in self._env["nodes"]:
            if not self._cm.node_stable(node):
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure(f"Unstable cluster nodes exist: {unstable}")

        return self.success()

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        return False
