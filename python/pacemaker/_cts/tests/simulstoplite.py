"""Simultaneously stop running nodes."""

__all__ = ["SimulStopLite"]
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


class SimulStopLite(CTSTest):
    """
    A pseudo-test that sets up conditions before running some other test.

    This class stops any running nodes more or less simultaneously.  It can be
    used both to set up a test or to clean up a test.  Other test classes
    should not use this one as a superclass.
    """

    def __init__(self, cm):
        """
        Create a new SimulStopLite instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.name = "SimulStopLite"

    def __call__(self, dummy):
        """Return whether stopping all running nodes more or less simultaneously succeeds."""
        self.incr("calls")
        self.debug(f"Setup: {self.name}")

        # We ignore the "node" parameter...
        watchpats = []

        for node in self._env["nodes"]:
            if self._cm.expected_status[node] == "up":
                self.incr("WasStarted")
                watchpats.append(self._cm.templates["Pat:We_stopped"] % node)

        if len(watchpats) == 0:
            return self.success()

        # Stop all the nodes - at about the same time...
        watch = self.create_watch(watchpats, self._env["dead_time"] + 10)

        watch.set_watch()
        self.set_timer()
        for node in self._env["nodes"]:
            if self._cm.expected_status[node] == "up":
                self._cm.stop_cm_async(node)

        if watch.look_for_all():
            # Make sure they're completely down with no residule
            for node in self._env["nodes"]:
                self._rsh(node, self._cm.templates["StopCmd"])

            return self.success()

        did_fail = False
        up_nodes = []
        for node in self._env["nodes"]:
            if self._cm.stat_cm(node):
                did_fail = True
                up_nodes.append(node)

        if did_fail:
            return self.failure(f"Active nodes exist: {up_nodes}")

        logging.log(f"Warn: All nodes stopped but CTS didn't detect: {watch.unmatched}")
        return self.failure(f"Missing log message: {watch.unmatched}")

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        return False
