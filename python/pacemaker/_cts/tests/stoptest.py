"""Stop the cluster manager on a given node."""

__all__ = ["StopTest"]
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


class StopTest(CTSTest):
    """
    A pseudo-test that sets up conditions before running some other test.

    This class stops the cluster manager on a given node.  Other test classes
    should not use this one as a superclass.
    """

    def __init__(self, cm):
        """
        Create a new StopTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.name = "Stop"

    def __call__(self, node):
        """Stop the given node, returning whether this succeeded or not."""
        self.incr("calls")
        if self._cm.expected_status[node] != "up":
            return self.skipped()

        # Technically we should always be able to notice ourselves stopping
        patterns = [
            self._cm.templates["Pat:We_stopped"] % node,
        ]

        # Any active node needs to notice this one left
        # (note that this won't work if we have multiple partitions)
        for other in self._env["nodes"]:
            if self._cm.expected_status[other] == "up" and other != node:
                patterns.append(self._cm.templates["Pat:They_stopped"] % (other, node))

        watch = self.create_watch(patterns, self._env["dead_time"])
        watch.set_watch()

        if node == self._cm.our_node:
            self.incr("us")
        else:
            if self._cm.upcount() <= 1:
                self.incr("all")
            else:
                self.incr("them")

        self._cm.stop_cm(node)
        watch.look_for_all()

        failreason = None
        unmatched_str = "||"

        if watch.unmatched:
            (_, output) = self._rsh.call(node, "/bin/ps axf", verbose=1)
            for line in output:
                self.debug(line)

            (_, output) = self._rsh.call(node, "/usr/sbin/dlm_tool dump 2>/dev/null", verbose=1)
            for line in output:
                self.debug(line)

            for regex in watch.unmatched:
                logging.log(f"ERROR: Shutdown pattern not found: {regex}")
                unmatched_str += f"{regex}||"
                failreason = "Missing shutdown pattern"

        self._cm.cluster_stable(self._env["dead_time"])

        if not watch.unmatched or self._cm.upcount() == 0:
            return self.success()

        if len(watch.unmatched) >= self._cm.upcount():
            return self.failure(f"no match against ({unmatched_str})")

        if failreason is None:
            return self.success()

        return self.failure(failreason)
