"""Start the cluster manager on a given node."""

__all__ = ["StartTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest


class StartTest(CTSTest):
    """
    A pseudo-test that sets up conditions before running some other test.

    This class starts the cluster manager on a given node.  Other test classes
    should not use this one as a superclass.
    """

    def __init__(self, cm, env):
        """
        Create a new StartTest instance.

        Arguments:
        cm  -- A ClusterManager instance
        env -- An Environment instance
        """
        CTSTest.__init__(self, cm, env)
        self.name = "Start"

    def __call__(self, node):
        """Start the given node, returning whether this succeeded or not."""
        self.incr("calls")

        if self._cm.upcount() == 0:
            self.incr("us")
        else:
            self.incr("them")

        if self._cm.expected_status[node] != "down":
            return self.skipped()

        if self._cm.start_cm(node):
            return self.success()

        return self.failure(f"Startup {self._env['Name']} on node {node} failed")
