"""Stop running nodes, and start stopped nodes."""

__all__ = ["FlipTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest


class FlipTest(CTSTest):
    """Stop running nodes and start stopped nodes."""

    def __init__(self, cm, env):
        """
        Create a new FlipTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm, env)
        self.name = "Flip"

        self._start = StartTest(cm, env)
        self._stop = StopTest(cm, env)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")

        if self._cm.expected_status[node] == "up":
            self.incr("stopped")
            ret = self._stop(node)
            kind = "up->down"
            # Give the cluster time to recognize it's gone...
            time.sleep(self._env["stable_time"])
        elif self._cm.expected_status[node] == "down":
            self.incr("started")
            ret = self._start(node)
            kind = "down->up"
        else:
            return self.skipped()

        self.incr(kind)
        if ret:
            return self.success()

        return self.failure(f"{kind} failure")
