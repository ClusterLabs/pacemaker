"""Stop all running nodes serially."""

__all__ = ["StopOnebyOne"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.stoptest import StopTest


class StopOnebyOne(CTSTest):
    """Stop all running nodes serially."""

    def __init__(self, cm, env):
        """
        Create a new StartOnebyOne instance.

        Arguments:
        cm  -- A ClusterManager instance
        env -- An Environment instance
        """
        CTSTest.__init__(self, cm, env)

        self.name = "StopOnebyOne"

        self._startall = SimulStartLite(cm, env)
        self._stop = StopTest(cm, env)

    def __call__(self, dummy):
        """Perform this test."""
        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._stop(node):
                failed.append(node)

        if failed:
            return self.failure(f"Some node failed to stop: {failed!r}")

        return self.success()
