"""Start all stopped nodes serially."""

__all__ = ["StartOnebyOne"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest


class StartOnebyOne(CTSTest):
    """Start all stopped nodes serially."""

    def __init__(self, cm, env):
        """
        Create a new StartOnebyOne instance.

        Arguments:
        cm  -- A ClusterManager instance
        env -- An Environment instance
        """
        CTSTest.__init__(self, cm, env)
        self.name = "StartOnebyOne"

        self._start = StartTest(cm, env)
        self._stopall = SimulStopLite(cm, env)

    def __call__(self, dummy):
        """Perform this test."""
        self.incr("calls")

        ret = self._stopall(None)
        if not ret:
            return self.failure("Test setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._start(node):
                failed.append(node)

        if failed:
            return self.failure(f"Some node failed to start: {failed!r}")

        return self.success()
