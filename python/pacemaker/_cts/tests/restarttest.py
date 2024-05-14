"""Stop and restart a node."""

__all__ = ["RestartTest"]
__copyright__ = "Copyright 2000-2024 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest


class RestartTest(CTSTest):
    """Stop and restart a node."""

    def __init__(self, cm):
        """
        Create a new RestartTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.benchmark = True
        self.name = "Restart"

        self._start = StartTest(cm)
        self._stop = StopTest(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        self.incr("node:%s" % node)

        if self._cm.stat_cm(node):
            self.incr("WasStopped")
            if not self._start(node):
                return self.failure("start (setup) failure: %s" % node)

        self.set_timer()

        if not self._stop(node):
            return self.failure("stop failure: %s" % node)

        if not self._start(node):
            return self.failure("start failure: %s" % node)

        return self.success()
