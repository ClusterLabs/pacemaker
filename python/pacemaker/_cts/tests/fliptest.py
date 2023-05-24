""" Stop running nodes, and start stopped nodes """

__all__ = ["FlipTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest


class FlipTest(CTSTest):
    """ A concrete test that stops running nodes and starts stopped nodes """

    def __init__(self, cm):
        """ Create a new FlipTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)
        self.name = "Flip"

        self._start = StartTest(cm)
        self._stop = StopTest(cm)

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")

        if self._cm.ShouldBeStatus[node] == "up":
            self.incr("stopped")
            ret = self._stop(node)
            type = "up->down"
            # Give the cluster time to recognize it's gone...
            time.sleep(self._env["StableTime"])
        elif self._cm.ShouldBeStatus[node] == "down":
            self.incr("started")
            ret = self._start(node)
            type = "down->up"
        else:
            return self.skipped()

        self.incr(type)
        if ret:
            return self.success()
        else:
            return self.failure("%s failure" % type)
