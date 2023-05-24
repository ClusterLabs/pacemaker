""" Stop running nodes, and start stopped nodes """

__all__ = ["FlipTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


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
            kind = "up->down"
            # Give the cluster time to recognize it's gone...
            time.sleep(self._env["StableTime"])
        elif self._cm.ShouldBeStatus[node] == "down":
            self.incr("started")
            ret = self._start(node)
            kind = "down->up"
        else:
            return self.skipped()

        self.incr(kind)
        if ret:
            return self.success()

        return self.failure("%s failure" % kind)
