""" Start all stopped nodes serially """

__all__ = ["StartOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest


class StartOnebyOne(CTSTest):
    """ A concrete test that starts all stopped nodes serially """

    def __init__(self, cm):
        """ Create a new StartOnebyOne instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)
        self.name = "StartOnebyOne"
        self.ns = NodeStatus(cm.Env)
        self.stopall = SimulStopLite(cm)

        self._start = StartTest(cm)

    def __call__(self, dummy):
        """ Perform this test """

        self.incr("calls")

        ret = self.stopall(None)
        if not ret:
            return self.failure("Test setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._start(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to start: " + repr(failed))

        return self.success()
