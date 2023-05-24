""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["StartOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest


class StartOnebyOne(CTSTest):
    '''Start all the nodes ~ one by one'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "StartOnebyOne"
        self.stopall = SimulStopLite(cm)
        self._start = StartTest(cm)
        self.ns = NodeStatus(cm.Env)

    def __call__(self, dummy):
        '''Perform the 'StartOnebyOne' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
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
