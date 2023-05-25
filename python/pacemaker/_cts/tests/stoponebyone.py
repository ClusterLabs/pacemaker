""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["StopOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.stoptest import StopTest


class StopOnebyOne(CTSTest):
    '''Stop all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "StopOnebyOne"
        self._startall = SimulStartLite(cm)
        self._stop = StopTest(cm)

    def __call__(self, dummy):
        '''Perform the 'StopOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._stop(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to stop: " + repr(failed))

        return self.success()
