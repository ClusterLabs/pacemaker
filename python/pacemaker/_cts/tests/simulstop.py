""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["SimulStop"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite


class SimulStop(CTSTest):
    '''Stop all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStop"
        self._startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStop' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self.stopall(None):
            return self.failure("Stopall failed")

        return self.success()
