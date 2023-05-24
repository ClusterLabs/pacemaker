""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["SimulStart"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite


class SimulStart(CTSTest):
    '''Start all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStart"
        self.stopall = SimulStopLite(cm)
        self._startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStart' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._startall(None):
            return self.failure("Startall failed")

        return self.success()
