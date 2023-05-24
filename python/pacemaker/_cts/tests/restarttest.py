""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["RestartTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest


class RestartTest(CTSTest):
    '''Stop and restart a node'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "Restart"
        self._start = StartTest(cm)
        self._stop = StopTest(cm)
        self.benchmark = True

    def __call__(self, node):
        '''Perform the 'restart' test. '''
        self.incr("calls")

        self.incr("node:" + node)

        ret1 = 1
        if self._cm.StataCM(node):
            self.incr("WasStopped")
            if not self._start(node):
                return self.failure("start (setup) failure: "+node)

        self.set_timer()
        if not self._stop(node):
            return self.failure("stop failure: "+node)
        if not self._start(node):
            return self.failure("start failure: "+node)
        return self.success()
