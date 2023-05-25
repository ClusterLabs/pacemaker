""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["RestartOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.restarttest import RestartTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite


class RestartOnebyOne(CTSTest):
    '''Restart all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "RestartOnebyOne"
        self._startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'RestartOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        did_fail = []
        self.set_timer()
        self.restart = RestartTest(self._cm)
        for node in self._env["nodes"]:
            if not self.restart(node):
                did_fail.append(node)

        if did_fail:
            return self.failure("Could not restart %d nodes: %s"
                                % (len(did_fail), repr(did_fail)))
        return self.success()
