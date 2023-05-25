""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["PartialStart"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.stoptest import StopTest


class PartialStart(CTSTest):
    '''Start a node - but tell it to stop before it finishes starting up'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "PartialStart"
        self._startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)
        self._stop = StopTest(cm)

    def __call__(self, node):
        '''Perform the 'PartialStart' test. '''
        self.incr("calls")

        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")

        watchpats = []
        watchpats.append("pacemaker-controld.*Connecting to .* cluster infrastructure")
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
        watch.set_watch()

        self._cm.StartaCMnoBlock(node)
        ret = watch.look_for_all()
        if not ret:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))
            return self.failure("Setup of %s failed" % node)

        ret = self._stop(node)
        if not ret:
            return self.failure("%s did not stop in time" % node)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        # We might do some fencing in the 2-node case if we make it up far enough
        return [ r"Executing reboot fencing operation",
                 r"Requesting fencing \([^)]+\) targeting node " ]
