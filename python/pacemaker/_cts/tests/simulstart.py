""" Start all stopped nodes simultaneously """

__all__ = ["SimulStart"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite


class SimulStart(CTSTest):
    """ A concrete test that starts all stopped nodes simultaneously """

    def __init__(self, cm):
        """ Create a new SimulStart instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.name = "SimulStart"

        self._startall = SimulStartLite(cm)
        self._stopall = SimulStopLite(cm)

    def __call__(self, dummy):
        """ Perform this test """

        self.incr("calls")

        ret = self._stopall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._startall(None):
            return self.failure("Startall failed")

        return self.success()
