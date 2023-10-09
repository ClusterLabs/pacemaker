""" Stop all running nodes serially """

__all__ = ["StopOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.stoptest import StopTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StopOnebyOne(CTSTest):
    """ A concrete test that stops all running nodes serially """

    def __init__(self, cm):
        """ Create a new StartOnebyOne instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.name = "StopOnebyOne"

        self._startall = SimulStartLite(cm)
        self._stop = StopTest(cm)

    def __call__(self, dummy):
        """ Perform this test """

        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._stop(node):
                failed.append(node)

        if failed:
            return self.failure("Some node failed to stop: %r" % failed)

        return self.success()
