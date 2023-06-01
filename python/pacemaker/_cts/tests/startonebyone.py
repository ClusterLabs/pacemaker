""" Start all stopped nodes serially """

__all__ = ["StartOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StartOnebyOne(CTSTest):
    """ A concrete test that starts all stopped nodes serially """

    def __init__(self, cm):
        """ Create a new StartOnebyOne instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)
        self.name = "StartOnebyOne"

        self._start = StartTest(cm)
        self._stopall = SimulStopLite(cm)

    def __call__(self, dummy):
        """ Perform this test """

        self.incr("calls")

        ret = self._stopall(None)
        if not ret:
            return self.failure("Test setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._start(node):
                failed.append(node)

        if failed:
            return self.failure("Some node failed to start: %r" % failed)

        return self.success()
