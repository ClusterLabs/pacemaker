""" Restart all nodes in order """

__all__ = ["RestartOnebyOne"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.restarttest import RestartTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class RestartOnebyOne(CTSTest):
    """ A concrete test that restarts all nodes in order """

    def __init__(self, cm):
        """ Create a new RestartOnebyOne instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.name = "RestartOnebyOne"

        self._restart = None
        self._startall = SimulStartLite(cm)

    def __call__(self, dummy):
        """ Perform the test """

        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        did_fail = []
        self.set_timer()
        self._restart = RestartTest(self._cm)

        for node in self._env["nodes"]:
            if not self._restart(node):
                did_fail.append(node)

        if did_fail:
            return self.failure("Could not restart %d nodes: %s"
                                % (len(did_fail), repr(did_fail)))

        return self.success()
