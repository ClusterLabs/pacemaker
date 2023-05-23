""" Start the cluster manager on a given node """

__all__ = ["StartTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StartTest(CTSTest):
    """ A pseudo-test that is only used to set up conditions before running
        some other test.  This class starts the cluster manager on a given
        node.

        Other test classes should not use this one as a superclass.
    """

    def __init__(self, cm):
        """ Create a new StartTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self,cm)
        self.name = "Start"

    def __call__(self, node):
        """ Start the given node, returning whether this succeeded or not """

        self.incr("calls")

        if self._cm.upcount() == 0:
            self.incr("us")
        else:
            self.incr("them")

        if self._cm.ShouldBeStatus[node] != "down":
            return self.skipped()

        if self._cm.StartaCM(node):
            return self.success()

        return self.failure("Startup %s on node %s failed"
                            % (self._env["Name"], node))
