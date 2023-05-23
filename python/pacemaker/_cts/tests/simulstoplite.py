""" Simultaneously stop running nodes """

__all__ = ["SimulStopLite"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable
# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class SimulStopLite(CTSTest):
    """ A pseudo-test that is only used to set up conditions before running
        some other test.  This class stops any running nodes more or less
        simultaneously.  It can be used both to set up a test or to clean up
        a test.

        Other test classes should not use this one as a superclass.
    """

    def __init__(self, cm):
        """ Create a new SimulStopLite instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self,cm)
        self.name = "SimulStopLite"

    def __call__(self, dummy):
        """ Stop all running nodes more or less simultaneously, returning
            whether this succeeded or not.
        """

        self.incr("calls")
        self.debug("Setup: %s" % self.name)

        # We ignore the "node" parameter...
        watchpats = []

        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self.incr("WasStarted")
                watchpats.append(self.templates["Pat:We_stopped"] % node)

        if len(watchpats) == 0:
            return self.success()

        # Stop all the nodes - at about the same time...
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)

        watch.set_watch()
        self.set_timer()
        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self._cm.StopaCMnoBlock(node)

        if watch.look_for_all():
            # Make sure they're completely down with no residule
            for node in self._env["nodes"]:
                self._rsh(node, self.templates["StopCmd"])

            return self.success()

        did_fail = False
        up_nodes = []
        for node in self._env["nodes"]:
            if self._cm.StataCM(node) == 1:
                did_fail = True
                up_nodes.append(node)

        if did_fail:
            return self.failure("Active nodes exist: %s" % up_nodes)

        self._logger.log("Warn: All nodes stopped but CTS didn't detect: %s" % watch.unmatched)
        return self.failure("Missing log message: %s " % watch.unmatched)

    def is_applicable(self):
        """ SimulStopLite is a setup test and never applicable """

        return False
