""" Stop the cluster manager on a given node """

__all__ = ["StopTest"]
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


class StopTest(CTSTest):
    """ A pseudo-test that is only used to set up conditions before running
        some other test.  This class stops the cluster manager on a given
        node.

        Other test classes should not use this one as a superclass.
    """

    def __init__(self, cm):
        """ Create a new StopTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)
        self.name = "Stop"

    def __call__(self, node):
        """ Stop the given node, returning whether this succeeded or not """

        self.incr("calls")
        if self._cm.ShouldBeStatus[node] != "up":
            return self.skipped()

        # Technically we should always be able to notice ourselves stopping
        patterns = [ self.templates["Pat:We_stopped"] % node ]

        # Any active node needs to notice this one left
        # (note that this won't work if we have multiple partitions)
        for other in self._env["nodes"]:
            if self._cm.ShouldBeStatus[other] == "up" and other != node:
                patterns.append(self.templates["Pat:They_stopped"] %(other, self._cm.key_for_node(node)))

        watch = self.create_watch(patterns, self._env["DeadTime"])
        watch.set_watch()

        if node == self._cm.OurNode:
            self.incr("us")
        else:
            if self._cm.upcount() <= 1:
                self.incr("all")
            else:
                self.incr("them")

        self._cm.StopaCM(node)
        watch.look_for_all()

        failreason = None
        unmatched_str = "||"

        if watch.unmatched:
            (_, output) = self._rsh(node, "/bin/ps axf", verbose=1)
            for line in output:
                self.debug(line)

            (_, output) = self._rsh(node, "/usr/sbin/dlm_tool dump 2>/dev/null", verbose=1)
            for line in output:
                self.debug(line)

            for regex in watch.unmatched:
                self._logger.log ("ERROR: Shutdown pattern not found: %s" % regex)
                unmatched_str +=  "%s||" % regex
                failreason = "Missing shutdown pattern"

        self._cm.cluster_stable(self._env["DeadTime"])

        if not watch.unmatched or self._cm.upcount() == 0:
            return self.success()

        if len(watch.unmatched) >= self._cm.upcount():
            return self.failure("no match against (%s)" % unmatched_str)

        if failreason is None:
            return self.success()

        return self.failure(failreason)
