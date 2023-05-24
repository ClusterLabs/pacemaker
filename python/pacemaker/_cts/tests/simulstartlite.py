""" Simultaneously start stopped nodes """

__all__ = ["SimulStartLite"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class SimulStartLite(CTSTest):
    """ A pseudo-test that is only used to set up conditions before running
        some other test.  This class starts any stopped nodes more or less
        simultaneously.

        Other test classes should not use this one as a superclass.
    """

    def __init__(self, cm):
        """ Create a new SimulStartLite instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self,cm)
        self.name = "SimulStartLite"

    def __call__(self, dummy):
        """ Start all stopped nodes more or less simultaneously, returning
            whether this succeeded or not.
        """

        self.incr("calls")
        self.debug("Setup: %s" % self.name)

        # We ignore the "node" parameter...
        node_list = []
        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "down":
                self.incr("WasStopped")
                node_list.append(node)

        self.set_timer()
        while len(node_list) > 0:
            # Repeat until all nodes come up
            uppat = self.templates["Pat:NonDC_started"]
            if self._cm.upcount() == 0:
                uppat = self.templates["Pat:Local_started"]

            watchpats = [ self.templates["Pat:DC_IDLE"] ]
            for node in node_list:
                watchpats.extend([uppat % node,
                                  self.templates["Pat:InfraUp"] % node,
                                  self.templates["Pat:PacemakerUp"] % node])

            #   Start all the nodes - at about the same time...
            watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
            watch.set_watch()

            stonith = self._cm.prepare_fencing_watcher(self.name)

            for node in node_list:
                self._cm.StartaCMnoBlock(node)

            watch.look_for_all()

            node_list = self._cm.fencing_cleanup(self.name, stonith)

            if node_list is None:
                return self.failure("Cluster did not stabilize")

            # Remove node_list messages from watch.unmatched
            for node in node_list:
                self._logger.debug("Dealing with stonith operations for %s" % node_list)
                if watch.unmatched:
                    try:
                        watch.unmatched.remove(uppat % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (uppat % node))

                    try:
                        watch.unmatched.remove(self.templates["Pat:InfraUp"] % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (self.templates["Pat:InfraUp"] % node))

                    try:
                        watch.unmatched.remove(self.templates["Pat:PacemakerUp"] % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (self.templates["Pat:PacemakerUp"] % node))

            if watch.unmatched:
                for regex in watch.unmatched:
                    self._logger.log ("Warn: Startup pattern not found: %s" % regex)

            if not self._cm.cluster_stable():
                return self.failure("Cluster did not stabilize")

        did_fail = False
        unstable = []
        for node in self._env["nodes"]:
            if self._cm.StataCM(node) == 0:
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure("Unstarted nodes exist: %s" % unstable)

        unstable = []
        for node in self._env["nodes"]:
            if not self._cm.node_stable(node):
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure("Unstable cluster nodes exist: %s" % unstable)

        return self.success()

    def is_applicable(self):
        """ SimulStartLite is a setup test and never applicable """

        return False
