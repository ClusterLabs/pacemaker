""" Fence a running node and wait for it to restart """

__all__ = ["StonithdTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable
# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StonithdTest(CTSTest):
    """ A concrete test that fences a running node and waits for it to restart """

    def __init__(self, cm):
        """ Create a new StonithdTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)
        self.benchmark = True
        self.name = "Stonithd"

        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")
        if len(self._env["nodes"]) < 2:
            return self.skipped()

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        watchpats = [ self.templates["Pat:Fencing_ok"] % node,
                      self.templates["Pat:NodeFenced"] % node ]

        if not self._env["at-boot"]:
            self.debug("Expecting %s to stay down" % node)
            self._cm.ShouldBeStatus[node] = "down"
        else:
            self.debug("Expecting %s to come up again %d" % (node, self._env["at-boot"]))
            watchpats.extend([ "%s.* S_STARTING -> S_PENDING" % node,
                               "%s.* S_PENDING -> S_NOT_DC" % node ])

        watch = self.create_watch(watchpats, 30 + self._env["DeadTime"] + self._env["StableTime"] + self._env["StartTime"])
        watch.set_watch()

        origin = self._env.random_gen.choice(self._env["nodes"])

        (rc, _) = self._rsh(origin, "stonith_admin --reboot %s -VVVVVV" % node)

        if rc == ExitStatus.TIMEOUT:
            # Look for the patterns, usually this means the required
            # device was running on the node to be fenced - or that
            # the required devices were in the process of being loaded
            # and/or moved
            #
            # Effectively the node committed suicide so there will be
            # no confirmation, but pacemaker should be watching and
            # fence the node again

            self._logger.log("Fencing command on %s to fence %s timed out" % (origin, node))

        elif origin != node and rc != 0:
            self.debug("Waiting for the cluster to recover")
            self._cm.cluster_stable()

            self.debug("Waiting for fenced node to come back up")
            self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

            self._logger.log("Fencing command on %s failed to fence %s (rc=%d)" % (origin, node, rc))

        elif origin == node and rc != 255:
            # 255 == broken pipe, ie. the node was fenced as expected
            self._logger.log("Locally originated fencing returned %d" % rc)

        with Timer(self._logger, self.name, "fence"):
            matched = watch.look_for_all()

        self.set_timer("reform")
        if watch.unmatched:
            self._logger.log("Patterns not found: %r" % watch.unmatched)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected patterns")

        if not is_stable:
            return self.failure("Cluster did not become stable")

        self.log_timer("reform")
        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ self.templates["Pat:Fencing_start"] % ".*",
                 self.templates["Pat:Fencing_ok"] % ".*",
                 self.templates["Pat:Fencing_active"],
                 r"error.*: Operation 'reboot' targeting .* by .* for stonith_admin.*: Timer expired" ]

    def is_applicable(self):
        """ Return True if this test is applicable in the current test configuration. """

        if not CTSTest.is_applicable(self):
            return False

        # pylint gets confused because of EnvFactory here.
        # pylint: disable=unsupported-membership-test
        if "DoFencing" in self._env:
            return self._env["DoFencing"]

        return True
