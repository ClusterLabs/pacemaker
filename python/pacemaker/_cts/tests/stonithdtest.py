"""Fence a running node and wait for it to restart."""

__all__ = ["StonithdTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts import logging
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StonithdTest(CTSTest):
    """Fence a running node and wait for it to restart."""

    def __init__(self, cm):
        """
        Create a new StonithdTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.benchmark = True
        self.name = "Stonithd"

        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        if len(self._env["nodes"]) < 2:
            return self.skipped()

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        watchpats = [
            self._cm.templates["Pat:Fencing_ok"] % node,
            self._cm.templates["Pat:NodeFenced"] % node,
        ]

        if not self._env["at-boot"]:
            self.debug(f"Expecting {node} to stay down")
            self._cm.expected_status[node] = "down"
        else:
            self.debug(f"Expecting {node} to come up again {self._env['at-boot']}")
            watchpats.extend([
                f"{node}.* S_STARTING -> S_PENDING",
                f"{node}.* S_PENDING -> S_NOT_DC",
            ])

        watch = self.create_watch(watchpats,
                                  30 + self._env["dead_time"] + self._env["stable_time"] + self._env["start_time"])
        watch.set_watch()

        origin = self._env.random_gen.choice(self._env["nodes"])

        (rc, _) = self._rsh.call(origin, f"stonith_admin --reboot {node} -VVVVVV")

        if rc == ExitStatus.TIMEOUT:
            # Look for the patterns, usually this means the required
            # device was running on the node to be fenced - or that
            # the required devices were in the process of being loaded
            # and/or moved
            #
            # Effectively the node committed suicide so there will be
            # no confirmation, but pacemaker should be watching and
            # fence the node again

            logging.log(f"Fencing command on {origin} to fence {node} timed out")

        elif origin != node and rc != 0:
            self.debug("Waiting for the cluster to recover")
            self._cm.cluster_stable()

            self.debug("Waiting for fenced node to come back up")
            self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

            logging.log(f"Fencing command on {origin} failed to fence {node} (rc={rc})")

        elif origin == node and rc != 255:
            # 255 == broken pipe, ie. the node was fenced as expected
            logging.log(f"Locally originated fencing returned {rc}")

        with Timer(self.name, "fence"):
            matched = watch.look_for_all()

        self.set_timer("reform")
        if watch.unmatched:
            logging.log(f"Patterns not found: {watch.unmatched!r}")

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["start_time"])

        if not matched:
            return self.failure("Didn't find all expected patterns")

        if not is_stable:
            return self.failure("Cluster did not become stable")

        self.log_timer("reform")
        return self.success()

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return [
            self._cm.templates["Pat:Fencing_start"] % ".*",
            self._cm.templates["Pat:Fencing_ok"] % ".*",
            self._cm.templates["Pat:Resource_active"],
            r"error.*: Operation 'reboot' targeting .* by .* for stonith_admin.*: Timer expired"
        ]

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        return self._env["fencing_enabled"] and CTSTest.is_applicable(self)
