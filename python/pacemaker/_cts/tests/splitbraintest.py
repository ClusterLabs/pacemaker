"""Create a split brain cluster and verify a resource is multiply managed."""

__all__ = ["SplitBrainTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts import logging
from pacemaker._cts.input import should_continue
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class SplitBrainTest(CTSTest):
    """
    Create a split brain cluster.

    This test verifies that one node in each partition takes over the
    resource, resulting in two nodes running the same resource.
    """

    def __init__(self, cm):
        """
        Create a new SplitBrainTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.is_unsafe = True
        self.name = "SplitBrain"

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def _isolate_partition(self, partition):
        """Create a new partition containing the given nodes."""
        other_nodes = self._env["nodes"].copy()

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                logging.log(f"Node {node} not in {self._env['nodes']!r} from {partition!r}")

        if not other_nodes:
            return

        self.debug(f"Creating partition: {partition!r}")
        self.debug(f"Everyone else: {other_nodes!r}")

        for node in partition:
            if not self._cm.isolate_node(node, other_nodes):
                logging.log(f"Could not isolate {node}")
                return

    def _heal_partition(self, partition):
        """Move the given nodes out of their own partition back into the cluster."""
        other_nodes = self._env["nodes"].copy()

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                logging.log(f"Node {node} not in {self._env['nodes']!r}")

        if len(other_nodes) == 0:
            return

        self.debug(f"Healing partition: {partition!r}")
        self.debug(f"Everyone else: {other_nodes!r}")

        for node in partition:
            self._cm.unisolate_node(node, other_nodes)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        self.passed = True
        partitions = {}

        if not self._startall(None):
            return self.failure("Setup failed")

        while True:
            # Retry until we get multiple partitions
            partitions = {}
            p_max = len(self._env["nodes"])

            for n in self._env["nodes"]:
                p = self._env.random_gen.randint(1, p_max)

                if p not in partitions:
                    partitions[p] = []

                partitions[p].append(n)

            p_max = len(partitions)
            if p_max > 1:
                break
            # else, try again

        self.debug(f"Created {p_max} partitions")
        for (key, val) in partitions.items():
            self.debug(f"Partition[{key}]:\t{val!r}")

        # Disabling STONITH to reduce test complexity for now
        self._rsh.call(node, "crm_attribute -V -n fencing-enabled -v false")

        for val in partitions.values():
            self._isolate_partition(val)

        count = 30
        while count > 0:
            if len(self._cm.find_partitions()) != p_max:
                time.sleep(10)
            else:
                break
        else:
            self.failure("Expected partitions were not created")

        # Target number of partitions formed - wait for stability
        if not self._cm.cluster_stable():
            self.failure("Partitioned cluster not stable")

        # Now audit the cluster state
        self._cm.partitions_expected = p_max
        if not self.audit():
            self.failure("Audits failed")

        self._cm.partitions_expected = 1

        # And heal them again
        for val in partitions.values():
            self._heal_partition(val)

        # Wait for a single partition to form
        count = 30
        while count > 0:
            if len(self._cm.find_partitions()) != 1:
                time.sleep(10)
                count -= 1
            else:
                break
        else:
            self.failure("Cluster did not reform")

        # Wait for it to have the right number of members
        count = 30
        while count > 0:
            members = []

            partitions = self._cm.find_partitions()
            if partitions:
                members = partitions[0].split()

            if len(members) != len(self._env["nodes"]):
                time.sleep(10)
                count -= 1
            else:
                break
        else:
            self.failure("Cluster did not completely reform")

        # Wait up to 20 minutes - the delay is more preferable than
        # trying to continue with in a messed up state
        if not self._cm.cluster_stable(1200):
            self.failure("Reformed cluster not stable")

            if not should_continue(self._env):
                raise ValueError("Reformed cluster not stable")

        # Turn fencing back on
        if self._env["fencing_enabled"]:
            self._rsh.call(node, "crm_attribute -V -D -n fencing-enabled")

        self._cm.cluster_stable()

        if self.passed:
            return self.success()

        return self.failure("See previous errors")

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return [
            r"Another DC detected:",
            r"(ERROR|error).*: .*Application of an update diff failed",
            r"pacemaker-controld.*:.*not in our membership list",
            r"CRIT:.*node.*returning after partition",
            self._cm.templates["Pat:Resource_active"],
        ]

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        if not CTSTest.is_applicable(self):
            return False

        return len(self._env["nodes"]) > 2
