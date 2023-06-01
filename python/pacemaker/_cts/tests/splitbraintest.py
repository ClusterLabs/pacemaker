""" Create a split brain cluster and verify a resource is multiply managed """

__all__ = ["SplitBrainTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest


class SplitBrainTest(CTSTest):
    """ A concrete test that creates a split brain cluster and verifies that
        one node in each partition takes over the resource, resulting in two
        nodes running the same resource.
    """

    def __init__(self, cm):
        """ Create a new SplitBrainTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.is_experimental = True
        self.name = "SplitBrain"

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def isolate_partition(self, partition):
        """ Create a new partition containing the given nodes """

        other_nodes = []
        other_nodes.extend(self._env["nodes"])

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self._logger.log("Node "+node+" not in " + repr(self._env["nodes"]) + " from " +repr(partition))

        if len(other_nodes) == 0:
            return 1

        self.debug("Creating partition: " + repr(partition))
        self.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            if not self._cm.isolate_node(node, other_nodes):
                self._logger.log("Could not isolate %s" % node)
                return 0

        return 1

    def heal_partition(self, partition):
        """ Move the given nodes out of their own partition back into the cluster """

        other_nodes = []
        other_nodes.extend(self._env["nodes"])

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self._logger.log("Node "+node+" not in " + repr(self._env["nodes"]))

        if len(other_nodes) == 0:
            return 1

        self.debug("Healing partition: " + repr(partition))
        self.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            self._cm.unisolate_node(node, other_nodes)

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")
        self.passed = True
        partitions = {}

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        while 1:
            # Retry until we get multiple partitions
            partitions = {}
            p_max = len(self._env["nodes"])

            for node in self._env["nodes"]:
                p = self._env.random_gen.randint(1, p_max)

                if not p in partitions:
                    partitions[p] = []

                partitions[p].append(node)

            p_max = len(list(partitions.keys()))
            if p_max > 1:
                break
            # else, try again

        self.debug("Created %d partitions" % p_max)
        for key in list(partitions.keys()):
            self.debug("Partition["+str(key)+"]:\t"+repr(partitions[key]))

        # Disabling STONITH to reduce test complexity for now
        self._rsh(node, "crm_attribute -V -n stonith-enabled -v false")

        for key in list(partitions.keys()):
            self.isolate_partition(partitions[key])

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
        for key in list(partitions.keys()):
            self.heal_partition(partitions[key])

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
            if len(partitions) > 0:
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

            if self._env["continue"]:
                answer = "Y"
            else:
                try:
                    answer = input('Continue? [nY]')
                except EOFError as e:
                    answer = "n"

            if answer and answer == "n":
                raise ValueError("Reformed cluster not stable")

        # Turn fencing back on
        if self._env["DoFencing"]:
            self._rsh(node, "crm_attribute -V -D -n stonith-enabled")

        self._cm.cluster_stable()

        if self.passed:
            return self.success()

        return self.failure("See previous errors")

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Another DC detected:",
                 r"(ERROR|error).*: .*Application of an update diff failed",
                 r"pacemaker-controld.*:.*not in our membership list",
                 r"CRIT:.*node.*returning after partition" ]

    def is_applicable(self):
        """ Return True if this test is applicable in the current test configuration. """

        if not CTSTest.is_applicable(self):
            return False

        return len(self._env["nodes"]) > 2
