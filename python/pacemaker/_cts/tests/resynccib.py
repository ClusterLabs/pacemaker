"""Start the cluster without a CIB and verify it gets copied from another node."""

__all__ = ["ResyncCIB"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker import BuildOptions
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.restarttest import RestartTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite


class ResyncCIB(CTSTest):
    """Start the cluster on a node without a CIB and verify the CIB is copied over later."""

    def __init__(self, cm):
        """
        Create a new ResyncCIB instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.name = "ResyncCIB"

        self._restart1 = RestartTest(cm)
        self._startall = SimulStartLite(cm)
        self._stopall = SimulStopLite(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")

        # Shut down all the nodes...
        if not self._stopall(None):
            return self.failure("Could not stop all nodes")

        # Test config recovery when the other nodes come up
        self._rsh.call(node, f"rm -f {BuildOptions.CIB_DIR}/cib*")

        # Start the selected node
        if not self._restart1(node):
            return self.failure(f"Could not start {node}")

        # Start all remaining nodes
        if not self._startall(None):
            return self.failure("Could not start the remaining nodes")

        return self.success()

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        # Errors that occur as a result of the CIB being wiped
        return [
            r"error.*: v1 patchset error, patch failed to apply: Application of an update diff failed",
            r"error.*: Resource start-up disabled since no fencing resources have been defined. "
            "Either configure some or disable fencing with the fencing-enabled option. "
            "NOTE: Clusters with shared data need fencing to ensure data integrity."
        ]
