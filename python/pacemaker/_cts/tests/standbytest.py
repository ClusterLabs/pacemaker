"""Put a node into standby mode and check that resources migrate."""

__all__ = ["StandbyTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class StandbyTest(CTSTest):
    """Put a node into standby and check that resources migrate away from it."""

    def __init__(self, cm):
        """
        Create a new StandbyTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.benchmark = True
        self.name = "Standby"

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    # make sure the node is active
    # set the node to standby mode
    # check resources, none resource should be running on the node
    # set the node to active mode
    # check resources, resources should have been migrated back (SHOULD THEY?)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        self.debug(f"Make sure node {node} is active")
        if self._cm.in_standby_mode(node):
            if not self._cm.set_standby_mode(node, False):
                return self.failure(f"can't set node {node} to active mode")

        self._cm.cluster_stable()

        if self._cm.in_standby_mode(node):
            return self.failure(f"standby status of {node} is [on] but we expect [off]")

        watchpats = [
            r"State transition .* -> S_POLICY_ENGINE",
        ]
        watch = self.create_watch(watchpats, self._env["dead_time"] + 10)
        watch.set_watch()

        self.debug(f"Setting node {node} to standby mode")
        if not self._cm.set_standby_mode(node, True):
            return self.failure(f"can't set node {node} to standby mode")

        self.set_timer("on")

        ret = watch.look_for_all()
        if not ret:
            logging.log(f"Patterns not found: {watch.unmatched!r}")
            self._cm.set_standby_mode(node, False)
            return self.failure(f"cluster didn't react to standby change on {node}")

        self._cm.cluster_stable()

        if not self._cm.in_standby_mode(node):
            return self.failure(f"standby status of {node} is [off] but we expect [on]")

        self.log_timer("on")

        self.debug("Checking resources")
        rscs_on_node = self._cm.active_resources(node)
        if rscs_on_node:
            rc = self.failure(f"{node} set to standby, {rscs_on_node!r} is still running on it")
            self.debug(f"Setting node {node} to active mode")
            self._cm.set_standby_mode(node, False)
            return rc

        self.debug(f"Setting node {node} to active mode")
        if not self._cm.set_standby_mode(node, False):
            return self.failure(f"can't set node {node} to active mode")

        self.set_timer("off")
        self._cm.cluster_stable()

        if self._cm.in_standby_mode(node):
            return self.failure(f"standby status of {node} is [on] but we expect [off]")

        self.log_timer("off")

        return self.success()
