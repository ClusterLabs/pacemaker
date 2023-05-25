""" Put a node into standby mode and check that resources migrate """

__all__ = ["StandbyTest"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest


class StandbyTest(CTSTest):
    """ A concrete tests that puts a node into standby and checks that resources
        migrate away from the node
    """

    def __init__(self, cm):
        """ Create a new StandbyTest instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.name = "Standby"
        self.benchmark = True

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    # make sure the node is active
    # set the node to standby mode
    # check resources, none resource should be running on the node
    # set the node to active mode
    # check resources, resources should have been migrated back (SHOULD THEY?)

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")
        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        self.debug("Make sure node %s is active" % node)
        if self._cm.StandbyStatus(node) != "off":
            if not self._cm.SetStandbyMode(node, "off"):
                return self.failure("can't set node %s to active mode" % node)

        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))

        self.debug("Getting resources running on node %s" % node)
        rsc_on_node = self._cm.active_resources(node)

        watchpats = []
        watchpats.append(r"State transition .* -> S_POLICY_ENGINE")
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
        watch.set_watch()

        self.debug("Setting node %s to standby mode" % node)
        if not self._cm.SetStandbyMode(node, "on"):
            return self.failure("can't set node %s to standby mode" % node)

        self.set_timer("on")

        ret = watch.look_for_all()
        if not ret:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))
            self._cm.SetStandbyMode(node, "off")
            return self.failure("cluster didn't react to standby change on %s" % node)

        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "on":
            return self.failure("standby status of %s is [%s] but we expect [on]" % (node, status))

        self.log_timer("on")

        self.debug("Checking resources")
        bad_run = self._cm.active_resources(node)
        if len(bad_run) > 0:
            rc = self.failure("%s set to standby, %s is still running on it" % (node, repr(bad_run)))
            self.debug("Setting node %s to active mode" % node)
            self._cm.SetStandbyMode(node, "off")
            return rc

        self.debug("Setting node %s to active mode" % node)
        if not self._cm.SetStandbyMode(node, "off"):
            return self.failure("can't set node %s to active mode" % node)

        self.set_timer("off")
        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))

        self.log_timer("off")

        return self.success()
