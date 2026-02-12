"""Restart the cluster and verify resources remain running."""

__all__ = ["Reattach"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import time

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts import logging
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest


class Reattach(CTSTest):
    """Restart the cluster and verify that resources remain running throughout."""

    def __init__(self, cm):
        """
        Create a new Reattach instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.name = "Reattach"

        self._startall = SimulStartLite(cm)
        self._stopall = SimulStopLite(cm)

    def _is_managed(self, node):
        """Return whether resources are managed by the cluster."""
        (_, is_managed) = self._rsh.call(node, "crm_attribute -t rsc_defaults -n is-managed -q -G -d true", verbose=1)
        is_managed = is_managed[0].strip()
        return is_managed == "true"

    def _set_unmanaged(self, node):
        """Disable resource management."""
        self.debug("Disable resource management")
        self._rsh.call(node, "crm_attribute -t rsc_defaults -n is-managed -v false")

    def _set_managed(self, node):
        """Enable resource management."""
        self.debug("Re-enable resource management")
        self._rsh.call(node, "crm_attribute -t rsc_defaults -n is-managed -D")

    def _disable_incompatible_rscs(self, node):
        """
        Disable resources that are incompatible with this test.

        Starts and stops of stonith-class resources are implemented internally
        by Pacemaker, which means that they must stop when Pacemaker is
        stopped, even if unmanaged. Disable them before running the Reattach
        test so they don't affect resource placement.

        Set target-role to "Stopped" for any of these resources in the CIB.
        """
        self.debug("Disable incompatible resources")
        xml = """'<meta_attributes id="cts-lab-Reattach-meta">
                    <nvpair id="cts-lab-Reattach-target-role" name="target-role" value="Stopped"/>
                    <rule id="cts-lab-Reattach-rule" boolean-op="or" score="INFINITY">
                      <rsc_expression id="cts-lab-Reattach-stonith" class="stonith"/>
                    </rule>
                  </meta_attributes>' --scope rsc_defaults"""
        return self._rsh.call(node, self._cm.templates['CibAddXml'] % xml)

    def _enable_incompatible_rscs(self, node):
        """Re-enable resources that were incompatible with this test."""
        self.debug("Re-enable incompatible resources")
        xml = """<meta_attributes id="cts-lab-Reattach-meta"/>"""
        return self._rsh.call(node, f"""cibadmin --delete --xml-text '{xml}'""")

    def _reprobe(self, node):
        """
        Reprobe all resources.

        The placement of some resources (such as promotable-1 in the
        lab-generated CIB) is affected by constraints using node-attribute-based
        rules. An earlier test may have erased the relevant node attribute, so
        do a reprobe, which should add the attribute back.
        """
        return self._rsh.call(node, """crm_resource --refresh""")

    def setup(self, node):
        """Set up this test."""
        if not self._startall(None):
            return self.failure("Startall failed")

        (rc, _) = self._disable_incompatible_rscs(node)
        if rc != ExitStatus.OK:
            return self.failure("Couldn't modify CIB to stop incompatible resources")

        (rc, _) = self._reprobe(node)
        if rc != ExitStatus.OK:
            return self.failure("Couldn't reprobe resources")

        if not self._cm.cluster_stable(double_check=True):
            return self.failure("Cluster did not stabilize after setup")

        return self.success()

    def teardown(self, node):
        """Tear down this test."""
        # Make sure 'node' is up
        start = StartTest(self._cm)
        start(node)

        if not self._is_managed(node):
            self._set_managed(node)

        (rc, _) = self._enable_incompatible_rscs(node)
        if rc != ExitStatus.OK:
            return self.failure("Couldn't modify CIB to re-enable incompatible resources")

        if not self._cm.cluster_stable():
            return self.failure("Cluster did not stabilize after teardown")
        if not self._is_managed(node):
            return self.failure("Could not re-enable resource management")

        return self.success()

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")

        # Conveniently, the scheduler will display this message when disabling
        # management, even if fencing is not enabled, so we can rely on it.
        managed = self.create_watch(["No fencing will be done"], 60)
        managed.set_watch()

        self._set_unmanaged(node)

        if not managed.look_for_all():
            logging.log(f"Patterns not found: {managed.unmatched!r}")
            return self.failure("Resource management not disabled")

        pats = [
            self._cm.templates["Pat:RscOpOK"] % ("start", ".*"),
            self._cm.templates["Pat:RscOpOK"] % ("stop", ".*"),
            self._cm.templates["Pat:RscOpOK"] % ("promote", ".*"),
            self._cm.templates["Pat:RscOpOK"] % ("demote", ".*"),
            self._cm.templates["Pat:RscOpOK"] % ("migrate", ".*")
        ]

        watch = self.create_watch(pats, 60, "ShutdownActivity")
        watch.set_watch()

        self.debug("Shutting down the cluster")
        ret = self._stopall(None)
        if not ret:
            self._set_managed(node)
            return self.failure("Couldn't shut down the cluster")

        self.debug("Bringing the cluster back up")
        ret = self._startall(None)
        time.sleep(5)  # allow ping to update the CIB
        if not ret:
            self._set_managed(node)
            return self.failure("Couldn't restart the cluster")

        if self.local_badnews("ResourceActivity:", watch):
            self._set_managed(node)
            return self.failure("Resources stopped or started during cluster restart")

        watch = self.create_watch(pats, 60, "StartupActivity")
        watch.set_watch()

        # Re-enable resource management (and verify it happened).
        self._set_managed(node)
        self._cm.cluster_stable()
        if not self._is_managed(node):
            return self.failure("Could not re-enable resource management")

        # Ignore actions for STONITH resources
        ignore = []
        (_, lines) = self._rsh.call(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self._cm, line)

                if r.rclass == "stonith":
                    self.debug(f"Ignoring start actions for {r.id}")
                    ignore.append(self._cm.templates["Pat:RscOpOK"] % ("start", r.id))

        if self.local_badnews("ResourceActivity:", watch, ignore):
            return self.failure("Resources stopped or started after resource management was re-enabled")

        return ret

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return [
            r"resource( was|s were) active at shutdown"
        ]
