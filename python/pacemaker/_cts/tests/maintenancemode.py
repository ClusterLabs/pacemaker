"""Toggle nodes in and out of maintenance mode."""

__all__ = ["MaintenanceMode"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re

from pacemaker._cts import logging
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.timer import Timer


class MaintenanceMode(CTSTest):
    """Toggle nodes in and ount of maintenance mode."""

    def __init__(self, cm):
        """
        Create a new MaintenanceMode instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.benchmark = True
        self.name = "MaintenanceMode"

        self._action = "asyncmon"
        self._rid = "maintenanceDummy"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def _toggle_maintenance_mode(self, node, enabled):
        """Toggle maintenance mode on the given node."""
        pats = [
            self._cm.templates["Pat:DC_IDLE"]
        ]

        if enabled:
            action = "On"
        else:
            action = "Off"

        # fail the resource right after turning Maintenance mode on
        # verify it is not recovered until maintenance mode is turned off
        if enabled:
            pats.append(self._cm.templates["Pat:RscOpFail"] % (self._action, self._rid))
        else:
            pats.extend([
                self._cm.templates["Pat:RscOpOK"] % ("stop", self._rid),
                self._cm.templates["Pat:RscOpOK"] % ("start", self._rid)
            ])

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self.debug(f"Turning maintenance mode {action}")
        self._rsh(node, self._cm.templates[f"MaintenanceMode{action}"])

        if enabled:
            self._rsh(node, f"crm_resource -V -F -r {self._rid} -H {node} &>/dev/null")

        with Timer(self.name, f"recover{action}"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug(f"Failed to find patterns when turning maintenance mode {action}")
            return repr(watch.unmatched)

        return ""

    def _insert_maintenance_dummy(self, node):
        """Create a dummy resource on the given node."""
        pats = [
            f"{node}.*" + (self._cm.templates["Pat:RscOpOK"] % ("start", self._rid))
        ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.add_dummy_rsc(node, self._rid)

        with Timer(self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def _remove_maintenance_dummy(self, node):
        """Remove the previously created dummy resource on the given node."""
        pats = [
            self._cm.templates["Pat:RscOpOK"] % ("stop", self._rid)
        ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()
        self._cm.remove_dummy_rsc(node, self._rid)

        with Timer(self.name, "removeDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when removing maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def _managed_rscs(self, node):
        """Return a list of all resources managed by the cluster."""
        rscs = []
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)

                if tmp.managed:
                    rscs.append(tmp.id)

        return rscs

    def _verify_resources(self, node, rscs, managed):
        """Verify that all resources are managed or unmanaged as expected."""
        managed_rscs = rscs
        managed_str = "managed"

        if not managed:
            managed_str = "unmanaged"

        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)

                if managed and not tmp.managed:
                    continue

                if not managed and tmp.managed:
                    continue

                if managed_rscs.count(tmp.id):
                    managed_rscs.remove(tmp.id)

        if not managed_rscs:
            self.debug(f"Found all {managed_str} resources on {node}")
            return True

        logging.log(f"Could not find all {managed_str} resources on {node}. {managed_rscs}")
        return False

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        verify_managed = False
        verify_unmanaged = False
        fail_pat = ""

        if not self._startall(None):
            return self.failure("Setup failed")

        # get a list of all the managed resources. We use this list
        # after enabling maintenance mode to verify all managed resources
        # become un-managed.  After maintenance mode is turned off, we use
        # this list to verify all the resources become managed again.
        managed_rscs = self._managed_rscs(node)
        if not managed_rscs:
            logging.log(f"No managed resources on {node}")
            return self.skipped()

        # insert a fake resource we can fail during maintenance mode
        # so we can verify recovery does not take place until after maintenance
        # mode is disabled.
        fail_pat += self._insert_maintenance_dummy(node)

        # toggle maintenance mode ON, then fail dummy resource.
        fail_pat += self._toggle_maintenance_mode(node, True)

        # verify all the resources are now unmanaged
        if self._verify_resources(node, managed_rscs, False):
            verify_unmanaged = True

        # Toggle maintenance mode  OFF, verify dummy is recovered.
        fail_pat += self._toggle_maintenance_mode(node, False)

        # verify all the resources are now managed again
        if self._verify_resources(node, managed_rscs, True):
            verify_managed = True

        # Remove our maintenance dummy resource.
        fail_pat += self._remove_maintenance_dummy(node)

        self._cm.cluster_stable()

        if fail_pat != "":
            return self.failure(f"Unmatched patterns: {fail_pat}")

        if not verify_unmanaged:
            return self.failure("Failed to verify resources became unmanaged during maintenance mode")

        if not verify_managed:
            return self.failure("Failed to verify resources switched back to managed after disabling maintenance mode")

        return self.success()

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return [
            f"Updating failcount for {self._rid}",
            fr"schedulerd.*: Recover\s+{self._rid}\s+\(.*\)",
            r"Unknown operation: fail",
            self._cm.templates["Pat:RscOpOK"] % (self._action, self._rid),
            f"(ERROR|error).*: Action {self._rid}_{self._action}_0 .* initiated outside of a transition",
        ]
