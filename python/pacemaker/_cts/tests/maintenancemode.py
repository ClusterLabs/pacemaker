""" Toggle nodes in and out of maintenance mode """

__all__ = ["MaintenanceMode"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re

from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable


class MaintenanceMode(CTSTest):
    """ A concrete test that toggles nodes in and out of maintenance mode """

    def __init__(self, cm):
        """ Create a new MaintenanceMode instance

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
        """ Toggle maintenance mode on the given node """

        pats = [ self.templates["Pat:DC_IDLE"] ]

        if enabled:
            action = "On"
        else:
            action = "Off"

        # fail the resource right after turning Maintenance mode on
        # verify it is not recovered until maintenance mode is turned off
        if enabled:
            pats.append(self.templates["Pat:RscOpFail"] % (self._action, self._rid))
        else:
            pats.extend([ self.templates["Pat:RscOpOK"] % ("stop", self._rid),
                          self.templates["Pat:RscOpOK"] % ("start", self._rid) ])

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self.debug("Turning maintenance mode %s" % action)
        self._rsh(node, self.templates["MaintenanceMode%s" % action])

        if enabled:
            self._rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self._rid, node))

        with Timer(self._logger, self.name, "recover%s" % action):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when turning maintenance mode %s" % action)
            return repr(watch.unmatched)

        return ""

    def _insert_maintenance_dummy(self, node):
        """ Create a dummy resource on the given node """

        pats = [ ("%s.*" % node) + (self.templates["Pat:RscOpOK"] % ("start", self._rid)) ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.AddDummyRsc(node, self._rid)

        with Timer(self._logger, self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def _remove_maintenance_dummy(self, node):
        """ Remove the previously created dummy resource on the given node """

        pats = [ self.templates["Pat:RscOpOK"] % ("stop", self._rid) ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()
        self._cm.RemoveDummyRsc(node, self._rid)

        with Timer(self._logger, self.name, "removeDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when removing maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def _managed_rscs(self, node):
        """ Return a list of all resources managed by the cluster """

        rscs = []
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)

                if tmp.managed:
                    rscs.append(tmp.id)

        return rscs

    def _verify_resources(self, node, rscs, managed):
        """ Verify that all resources in rscList are managed if they are expected
            to be, or unmanaged if they are expected to be.
        """

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
            self.debug("Found all %s resources on %s" % (managed_str, node))
            return True

        self._logger.log("Could not find all %s resources on %s. %s" % (managed_str, node, managed_rscs))
        return False

    def __call__(self, node):
        """ Perform this test """

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
            self._logger.log("No managed resources on %s" % node)
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
            return self.failure("Unmatched patterns: %s" % fail_pat)

        if not verify_unmanaged:
            return self.failure("Failed to verify resources became unmanaged during maintenance mode")

        if not verify_managed:
            return self.failure("Failed to verify resources switched back to managed after disabling maintenance mode")

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for %s" % self._rid,
                 r"schedulerd.*: Recover\s+%s\s+\(.*\)" % self._rid,
                 r"Unknown operation: fail",
                 self.templates["Pat:RscOpOK"] % (self._action, self._rid),
                 r"(ERROR|error).*: Action %s_%s_%d .* initiated outside of a transition" % (self._rid, self._action, 0) ]
