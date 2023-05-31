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


class MaintenanceMode(CTSTest):
    """ A concrete test that toggles nodes in and out of maintenance mode """

    def __init__(self, cm):
        """ Create a new MaintenanceMode instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.action = "asyncmon"
        self.benchmark = True
        self.interval = 0
        self.max = 30
        self.name = "MaintenanceMode"
        self.rid = "maintenanceDummy"

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def toggleMaintenanceMode(self, node, action):
        """ Toggle maintenance mode on the given node """

        pats = []
        pats.append(self.templates["Pat:DC_IDLE"])

        # fail the resource right after turning Maintenance mode on
        # verify it is not recovered until maintenance mode is turned off
        if action == "On":
            pats.append(self.templates["Pat:RscOpFail"] % (self.action, self.rid))
        else:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))
            pats.append(self.templates["Pat:RscOpOK"] % ("start", self.rid))

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self.debug("Turning maintenance mode %s" % action)
        self._rsh(node, self.templates["MaintenanceMode%s" % (action)])

        if (action == "On"):
            self._rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self.rid, node))

        with Timer(self._logger, self.name, "recover%s" % action):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when turning maintenance mode %s" % action)
            return repr(watch.unmatched)

        return ""

    def insertMaintenanceDummy(self, node):
        """ Create a dummy resource on the given node """

        pats = []
        pats.append(("%s.*" % node) + (self.templates["Pat:RscOpOK"] % ("start", self.rid)))

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.AddDummyRsc(node, self.rid)

        with Timer(self._logger, self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def removeMaintenanceDummy(self, node):
        """ Remove the previously created dummy resource on the given node """

        pats = []
        pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))

        watch = self.create_watch(pats, 60)
        watch.set_watch()
        self._cm.RemoveDummyRsc(node, self.rid)

        with Timer(self._logger, self.name, "removeDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when removing maintenance dummy resource")
            return repr(watch.unmatched)

        return ""

    def managedRscList(self, node):
        """ Return a list of all resources managed by the cluster """

        rscList = []
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)

                if tmp.managed:
                    rscList.append(tmp.id)

        return rscList

    def verifyResources(self, node, rscList, managed):
        """ Verify that all resources in rscList are managed if they are expected
            to be, or unmanaged if they are expected to be.
        """

        managedList = list(rscList)
        managed_str = "managed"

        if not managed:
            managed_str = "unmanaged"

        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)

                if managed and not tmp.managed:
                    continue
                elif not managed and tmp.managed:
                    continue
                elif managedList.count(tmp.id):
                    managedList.remove(tmp.id)

        if len(managedList) == 0:
            self.debug("Found all %s resources on %s" % (managed_str, node))
            return True

        self._logger.log("Could not find all %s resources on %s. %s" % (managed_str, node, managedList))
        return False

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")
        verify_managed = False
        verify_unmanaged = False
        failPat = ""

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        # get a list of all the managed resources. We use this list
        # after enabling maintenance mode to verify all managed resources
        # become un-managed.  After maintenance mode is turned off, we use
        # this list to verify all the resources become managed again.
        managedResources = self.managedRscList(node)
        if len(managedResources) == 0:
            self._logger.log("No managed resources on %s" % node)
            return self.skipped()

        # insert a fake resource we can fail during maintenance mode
        # so we can verify recovery does not take place until after maintenance
        # mode is disabled.
        failPat = failPat + self.insertMaintenanceDummy(node)

        # toggle maintenance mode ON, then fail dummy resource.
        failPat = failPat + self.toggleMaintenanceMode(node, "On")

        # verify all the resources are now unmanaged
        if self.verifyResources(node, managedResources, False):
            verify_unmanaged = True

        # Toggle maintenance mode  OFF, verify dummy is recovered.
        failPat = failPat + self.toggleMaintenanceMode(node, "Off")

        # verify all the resources are now managed again
        if self.verifyResources(node, managedResources, True):
            verify_managed = True

        # Remove our maintenance dummy resource.
        failPat = failPat + self.removeMaintenanceDummy(node)

        self._cm.cluster_stable()

        if failPat != "":
            return self.failure("Unmatched patterns: %s" % (failPat))
        elif verify_unmanaged is False:
            return self.failure("Failed to verify resources became unmanaged during maintenance mode")
        elif verify_managed is False:
            return self.failure("Failed to verify resources switched back to managed after disabling maintenance mode")

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for %s" % self.rid,
                 r"schedulerd.*: Recover\s+%s\s+\(.*\)" % self.rid,
                 r"Unknown operation: fail",
                 self.templates["Pat:RscOpOK"] % (self.action, self.rid),
                 r"(ERROR|error).*: Action %s_%s_%d .* initiated outside of a transition" % (self.rid, self.action, self.interval) ]
