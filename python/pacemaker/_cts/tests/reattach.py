""" Restart the cluster and verify resources remain running """

__all__ = ["Reattach"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import time

from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.restarttest import RestartTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.starttest import StartTest


class Reattach(CTSTest):
    """ A concrete test that restarts the cluster and verifies that resources
        remain running throughout
    """

    def __init__(self, cm):
        """ Create a new Reattach instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.is_unsafe = False
        self.name = "Reattach"
        self.restart1 = RestartTest(cm)
        self.stopall = SimulStopLite(cm)

        self._startall = SimulStartLite(cm)

    def _is_managed(self, node):
        """ Are resources managed by the cluster? """

        (_, is_managed) = self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -q -G -d true", verbose=1)
        is_managed = is_managed[0].strip()
        return is_managed == "true"

    def _set_unmanaged(self, node):
        """ Disable resource management """

        self.debug("Disable resource management")
        self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -v false")

    def _set_managed(self, node):
        """ Enable resource management """

        self.debug("Re-enable resource management")
        self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -D")

    def setup(self, node):
        """ Setup this test """

        attempt = 0
        if not self._startall(None):
            return None

        # Make sure we are really _really_ stable and that all
        # resources, including those that depend on transient node
        # attributes, are started
        while not self._cm.cluster_stable(double_check=True):
            if attempt < 5:
                attempt += 1
                self.debug("Not stable yet, re-testing")
            else:
                self._logger.log("Cluster is not stable")
                return None

        return 1

    def teardown(self, node):
        """ Tear down this test """

        # Make sure 'node' is up
        start = StartTest(self._cm)
        start(node)

        if not self._is_managed(node):
            self._logger.log("Attempting to re-enable resource management on %s" % node)
            self._set_managed(node)
            self._cm.cluster_stable()

            if not self._is_managed(node):
                self._logger.log("Could not re-enable resource management")
                return 0

        return 1

    def can_run_now(self, node):
        """ Return True if we can meaningfully run right now """

        if self._find_ocfs2_resources(node):
            self._logger.log("Detach/Reattach scenarios are not possible with OCFS2 services present")
            return False

        return True

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")

        pats = []

        # Conveniently, the scheduler will display this message when disabling
        # management, even if fencing is not enabled, so we can rely on it.
        managed = self.create_watch(["No fencing will be done"], 60)
        managed.set_watch()

        self._set_unmanaged(node)

        if not managed.look_for_all():
            self._logger.log("Patterns not found: " + repr(managed.unmatched))
            return self.failure("Resource management not disabled")

        pats = []
        pats.append(self.templates["Pat:RscOpOK"] % ("start", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("stop", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("promote", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("demote", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("migrate", ".*"))

        watch = self.create_watch(pats, 60, "ShutdownActivity")
        watch.set_watch()

        self.debug("Shutting down the cluster")
        ret = self.stopall(None)
        if not ret:
            self._set_managed(node)
            return self.failure("Couldn't shut down the cluster")

        self.debug("Bringing the cluster back up")
        ret = self._startall(None)
        time.sleep(5) # allow ping to update the CIB
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
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self._cm, line)

                if r.rclass == "stonith":
                    self.debug("Ignoring start actions for %s" % r.id)
                    ignore.append(self.templates["Pat:RscOpOK"] % ("start", r.id))

        if self.local_badnews("ResourceActivity:", watch, ignore):
            return self.failure("Resources stopped or started after resource management was re-enabled")

        return ret

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"resource( was|s were) active at shutdown" ]

    def is_applicable(self):
        return True
