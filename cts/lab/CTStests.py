""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

#
#        SPECIAL NOTE:
#
#        Tests may NOT implement any cluster-manager-specific code in them.
#        EXTEND the ClusterManager object to provide the base capabilities
#        the test needs if you need to do something that the current CM classes
#        do not.  Otherwise you screw up the whole point of the object structure
#        in CTS.
#
#                Thank you.
#

import re
import time

from stat import *

from pacemaker import BuildOptions
from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests import *
from pacemaker._cts.timer import Timer

AllTestClasses = [ ]
AllTestClasses.append(FlipTest)
AllTestClasses.append(RestartTest)
AllTestClasses.append(StonithdTest)
AllTestClasses.append(StartOnebyOne)
AllTestClasses.append(SimulStart)
AllTestClasses.append(SimulStop)
AllTestClasses.append(StopOnebyOne)
AllTestClasses.append(RestartOnebyOne)
AllTestClasses.append(PartialStart)
AllTestClasses.append(StandbyTest)
AllTestClasses.append(MaintenanceMode)
AllTestClasses.append(ResourceRecover)
AllTestClasses.append(ComponentFail)
AllTestClasses.append(SplitBrainTest)
AllTestClasses.append(Reattach)
AllTestClasses.append(ResyncCIB)
AllTestClasses.append(NearQuorumPointTest)
AllTestClasses.append(RemoteBasic)
AllTestClasses.append(RemoteStonithd)
AllTestClasses.append(RemoteMigrate)


def TestList(cm, audits):
    result = []
    for testclass in AllTestClasses:
        bound_test = testclass(cm)
        if bound_test.is_applicable():
            bound_test.audits = audits
            result.append(bound_test)
    return result


class RemoteRscFailure(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteRscFailure"

    def __call__(self, node):
        '''Perform the 'RemoteRscFailure' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        # This is an important step. We are migrating the connection
        # before failing the resource. This verifies that the migration
        # has properly maintained control over the remote-node.
        self.migrate_connection(node)

        self.fail_rsc(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"schedulerd.*: Recover\s+remote-rsc\s+\(.*\)",
                 r"Dummy.*: No process state file found" ] + super().errors_to_ignore

    def is_applicable(self):
        if not RemoteDriver.is_applicable(self):
            return 0
        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        if len(self._env["nodes"]) < 3:
            return 0
        return 1

AllTestClasses.append(RemoteRscFailure)

# vim:ts=4:sw=4:et:
