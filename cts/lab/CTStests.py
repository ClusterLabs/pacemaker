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
AllTestClasses.append(RemoteRscFailure)


def TestList(cm, audits):
    result = []
    for testclass in AllTestClasses:
        bound_test = testclass(cm)
        if bound_test.is_applicable():
            bound_test.audits = audits
            result.append(bound_test)
    return result

# vim:ts=4:sw=4:et:
