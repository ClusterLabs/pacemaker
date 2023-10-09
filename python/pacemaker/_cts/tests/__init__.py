"""
Test classes for the `pacemaker._cts` package.
"""

__copyright__ = "Copyright 2023 the Pacemaker project contributors"
__license__ = "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)"

from pacemaker._cts.tests.componentfail import ComponentFail
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.fliptest import FlipTest
from pacemaker._cts.tests.maintenancemode import MaintenanceMode
from pacemaker._cts.tests.nearquorumpointtest import NearQuorumPointTest
from pacemaker._cts.tests.partialstart import PartialStart
from pacemaker._cts.tests.reattach import Reattach
from pacemaker._cts.tests.restartonebyone import RestartOnebyOne
from pacemaker._cts.tests.resourcerecover import ResourceRecover
from pacemaker._cts.tests.restarttest import RestartTest
from pacemaker._cts.tests.resynccib import ResyncCIB
from pacemaker._cts.tests.remotebasic import RemoteBasic
from pacemaker._cts.tests.remotedriver import RemoteDriver
from pacemaker._cts.tests.remotemigrate import RemoteMigrate
from pacemaker._cts.tests.remoterscfailure import RemoteRscFailure
from pacemaker._cts.tests.remotestonithd import RemoteStonithd
from pacemaker._cts.tests.simulstart import SimulStart
from pacemaker._cts.tests.simulstop import SimulStop
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.splitbraintest import SplitBrainTest
from pacemaker._cts.tests.standbytest import StandbyTest
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.startonebyone import StartOnebyOne
from pacemaker._cts.tests.stonithdtest import StonithdTest
from pacemaker._cts.tests.stoponebyone import StopOnebyOne
from pacemaker._cts.tests.stoptest import StopTest

def test_list(cm, audits):
    """ Return a list of test class objects that are enabled and whose
        is_applicable methods return True.  These are the tests that
        should be run.
    """

    # cm is a reasonable name here.
    # pylint: disable=invalid-name

    # A list of all enabled test classes, in the order that they should
    # be run (if we're doing --once).  There are various other ways of
    # specifying which tests should be run, in which case the order here
    # will not matter.
    #
    # Note that just because a test is listed here doesn't mean it will
    # definitely be run - is_applicable is still taken into consideration.
    # Also note that there are other tests that are excluded from this
    # list for various reasons.
    enabled_test_classes = [ FlipTest,
                             RestartTest,
                             StonithdTest,
                             StartOnebyOne,
                             SimulStart,
                             SimulStop,
                             StopOnebyOne,
                             RestartOnebyOne,
                             PartialStart,
                             StandbyTest,
                             MaintenanceMode,
                             ResourceRecover,
                             ComponentFail,
                             SplitBrainTest,
                             Reattach,
                             ResyncCIB,
                             NearQuorumPointTest,
                             RemoteBasic,
                             RemoteStonithd,
                             RemoteMigrate,
                             RemoteRscFailure,
                           ]

    result = []

    for testclass in enabled_test_classes:
        bound_test = testclass(cm)

        if bound_test.is_applicable():
            bound_test.audits = audits
            result.append(bound_test)

    return result
