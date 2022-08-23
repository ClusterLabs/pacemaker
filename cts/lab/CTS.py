""" Main classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2000-2021 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys
import time
import traceback

from cts.logging     import LogFactory
from cts.remote      import RemoteFactory
from cts.environment import EnvFactory

class CtsLab(object):
    '''This class defines the Lab Environment for the Cluster Test System.
    It defines those things which are expected to change from test
    environment to test environment for the same cluster manager.

    It is where you define the set of nodes that are in your test lab
    what kind of reset mechanism you use, etc.

    At this point in time, it is the intent of this class to model static
    configuration and/or environmental data about the environment which
    doesn't change as the tests proceed.

    Well-known names (keys) are an important concept in this class.
    The HasMinimalKeys member function knows the minimal set of
    well-known names for the class.

    The following names are standard (well-known) at this time:

        nodes           An array of the nodes in the cluster
        reset           A ResetMechanism object
        logger          An array of objects that log strings...
        CMclass         The type of ClusterManager we are running
                        (This is a class object, not a class instance)
        RandSeed        Random seed.  It is a triple of bytes. (optional)

    The CTS code ignores names it doesn't know about/need.
    The individual tests have access to this information, and it is
    perfectly acceptable to provide hints, tweaks, fine-tuning
    directions or other information to the tests through this mechanism.
    '''

    def __init__(self, args=None):
        self.Env = EnvFactory().getInstance(args)
        self.Scenario = None
        self.logger = LogFactory()
        self.rsh = RemoteFactory().getInstance()

    def dump(self):
        self.Env.dump()

    def has_key(self, key):
        return key in list(self.Env.keys())

    def __getitem__(self, key):
        return self.Env[key]

    def __setitem__(self, key, value):
        self.Env[key] = value

    def run(self, Scenario, Iterations):
        if not Scenario:
            self.logger.log("No scenario was defined")
            return 1

        self.logger.log("Cluster nodes: ")
        for node in self.Env["nodes"]:
            self.logger.log("    * %s" % (node))

        if not Scenario.SetUp():
            return 1

        try :
            Scenario.run(Iterations)
        except :
            self.logger.log("Exception by %s" % sys.exc_info()[0])
            self.logger.traceback(traceback)

            Scenario.summarize()
            Scenario.TearDown()
            return 1

        #ClusterManager.oprofileSave(Iterations)
        Scenario.TearDown()

        Scenario.summarize()
        if Scenario.Stats["failure"] > 0:
            return Scenario.Stats["failure"]

        elif Scenario.Stats["success"] != Iterations:
            self.logger.log("No failure count but success != requested iterations")
            return 1

        return 0

    def __CheckNode(self, node):
        "Raise a ValueError if the given node isn't valid"

        if not self.IsValidNode(node):
            raise ValueError("Invalid node [%s] in CheckNode" % node)

class NodeStatus(object):
    def __init__(self, env):
        self.Env = env

    def IsNodeBooted(self, node):
        '''Return TRUE if the given node is booted (responds to pings)'''
        return RemoteFactory().getInstance()("localhost", "ping -nq -c1 -w1 %s" % node, silent=True) == 0

    def IsSshdUp(self, node):
        rc = RemoteFactory().getInstance()(node, "true", silent=True)
        return rc == 0

    def WaitForNodeToComeUp(self, node, Timeout=300):
        '''Return TRUE when given node comes up, or None/FALSE if timeout'''
        timeout = Timeout
        anytimeouts = 0
        while timeout > 0:
            if self.IsNodeBooted(node) and self.IsSshdUp(node):
                if anytimeouts:
                     # Fudge to wait for the system to finish coming up
                     time.sleep(30)
                     LogFactory().debug("Node %s now up" % node)
                return 1

            time.sleep(30)
            if (not anytimeouts):
                LogFactory().debug("Waiting for node %s to come up" % node)

            anytimeouts = 1
            timeout = timeout - 1

        LogFactory().log("%s did not come up within %d tries" % (node, Timeout))
        if self.Env["continue"] == 1:
            answer = "Y"
        else:
            try:
                answer = input('Continue? [nY]')
            except EOFError as e:
                answer = "n"
        if answer and answer == "n":
            raise ValueError("%s did not come up within %d tries" % (node, Timeout))

    def WaitForAllNodesToComeUp(self, nodes, timeout=300):
        '''Return TRUE when all nodes come up, or FALSE if timeout'''

        for node in nodes:
            if not self.WaitForNodeToComeUp(node, timeout):
                return None
        return 1


class Component(object):
    def kill(self, node):
        None


class Process(Component):
    def __init__(self, cm, name, process=None, dc_only=0, pats=[], dc_pats=[], badnews_ignore=[], common_ignore=[], triggersreboot=0):
        self.name = str(name)
        self.dc_only = dc_only
        self.pats = pats
        self.dc_pats = dc_pats
        self.CM = cm
        self.badnews_ignore = badnews_ignore
        self.badnews_ignore.extend(common_ignore)
        self.triggersreboot = triggersreboot

        if process:
            self.proc = str(process)
        else:
            self.proc = str(name)
        self.KillCmd = "killall -9 " + self.proc

    def kill(self, node):
        if self.CM.rsh(node, self.KillCmd) != 0:
            self.CM.log ("ERROR: Kill %s failed on node %s" % (self.name,node))
            return None
        return 1
