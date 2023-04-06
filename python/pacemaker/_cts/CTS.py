""" Main classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["CtsLab", "NodeStatus", "Process"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys
import time
import traceback

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteFactory

class CtsLab:
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
        self._env = EnvFactory().getInstance(args)
        self._logger = LogFactory()

    def dump(self):
        self._env.dump()

    def has_key(self, key):
        return key in list(self._env.keys())

    def __getitem__(self, key):
        # Throughout this file, pylint has trouble understanding that EnvFactory
        # and RemoteFactory are singleton instances that can be treated as callable
        # and subscriptable objects.  Various warnings are disabled because of this.
        # See also a comment about self._rsh in environment.py.
        # pylint: disable=unsubscriptable-object
        return self._env[key]

    def __setitem__(self, key, value):
        # pylint: disable=unsupported-assignment-operation
        self._env[key] = value

    def run(self, scenario, iterations):
        if not scenario:
            self._logger.log("No scenario was defined")
            return ExitStatus.ERROR

        self._logger.log("Cluster nodes: ")
        # pylint: disable=unsubscriptable-object
        for node in self._env["nodes"]:
            self._logger.log("    * %s" % (node))

        if not scenario.SetUp():
            return ExitStatus.ERROR

        # We want to alert on any exceptions caused by running a scenario, so
        # here it's okay to disable the pylint warning.
        # pylint: disable=bare-except
        try:
            scenario.run(iterations)
        except:
            self._logger.log("Exception by %s" % sys.exc_info()[0])
            self._logger.traceback(traceback)

            scenario.summarize()
            scenario.TearDown()
            return ExitStatus.ERROR

        scenario.TearDown()
        scenario.summarize()

        if scenario.Stats["failure"] > 0:
            return ExitStatus.ERROR

        if scenario.Stats["success"] != iterations:
            self._logger.log("No failure count but success != requested iterations")
            return ExitStatus.ERROR

        return ExitStatus.OK


class NodeStatus:
    def __init__(self, env):
        self._env = env

    def _node_booted(self, node):
        """ Return True if the given node is booted (responds to pings) """

        # pylint: disable=not-callable
        (rc, _) = RemoteFactory().getInstance()("localhost", "ping -nq -c1 -w1 %s" % node, verbose=0)
        return rc == 0

    def _sshd_up(self, node):
        """ Return true if sshd responds on the given node """

        # pylint: disable=not-callable
        (rc, _) = RemoteFactory().getInstance()(node, "true", verbose=0)
        return rc == 0

    def wait_for_node(self, node, timeout=300):
        """ Wait for a node to become available.  Should the timeout be reached,
            the user will be given a choice whether to continue or not.  If not,
            ValueError will be raised.

            Returns:

            True when the node is available, or False if the timeout is reached.
        """

        initial_timeout = timeout
        anytimeouts = False

        while timeout > 0:
            if self._node_booted(node) and self._sshd_up(node):
                if anytimeouts:
                    # Fudge to wait for the system to finish coming up
                    time.sleep(30)
                    LogFactory().debug("Node %s now up" % node)

                return True

            time.sleep(30)
            if not anytimeouts:
                LogFactory().debug("Waiting for node %s to come up" % node)

            anytimeouts = True
            timeout -= 1

        LogFactory().log("%s did not come up within %d tries" % (node, initial_timeout))
        if self._env["continue"]:
            answer = "Y"
        else:
            try:
                answer = input('Continue? [nY]')
            except EOFError:
                answer = "n"

        if answer and answer == "n":
            raise ValueError("%s did not come up within %d tries" % (node, initial_timeout))

        return False

    def wait_for_all_nodes(self, nodes, timeout=300):
        """ Return True when all nodes come up, or False if the timeout is reached """

        for node in nodes:
            if not self.wait_for_node(node, timeout):
                return False

        return True


class Process:
    # pylint: disable=invalid-name
    def __init__(self, cm, name, dc_only=False, pats=None, dc_pats=None,
                 badnews_ignore=None, common_ignore=None):
        self._cm = cm
        self.badnews_ignore = badnews_ignore
        self.dc_only = dc_only
        self.dc_pats = dc_pats
        self.name = name
        self.pats = pats

        if self.badnews_ignore is None:
            self.badnews_ignore = []

        if common_ignore:
            self.badnews_ignore.extend(common_ignore)

        if self.dc_pats is None:
            self.dc_pats = []

        if self.pats is None:
            self.pats = []

    def kill(self, node):
        (rc, _) = self._cm.rsh(node, "killall -9 %s" % self.name)

        if rc != 0:
            self._cm.log ("ERROR: Kill %s failed on node %s" % (self.name, node))
