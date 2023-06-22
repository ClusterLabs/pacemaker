""" Main classes for Pacemaker's Cluster Test Suite (CTS) """

__all__ = ["CtsLab", "NodeStatus", "Process"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys
import time
import traceback

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.input import should_continue
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteFactory

class CtsLab:
    """ A class that defines the Lab Environment for the Cluster Test System.
        It defines those things which are expected to change from test
        environment to test environment for the same cluster manager.

        This is where you define the set of nodes that are in your test lab,
        what kind of reset mechanism you use, etc.  All this data is stored
        as key/value pairs in an Environment instance constructed from arguments
        passed to this class.

        The CTS code ignores names it doesn't know about or need.  Individual
        tests have access to this information, and it is perfectly acceptable
        to provide hints, tweaks, fine-tuning directions, or other information
        to the tests through this mechanism.
    """

    def __init__(self, args=None):
        """ Create a new CtsLab instance.  This class can be treated kind
            of like a dictionary due to the presence of typical dict functions
            like __contains__, __getitem__, and __setitem__.  However, it is not a
            dictionary so do not rely on standard dictionary behavior.

            Arguments:

            args -- A list of command line parameters, minus the program name.
        """

        self._env = EnvFactory().getInstance(args)
        self._logger = LogFactory()

    def dump(self):
        """ Print the current environment """

        self._env.dump()

    def __contains__(self, key):
        """ Does the given environment key exist? """

        # pylint gets confused because of EnvFactory here.
        # pylint: disable=unsupported-membership-test
        return key in self._env

    def __getitem__(self, key):
        """ Return the given environment key, or raise KeyError if it does
            not exist
        """

        # Throughout this file, pylint has trouble understanding that EnvFactory
        # and RemoteFactory are singleton instances that can be treated as callable
        # and subscriptable objects.  Various warnings are disabled because of this.
        # See also a comment about self._rsh in environment.py.
        # pylint: disable=unsubscriptable-object
        return self._env[key]

    def __setitem__(self, key, value):
        """ Set the given environment key to the given value, overriding any
            previous value
        """

        # pylint: disable=unsupported-assignment-operation
        self._env[key] = value

    def run(self, scenario, iterations):
        """ Run the given scenario the given number of times.

            Returns:

            ExitStatus.OK on success, or ExitStatus.ERROR on error
        """

        if not scenario:
            self._logger.log("No scenario was defined")
            return ExitStatus.ERROR

        self._logger.log("Cluster nodes: ")
        # pylint: disable=unsubscriptable-object
        for node in self._env["nodes"]:
            self._logger.log("    * %s" % (node))

        if not scenario.setup():
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
    """ A class for querying the status of cluster nodes - are nodes up?  Do
        they respond to SSH connections?
    """

    def __init__(self, env):
        """ Create a new NodeStatus instance

            Arguments:

            env -- An Environment instance
        """
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
        if not should_continue(self._env["continue"]):
            raise ValueError("%s did not come up within %d tries" % (node, initial_timeout))

        return False

    def wait_for_all_nodes(self, nodes, timeout=300):
        """ Return True when all nodes come up, or False if the timeout is reached """

        for node in nodes:
            if not self.wait_for_node(node, timeout):
                return False

        return True


class Process:
    """ A class for managing a Pacemaker daemon """

    # pylint: disable=invalid-name
    def __init__(self, cm, name, dc_only=False, pats=None, dc_pats=None,
                 badnews_ignore=None):
        """ Create a new Process instance.

            Arguments:

            cm              -- A ClusterManager instance
            name            -- The command being run
            dc_only         -- Should this daemon be killed only on the DC?
            pats            -- Regexes we expect to find in log files
            dc_pats         -- Additional DC-specific regexes we expect to find
                               in log files
            badnews_ignore  -- Regexes for lines in the log that can be ignored
        """

        self._cm = cm
        self.badnews_ignore = badnews_ignore
        self.dc_only = dc_only
        self.dc_pats = dc_pats
        self.name = name
        self.pats = pats

        if self.badnews_ignore is None:
            self.badnews_ignore = []

        if self.dc_pats is None:
            self.dc_pats = []

        if self.pats is None:
            self.pats = []

    def kill(self, node):
        """ Kill the instance of this process running on the given node """

        (rc, _) = self._cm.rsh(node, "killall -9 %s" % self.name)

        if rc != 0:
            self._cm.log ("ERROR: Kill %s failed on node %s" % (self.name, node))
