""" ClusterManager class for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["ClusterManager"]
__copyright__ = """Copyright 2000-2023 the Pacemaker project contributors.
Certain portions by Huang Zhen <zhenhltc@cn.ibm.com> are copyright 2004
International Business Machines. The version control history for this file
may have further details."""
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import os
import re
import time

from collections import UserDict

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.CTS import NodeStatus, Process
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.cib import ConfigFactory
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.patterns import PatternSelector
from pacemaker._cts.remote import RemoteFactory
from pacemaker._cts.watcher import LogWatcher

# Throughout this file, pylint has trouble understanding that EnvFactory
# and RemoteFactory are singleton instances that can be treated as callable
# and subscriptable objects.  Various warnings are disabled because of this.
# See also a comment about self._rsh in environment.py.
# pylint: disable=unsubscriptable-object

# pylint doesn't understand that self._rsh is callable (it stores the
# singleton instance of RemoteExec, as returned by the getInstance method
# of RemoteFactory).  It's possible we could fix this with type annotations,
# but those were introduced with python 3.5 and we only support python 3.4.
# I think we could also fix this by getting rid of the getInstance methods,
# but that's a project for another day.  For now, just disable the warning.
# pylint: disable=not-callable

# ClusterManager has a lot of methods.
# pylint: disable=too-many-public-methods

class ClusterManager(UserDict):
    '''The Cluster Manager class.
    This is an subclass of the Python dictionary class.
    (this is because it contains lots of {name,value} pairs,
    not because it's behavior is that terribly similar to a
    dictionary in other ways.)

    This is an abstract class which class implements high-level
    operations on the cluster and/or its cluster managers.
    Actual cluster managers classes are subclassed from this type.

    One of the things we do is track the state we think every node should
    be in.
    '''

    def _finalConditions(self):
        for key in list(self.keys()):
            if self[key] is None:
                raise ValueError("Improper derivation: self[%s] must be overridden by subclass." % key)

    def __init__(self):
        # Eventually, ClusterManager should not be a UserDict subclass.  Until
        # that point...
        # pylint: disable=super-init-not-called
        self.Env = EnvFactory().getInstance()
        self.templates = PatternSelector(self.Env["Name"])
        self.logger = LogFactory()
        self.data = {}
        self.name = self.Env["Name"]

        self.rsh = RemoteFactory().getInstance()
        self.ShouldBeStatus={}
        # pylint: disable=invalid-name
        self.ns = NodeStatus(self.Env)
        self.OurNode = os.uname()[1].lower()
        self.__instance_errors_to_ignore = []

        self.cib_installed = 0

        self._finalConditions()

        self.CIBsync = {}
        self.CibFactory = ConfigFactory(self)
        self.cib = self.CibFactory.create_config(self.Env["Schema"])

    def __getitem__(self, key):
        if key == "Name":
            return self.name

        print("FIXME: Getting %s from %r" % (key, self))
        if key in self.data:
            return self.data[key]

        return self.templates.get_patterns(key)

    def __setitem__(self, key, value):
        print("FIXME: Setting %s=%s on %r" % (key, value, self))
        self.data[key] = value

    def key_for_node(self, node):
        return node

    def clear_instance_errors_to_ignore(self):
        """ Reset instance-specific errors to ignore on each iteration """

        self.__instance_errors_to_ignore = []

    @property
    def instance_errors_to_ignore(self):
        """ Return a list of known errors that should be ignored for a specific
            test instance
        """

        return self.__instance_errors_to_ignore

    @property
    def errors_to_ignore(self):
        """ Return a list of known error messages that should be ignored """

        return self.templates.get_patterns("BadNewsIgnore")

    def log(self, args):
        self.logger.log(args)

    def debug(self, args):
        self.logger.debug(args)

    def upcount(self):
        '''How many nodes are up?'''
        count = 0
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                count = count + 1
        return count

    def install_support(self, command="install"):
        for node in self.Env["nodes"]:
            self.rsh(node, "%s/cts-support %s" % (BuildOptions.DAEMON_DIR, command))

    def prepare_fencing_watcher(self):
        # If we don't have quorum now but get it as a result of starting this node,
        # then a bunch of nodes might get fenced
        if self.has_quorum(None):
            self.debug("Have quorum")
            return None

        if not self.templates["Pat:Fencing_start"]:
            print("No start pattern")
            return None

        if not self.templates["Pat:Fencing_ok"]:
            print("No ok pattern")
            return None

        stonith = None
        stonithPats = []
        for peer in self.Env["nodes"]:
            if self.ShouldBeStatus[peer] == "up":
                continue

            stonithPats.extend([ self.templates["Pat:Fencing_ok"] % peer,
                                 self.templates["Pat:Fencing_start"] % peer ])

        stonith = LogWatcher(self.Env["LogFileName"], stonithPats, self.Env["nodes"], self.Env["LogWatcher"], "StartupFencing", 0)
        stonith.set_watch()
        return stonith

    def fencing_cleanup(self, node, stonith):
        peer_list = []
        peer_state = {}

        self.debug("Looking for nodes that were fenced as a result of %s starting" % node)

        # If we just started a node, we may now have quorum (and permission to fence)
        if not stonith:
            self.debug("Nothing to do")
            return peer_list

        q = self.has_quorum(None)
        if not q and len(self.Env["nodes"]) > 2:
            # We didn't gain quorum - we shouldn't have shot anyone
            self.debug("Quorum: %s Len: %d" % (q, len(self.Env["nodes"])))
            return peer_list

        for n in self.Env["nodes"]:
            peer_state[n] = "unknown"

        # Now see if any states need to be updated
        self.debug("looking for: %r" % stonith.regexes)
        shot = stonith.look(0)
        while shot:
            self.debug("Found: %r" % shot)
            del stonith.regexes[stonith.whichmatch]

            # Extract node name
            for n in self.Env["nodes"]:
                if re.search(self.templates["Pat:Fencing_ok"] % n, shot):
                    peer = n
                    peer_state[peer] = "complete"
                    self.__instance_errors_to_ignore.append(self.templates["Pat:Fencing_ok"] % peer)

                elif peer_state[n] != "complete" and re.search(self.templates["Pat:Fencing_start"] % n, shot):
                    # TODO: Correctly detect multiple fencing operations for the same host
                    peer = n
                    peer_state[peer] = "in-progress"
                    self.__instance_errors_to_ignore.append(self.templates["Pat:Fencing_start"] % peer)

            if not peer:
                self.logger.log("ERROR: Unknown stonith match: %r" % shot)

            elif not peer in peer_list:
                self.debug("Found peer: %s" % peer)
                peer_list.append(peer)

            # Get the next one
            shot = stonith.look(60)

        for peer in peer_list:

            self.debug("   Peer %s was fenced as a result of %s starting: %s" % (peer, node, peer_state[peer]))
            if self.Env["at-boot"]:
                self.ShouldBeStatus[peer] = "up"
            else:
                self.ShouldBeStatus[peer] = "down"

            if peer_state[peer] == "in-progress":
                # Wait for any in-progress operations to complete
                shot = stonith.look(60)
                while stonith.regexes and shot:
                    self.debug("Found: %r" % shot)
                    del stonith.regexes[stonith.whichmatch]
                    shot = stonith.look(60)

            # Now make sure the node is alive too
            self.ns.wait_for_node(peer, self.Env["DeadTime"])

            # Poll until it comes up
            if self.Env["at-boot"]:
                if not self.stat_cm(peer):
                    time.sleep(self.Env["StartTime"])

                if not self.stat_cm(peer):
                    self.logger.log("ERROR: Peer %s failed to restart after being fenced" % peer)
                    return None

        return peer_list

    def start_cm(self, node, verbose=False):
        """ Start up the cluster manager on a given node """

        if verbose:
            self.logger.log("Starting %s on node %s" % (self.templates["Name"], node))
        else:
            self.debug("Starting %s on node %s" % (self.templates["Name"], node))

        if not node in self.ShouldBeStatus:
            self.ShouldBeStatus[node] = "down"

        if self.ShouldBeStatus[node] != "down":
            return True

        # Technically we should always be able to notice ourselves starting
        patterns = [ self.templates["Pat:Local_started"] % node ]
        if self.upcount() == 0:
            patterns.append(self.templates["Pat:DC_started"] % node)
        else:
            patterns.append(self.templates["Pat:NonDC_started"] % node)

        watch = LogWatcher(
            self.Env["LogFileName"], patterns, self.Env["nodes"], self.Env["LogWatcher"], "StartaCM", self.Env["StartTime"]+10)

        self.install_config(node)

        self.ShouldBeStatus[node] = "any"
        if self.stat_cm(node) and self.cluster_stable(self.Env["DeadTime"]):
            self.logger.log ("%s was already started" % node)
            return True

        stonith = self.prepare_fencing_watcher()
        watch.set_watch()

        (rc, _) = self.rsh(node, self.templates["StartCmd"])
        if rc != 0:
            self.logger.log ("Warn: Start command failed on node %s" % node)
            self.fencing_cleanup(node, stonith)
            return False

        self.ShouldBeStatus[node] = "up"
        watch_result = watch.look_for_all()

        if watch.unmatched:
            for regex in watch.unmatched:
                self.logger.log ("Warn: Startup pattern not found: %s" % regex)

        if watch_result and self.cluster_stable(self.Env["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return True

        if self.stat_cm(node) and self.cluster_stable(self.Env["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return True

        self.logger.log ("Warn: Start failed for node %s" % node)
        return False

    def start_cm_async(self, node, verbose=False):
        """ Start up the cluster manager on a given node without blocking """

        if verbose:
            self.logger.log("Starting %s on node %s" % (self["Name"], node))
        else:
            self.debug("Starting %s on node %s" % (self["Name"], node))

        self.install_config(node)
        self.rsh(node, self.templates["StartCmd"], synchronous=False)
        self.ShouldBeStatus[node] = "up"

    def StopaCM(self, node, verbose=False, force=False):

        '''Stop the cluster manager on a given node'''

        if verbose:
            self.logger.log("Stopping %s on node %s" % (self["Name"], node))
        else:
            self.debug("Stopping %s on node %s" % (self["Name"], node))

        if self.ShouldBeStatus[node] != "up" and not force:
            return 1

        (rc, _) = self.rsh(node, self.templates["StopCmd"])
        if rc == 0:
            # Make sure we can continue even if corosync leaks
            self.ShouldBeStatus[node] = "down"
            self.cluster_stable(self.Env["DeadTime"])
            return 1

        self.logger.log ("ERROR: Could not stop %s on node %s" % (self["Name"], node))
        return None

    def StopaCMnoBlock(self, node):

        '''Stop the cluster manager on a given node with none-block mode'''

        self.debug("Stopping %s on node %s" % (self["Name"], node))

        self.rsh(node, self.templates["StopCmd"], synchronous=False)
        self.ShouldBeStatus[node] = "down"
        return 1

    def startall(self, nodelist=None, verbose=False, quick=False):

        '''Start the cluster manager on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''
        if not nodelist:
            nodelist = self.Env["nodes"]

        for node in nodelist:
            if self.ShouldBeStatus[node] == "down":
                self.ns.wait_for_all_nodes(nodelist, 300)

        if not quick:
            # This is used for "basic sanity checks", so only start one node ...
            return self.start_cm(nodelist[0], verbose=verbose)

        # Approximation of SimulStartList for --boot
        watchpats = [ self.templates["Pat:DC_IDLE"] ]
        for node in nodelist:
            watchpats.extend([ self.templates["Pat:InfraUp"] % node,
                               self.templates["Pat:PacemakerUp"] % node,
                               self.templates["Pat:Local_started"] % node,
                               self.templates["Pat:They_up"] % (nodelist[0], node) ])

        #   Start all the nodes - at about the same time...
        watch = LogWatcher(self.Env["LogFileName"], watchpats, self.Env["nodes"], self.Env["LogWatcher"], "fast-start", self.Env["DeadTime"]+10)
        watch.set_watch()

        if not self.start_cm(nodelist[0], verbose=verbose):
            return 0
        for node in nodelist:
            self.start_cm_async(node, verbose=verbose)

        watch.look_for_all()
        if watch.unmatched:
            for regex in watch.unmatched:
                self.logger.log ("Warn: Startup pattern not found: %s" % regex)

        if not self.cluster_stable():
            self.logger.log("Cluster did not stabilize")
            return 0

        return 1

    def stopall(self, nodelist=None, verbose=False, force=False):

        '''Stop the cluster managers on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        ret = 1
        if not nodelist:
            nodelist = self.Env["nodes"]
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up" or force:
                if not self.StopaCM(node, verbose=verbose, force=force):
                    ret = 0
        return ret

    def statall(self, nodelist=None):

        '''Return the status of the cluster managers in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        result = {}
        if not nodelist:
            nodelist = self.Env["nodes"]
        for node in nodelist:
            if self.stat_cm(node):
                result[node] = "up"
            else:
                result[node] = "down"
        return result

    def isolate_node(self, target, nodes=None):
        '''isolate the communication between the nodes'''
        if not nodes:
            nodes = self.Env["nodes"]

        for node in nodes:
            if node == target:
                continue

            (rc, _) = self.rsh(target, self.templates["BreakCommCmd"] % self.key_for_node(node))
            if rc != 0:
                self.logger.log("Could not break the communication between %s and %s: %d" % (target, node, rc))
                return None

            self.debug("Communication cut between %s and %s" % (target, node))

        return 1

    def unisolate_node(self, target, nodes=None):
        '''fix the communication between the nodes'''
        if not nodes:
            nodes = self.Env["nodes"]

        for node in nodes:
            if node == target:
                continue

            # Limit the amount of time we have asynchronous connectivity for
            # Restore both sides as simultaneously as possible
            self.rsh(target, self.templates["FixCommCmd"] % self.key_for_node(node), synchronous=False)
            self.rsh(node, self.templates["FixCommCmd"] % self.key_for_node(target), synchronous=False)
            self.debug("Communication restored between %s and %s" % (target, node))

    def oprofileStart(self, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileStart(n)

        elif node in self.Env["oprofile"]:
            self.debug("Enabling oprofile on %s" % node)
            self.rsh(node, "opcontrol --init")
            self.rsh(node, "opcontrol --setup --no-vmlinux --separate=lib --callgraph=20 --image=all")
            self.rsh(node, "opcontrol --start")
            self.rsh(node, "opcontrol --reset")

    def oprofileSave(self, test, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileSave(test, n)

        elif node in self.Env["oprofile"]:
            self.rsh(node, "opcontrol --dump")
            self.rsh(node, "opcontrol --save=cts.%d" % test)
            # Read back with: opreport -l session:cts.0 image:<directory>/c*
            self.oprofileStop(node)
            self.oprofileStart(node)

    def oprofileStop(self, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileStop(n)

        elif node in self.Env["oprofile"]:
            self.debug("Stopping oprofile on %s" % node)
            self.rsh(node, "opcontrol --reset")
            self.rsh(node, "opcontrol --shutdown 2>&1 > /dev/null")

    def install_config(self, node):
        if not self.ns.wait_for_node(node):
            self.log("Node %s is not up." % node)
            return

        if node in self.CIBsync or not self.Env["ClobberCIB"]:
            return

        self.CIBsync[node] = 1
        self.rsh(node, "rm -f %s/cib*" % BuildOptions.CIB_DIR)

        # Only install the CIB on the first node, all the other ones will pick it up from there
        if self.cib_installed == 1:
            return

        self.cib_installed = 1
        if self.Env["CIBfilename"] is None:
            self.log("Installing Generated CIB on node %s" % node)
            self.cib.install(node)

        else:
            self.log("Installing CIB (%s) on node %s" % (self.Env["CIBfilename"], node))

            rc = self.rsh.copy(self.Env["CIBfilename"], "root@" + (self.templates["CIBfile"] % node))

            if rc != 0:
                raise ValueError("Can not scp file to %s %d" % (node, rc))

        self.rsh(node, "chown %s %s/cib.xml" % (BuildOptions.DAEMON_USER, BuildOptions.CIB_DIR))

    def prepare(self):
        '''Finish the Initialization process. Prepare to test...'''

        self.partitions_expected = 1
        for node in self.Env["nodes"]:
            self.ShouldBeStatus[node] = ""
            if self.Env["experimental-tests"]:
                self.unisolate_node(node)
            self.stat_cm(node)

    def test_node_CM(self, node):
        '''Report the status of the cluster manager on a given node'''

        watchpats = [ "Current ping state: (S_IDLE|S_NOT_DC)",
                      self.templates["Pat:NonDC_started"] % node,
                      self.templates["Pat:DC_started"] % node ]

        idle_watch = LogWatcher(self.Env["LogFileName"], watchpats, [node], self.Env["LogWatcher"], "ClusterIdle")
        idle_watch.set_watch()

        (_, out) = self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

        if not out:
            out = ""
        else:
            out = out[0].strip()

        self.debug("Node %s status: '%s'" % (node, out))

        if out.find('ok') < 0:
            if self.ShouldBeStatus[node] == "up":
                self.log(
                    "Node status for %s is %s but we think it should be %s"
                    % (node, "down", self.ShouldBeStatus[node]))
            self.ShouldBeStatus[node] = "down"
            return 0

        if self.ShouldBeStatus[node] == "down":
            self.log(
                "Node status for %s is %s but we think it should be %s: %s"
                % (node, "up", self.ShouldBeStatus[node], out))

        self.ShouldBeStatus[node] = "up"

        # check the output first - because syslog-ng loses messages
        if out.find('S_NOT_DC') != -1:
            # Up and stable
            return 2
        if out.find('S_IDLE') != -1:
            # Up and stable
            return 2

        # fall back to syslog-ng and wait
        if not idle_watch.look():
            # just up
            self.debug("Warn: Node %s is unstable: %s" % (node, out))
            return 1

        # Up and stable
        return 2

    def stat_cm(self, node):
        """ Report the status of the cluster manager on a given node """

        return self.test_node_CM(node) > 0

    # Being up and being stable is not the same question...
    def node_stable(self, node):
        '''Report the status of the cluster manager on a given node'''

        if self.test_node_CM(node) == 2:
            return 1
        self.log("Warn: Node %s not stable" % node)
        return None

    def partition_stable(self, nodes, timeout=None):
        watchpats = [ "Current ping state: S_IDLE",
                      self.templates["Pat:DC_IDLE"] ]

        self.debug("Waiting for cluster stability...")

        if timeout is None:
            timeout = self.Env["DeadTime"]

        if len(nodes) < 3:
            self.debug("Cluster is inactive")
            return 1

        idle_watch = LogWatcher(self.Env["LogFileName"], watchpats, nodes.split(), self.Env["LogWatcher"], "ClusterStable", timeout)
        idle_watch.set_watch()

        for node in nodes.split():
            # have each node dump its current state
            self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

        ret = idle_watch.look()
        while ret:
            self.debug(ret)
            for node in nodes.split():
                if re.search(node, ret):
                    return 1
            ret = idle_watch.look()

        self.debug("Warn: Partition %r not IDLE after %ds" % (nodes, timeout))
        return None

    def cluster_stable(self, timeout=None, double_check=False):
        partitions = self.find_partitions()

        for partition in partitions:
            if not self.partition_stable(partition, timeout):
                return None

        if not double_check:
            return 1

        # Make sure we are really stable and that all resources,
        # including those that depend on transient node attributes,
        # are started if they were going to be
        time.sleep(5)
        for partition in partitions:
            if not self.partition_stable(partition, timeout):
                return None

        return 1

    def is_node_dc(self, node, status_line=None):
        if not status_line:
            (_, out) = self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

            if out:
                status_line = out[0].strip()

        if not status_line:
            return False

        if status_line.find('S_IDLE') != -1:
            return True

        if status_line.find('S_INTEGRATION') != -1:
            return True

        if status_line.find('S_FINALIZE_JOIN') != -1:
            return True

        if status_line.find('S_POLICY_ENGINE') != -1:
            return True

        if status_line.find('S_TRANSITION_ENGINE') != -1:
            return True

        return False

    def active_resources(self, node):
        (_, output) = self.rsh(node, "crm_resource -c", verbose=1)
        resources = []
        for line in output:
            if not re.search("^Resource", line):
                continue

            tmp = AuditResource(self, line)
            if tmp.type == "primitive" and tmp.host == node:
                resources.append(tmp.id)

        return resources

    def ResourceLocation(self, rid):
        ResourceNodes = []
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] != "up":
                continue

            cmd = self.templates["RscRunning"] % rid
            (rc, lines) = self.rsh(node, cmd)

            if rc == 127:
                self.log("Command '%s' failed. Binary or pacemaker-cts package not installed?" % cmd)
                for line in lines:
                    self.log("Output: %s " % line)
            elif rc == 0:
                ResourceNodes.append(node)

        return ResourceNodes

    def find_partitions(self):
        ccm_partitions = []

        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] != "up":
                self.debug("Node %s is down... skipping" % node)
                continue

            (_, out) = self.rsh(node, self.templates["PartitionCmd"], verbose=1)

            if not out:
                self.log("no partition details for %s" % node)
                continue

            partition = out[0].strip()

            if len(partition) <= 2:
                self.log("bad partition details for %s" % node)
                continue

            nodes = partition.split()
            nodes.sort()
            partition = ' '.join(nodes)

            found = 0
            for a_partition in ccm_partitions:
                if partition == a_partition:
                    found = 1
            if found == 0:
                self.debug("Adding partition from %s: %s" % (node, partition))
                ccm_partitions.append(partition)
            else:
                self.debug("Partition '%s' from %s is consistent with existing entries" % (partition, node))

        self.debug("Found partitions: %r" % ccm_partitions)
        return ccm_partitions

    def has_quorum(self, node_list):
        # If we are auditing a partition, then one side will
        #   have quorum and the other not.
        # So the caller needs to tell us which we are checking
        # If no value for node_list is specified... assume all nodes
        if not node_list:
            node_list = self.Env["nodes"]

        for node in node_list:
            if self.ShouldBeStatus[node] != "up":
                continue

            (_, quorum) = self.rsh(node, self.templates["QuorumCmd"], verbose=1)
            quorum = quorum[0].strip()

            if quorum.find("1") != -1:
                return True

            if quorum.find("0") != -1:
                return False

            self.debug("WARN: Unexpected quorum test result from %s:%s" % (node, quorum))

        return False

    def Components(self):
        complist = []
        common_ignore = [
                    "Pending action:",
                    "(ERROR|error): crm_log_message_adv:",
                    "(ERROR|error): MSG: No message to dump",
                    "pending LRM operations at shutdown",
                    "Lost connection to the CIB manager",
                    "Connection to the CIB terminated...",
                    "Sending message to the CIB manager FAILED",
                    "Action A_RECOVER .* not supported",
                    "(ERROR|error): stonithd_op_result_ready: not signed on",
                    "pingd.*(ERROR|error): send_update: Could not send update",
                    "send_ipc_message: IPC Channel to .* is not connected",
                    "unconfirmed_actions: Waiting on .* unconfirmed actions",
                    "cib_native_msgready: Message pending on command channel",
                    r": Performing A_EXIT_1 - forcefully exiting ",
                    r"Resource .* was active at shutdown.  You may ignore this error if it is unmanaged.",
            ]

        stonith_ignore = [
            r"Updating failcount for child_DoFencing",
            r"error.*: Fencer connection failed \(will retry\)",
            "pacemaker-execd.*(ERROR|error): stonithd_receive_ops_result failed.",
             ]

        stonith_ignore.extend(common_ignore)

        ccm = Process(self, "ccm", pats = [
                    "State transition .* S_RECOVERY",
                    "pacemaker-controld.*Action A_RECOVER .* not supported",
                    r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
                    r"pacemaker-controld.*: Could not recover from internal error",
                    "pacemaker-controld.*I_ERROR.*crmd_cib_connection_destroy",
                    # these status numbers are likely wrong now
                    r"pacemaker-controld.*exited with status 2",
                    r"attrd.*exited with status 1",
                    r"cib.*exited with status 2",
                    "State transition S_STARTING -> S_PENDING",
                    ], badnews_ignore = common_ignore)

        based = Process(self, "pacemaker-based", pats = [
                    "State transition .* S_RECOVERY",
                    "Lost connection to the CIB manager",
                    "Connection to the CIB manager terminated",
                    r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
                    "pacemaker-controld.*I_ERROR.*crmd_cib_connection_destroy",
                    r"pacemaker-controld.*: Could not recover from internal error",
                    # these status numbers are likely wrong now
                    r"pacemaker-controld.*exited with status 2",
                    r"attrd.*exited with status 1",
                    ], badnews_ignore = common_ignore)

        execd = Process(self, "pacemaker-execd", pats = [
                    "State transition .* S_RECOVERY",
                    "LRM Connection failed",
                    "pacemaker-controld.*I_ERROR.*lrm_connection_destroy",
                    "State transition S_STARTING -> S_PENDING",
                    r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
                    r"pacemaker-controld.*: Could not recover from internal error",
                    # this status number is likely wrong now
                    r"pacemaker-controld.*exited with status 2",
                    ], badnews_ignore = common_ignore)

        controld = Process(self, "pacemaker-controld",
                    pats = [
                    "State transition .* S_IDLE",
                    "State transition S_STARTING -> S_PENDING",
                    ], badnews_ignore = common_ignore)

        schedulerd = Process(self, "pacemaker-schedulerd", pats = [
                    "State transition .* S_RECOVERY",
                    r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
                    r"pacemaker-controld.*: Could not recover from internal error",
                    r"pacemaker-controld.*CRIT.*: Connection to the scheduler failed",
                    "pacemaker-controld.*I_ERROR.*save_cib_contents",
                    # this status number is likely wrong now
                    r"pacemaker-controld.*exited with status 2",
                    ], badnews_ignore = common_ignore, dc_only=True)

        if self.Env["DoFencing"]:
            complist.append(Process(self, "stoniths", dc_pats = [
                        r"pacemaker-controld.*CRIT.*: Fencing daemon connection failed",
                        "Attempting connection to fencing daemon",
                    ], badnews_ignore = stonith_ignore))

        ccm.pats.extend([
            # these status numbers are likely wrong now
            r"attrd.*exited with status 1",
            r"pacemaker-(based|controld).*exited with status 2",
            ])
        based.pats.extend([
            # these status numbers are likely wrong now
            r"attrd.*exited with status 1",
            r"pacemaker-controld.*exited with status 2",
            ])
        execd.pats.extend([
            # these status numbers are likely wrong now
            r"pacemaker-controld.*exited with status 2",
            ])

        complist.extend([ ccm, based, execd, controld, schedulerd ])

        return complist

    def StandbyStatus(self, node):
        (_, out) = self.rsh(node, self.templates["StandbyQueryCmd"] % node, verbose=1)
        if not out:
            return "off"
        out = out[0].strip()
        self.debug("Standby result: %s" % out)
        return out

    # status == "on" : Enter Standby mode
    # status == "off": Enter Active mode
    def set_standby_mode(self, node, status):
        current_status = self.StandbyStatus(node)

        if current_status == status:
            return True

        cmd = self.templates["StandbyCmd"] % (node, status)
        (rc, _) = self.rsh(node, cmd)
        return rc == 0

    def AddDummyRsc(self, node, rid):
        rsc_xml = """ '<resources>
                <primitive class=\"ocf\" id=\"%s\" provider=\"pacemaker\" type=\"Dummy\">
                    <operations>
                        <op id=\"%s-interval-10s\" interval=\"10s\" name=\"monitor\"/
                    </operations>
                </primitive>
            </resources>'""" % (rid, rid)
        constraint_xml = """ '<constraints>
                <rsc_location id=\"location-%s-%s\" node=\"%s\" rsc=\"%s\" score=\"INFINITY\"/>
            </constraints>'
            """ % (rid, node, node, rid)

        self.rsh(node, self.templates['CibAddXml'] % rsc_xml)
        self.rsh(node, self.templates['CibAddXml'] % constraint_xml)

    def RemoveDummyRsc(self, node, rid):
        constraint = "\"//rsc_location[@rsc='%s']\"" % rid
        rsc = "\"//primitive[@id='%s']\"" % rid

        self.rsh(node, self.templates['CibDelXpath'] % constraint)
        self.rsh(node, self.templates['CibDelXpath'] % rsc)
