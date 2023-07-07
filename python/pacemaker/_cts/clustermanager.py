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
from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.cib import ConfigFactory
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.patterns import PatternSelector
from pacemaker._cts.remote import RemoteFactory
from pacemaker._cts.watcher import LogWatcher

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

    def _final_conditions(self):
        for key in list(self.keys()):
            if self[key] is None:
                raise ValueError("Improper derivation: self[%s] must be overridden by subclass." % key)

    def __init__(self):
        # Eventually, ClusterManager should not be a UserDict subclass.  Until
        # that point...
        # pylint: disable=super-init-not-called
        self.__instance_errors_to_ignore = []

        self._cib_installed = False
        self._data = {}
        self._logger = LogFactory()

        self.env = EnvFactory().getInstance()
        self.expected_status = {}
        self.name = self.env["Name"]
        # pylint: disable=invalid-name
        self.ns = NodeStatus(self.env)
        self.our_node = os.uname()[1].lower()
        self.partitions_expected = 1
        self.rsh = RemoteFactory().getInstance()
        self.templates = PatternSelector(self.env["Name"])

        self._final_conditions()

        self._cib_factory = ConfigFactory(self)
        self._cib = self._cib_factory.create_config(self.env["Schema"])
        self._cib_sync = {}

    def __getitem__(self, key):
        if key == "Name":
            return self.name

        print("FIXME: Getting %s from %r" % (key, self))
        if key in self._data:
            return self._data[key]

        return self.templates.get_patterns(key)

    def __setitem__(self, key, value):
        print("FIXME: Setting %s=%s on %r" % (key, value, self))
        self._data[key] = value

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
        self._logger.log(args)

    def debug(self, args):
        self._logger.debug(args)

    def upcount(self):
        '''How many nodes are up?'''
        count = 0
        for node in self.env["nodes"]:
            if self.expected_status[node] == "up":
                count = count + 1
        return count

    def install_support(self, command="install"):
        for node in self.env["nodes"]:
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
        stonith_pats = []
        for peer in self.env["nodes"]:
            if self.expected_status[peer] == "up":
                continue

            stonith_pats.extend([ self.templates["Pat:Fencing_ok"] % peer,
                                 self.templates["Pat:Fencing_start"] % peer ])

        stonith = LogWatcher(self.env["LogFileName"], stonith_pats, self.env["nodes"], self.env["LogWatcher"], "StartupFencing", 0)
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
        if not q and len(self.env["nodes"]) > 2:
            # We didn't gain quorum - we shouldn't have shot anyone
            self.debug("Quorum: %s Len: %d" % (q, len(self.env["nodes"])))
            return peer_list

        for n in self.env["nodes"]:
            peer_state[n] = "unknown"

        # Now see if any states need to be updated
        self.debug("looking for: %r" % stonith.regexes)
        shot = stonith.look(0)
        while shot:
            self.debug("Found: %r" % shot)
            del stonith.regexes[stonith.whichmatch]

            # Extract node name
            for n in self.env["nodes"]:
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
                self._logger.log("ERROR: Unknown stonith match: %r" % shot)

            elif not peer in peer_list:
                self.debug("Found peer: %s" % peer)
                peer_list.append(peer)

            # Get the next one
            shot = stonith.look(60)

        for peer in peer_list:

            self.debug("   Peer %s was fenced as a result of %s starting: %s" % (peer, node, peer_state[peer]))
            if self.env["at-boot"]:
                self.expected_status[peer] = "up"
            else:
                self.expected_status[peer] = "down"

            if peer_state[peer] == "in-progress":
                # Wait for any in-progress operations to complete
                shot = stonith.look(60)
                while stonith.regexes and shot:
                    self.debug("Found: %r" % shot)
                    del stonith.regexes[stonith.whichmatch]
                    shot = stonith.look(60)

            # Now make sure the node is alive too
            self.ns.wait_for_node(peer, self.env["DeadTime"])

            # Poll until it comes up
            if self.env["at-boot"]:
                if not self.stat_cm(peer):
                    time.sleep(self.env["StartTime"])

                if not self.stat_cm(peer):
                    self._logger.log("ERROR: Peer %s failed to restart after being fenced" % peer)
                    return None

        return peer_list

    def start_cm(self, node, verbose=False):
        """ Start up the cluster manager on a given node """

        if verbose:
            self._logger.log("Starting %s on node %s" % (self.templates["Name"], node))
        else:
            self.debug("Starting %s on node %s" % (self.templates["Name"], node))

        if not node in self.expected_status:
            self.expected_status[node] = "down"

        if self.expected_status[node] != "down":
            return True

        # Technically we should always be able to notice ourselves starting
        patterns = [ self.templates["Pat:Local_started"] % node ]
        if self.upcount() == 0:
            patterns.append(self.templates["Pat:DC_started"] % node)
        else:
            patterns.append(self.templates["Pat:NonDC_started"] % node)

        watch = LogWatcher(
            self.env["LogFileName"], patterns, self.env["nodes"], self.env["LogWatcher"], "StartaCM", self.env["StartTime"]+10)

        self.install_config(node)

        self.expected_status[node] = "any"
        if self.stat_cm(node) and self.cluster_stable(self.env["DeadTime"]):
            self._logger.log ("%s was already started" % node)
            return True

        stonith = self.prepare_fencing_watcher()
        watch.set_watch()

        (rc, _) = self.rsh(node, self.templates["StartCmd"])
        if rc != 0:
            self._logger.log ("Warn: Start command failed on node %s" % node)
            self.fencing_cleanup(node, stonith)
            return False

        self.expected_status[node] = "up"
        watch_result = watch.look_for_all()

        if watch.unmatched:
            for regex in watch.unmatched:
                self._logger.log ("Warn: Startup pattern not found: %s" % regex)

        if watch_result and self.cluster_stable(self.env["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return True

        if self.stat_cm(node) and self.cluster_stable(self.env["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return True

        self._logger.log ("Warn: Start failed for node %s" % node)
        return False

    def start_cm_async(self, node, verbose=False):
        """ Start up the cluster manager on a given node without blocking """

        if verbose:
            self._logger.log("Starting %s on node %s" % (self["Name"], node))
        else:
            self.debug("Starting %s on node %s" % (self["Name"], node))

        self.install_config(node)
        self.rsh(node, self.templates["StartCmd"], synchronous=False)
        self.expected_status[node] = "up"

    def stop_cm(self, node, verbose=False, force=False):
        """ Stop the cluster manager on a given node """

        if verbose:
            self._logger.log("Stopping %s on node %s" % (self["Name"], node))
        else:
            self.debug("Stopping %s on node %s" % (self["Name"], node))

        if self.expected_status[node] != "up" and not force:
            return True

        (rc, _) = self.rsh(node, self.templates["StopCmd"])
        if rc == 0:
            # Make sure we can continue even if corosync leaks
            self.expected_status[node] = "down"
            self.cluster_stable(self.env["DeadTime"])
            return True

        self._logger.log ("ERROR: Could not stop %s on node %s" % (self["Name"], node))
        return False

    def stop_cm_async(self, node):
        """ Stop the cluster manager on a given node without blocking """

        self.debug("Stopping %s on node %s" % (self["Name"], node))

        self.rsh(node, self.templates["StopCmd"], synchronous=False)
        self.expected_status[node] = "down"

    def startall(self, nodelist=None, verbose=False, quick=False):
        """ Start the cluster manager on every node in the cluster, or on every
            node in nodelist if not None
        """

        if not nodelist:
            nodelist = self.env["nodes"]

        for node in nodelist:
            if self.expected_status[node] == "down":
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
        watch = LogWatcher(self.env["LogFileName"], watchpats, self.env["nodes"], self.env["LogWatcher"], "fast-start", self.env["DeadTime"]+10)
        watch.set_watch()

        if not self.start_cm(nodelist[0], verbose=verbose):
            return False
        for node in nodelist:
            self.start_cm_async(node, verbose=verbose)

        watch.look_for_all()
        if watch.unmatched:
            for regex in watch.unmatched:
                self._logger.log ("Warn: Startup pattern not found: %s" % regex)

        if not self.cluster_stable():
            self._logger.log("Cluster did not stabilize")
            return False

        return True

    def stopall(self, nodelist=None, verbose=False, force=False):
        """ Stop the cluster manager on every node in the cluster, or on every
            node in nodelist if not None
        """

        ret = True
        if not nodelist:
            nodelist = self.env["nodes"]
        for node in self.env["nodes"]:
            if self.expected_status[node] == "up" or force:
                if not self.stop_cm(node, verbose=verbose, force=force):
                    ret = False
        return ret

    def statall(self, nodelist=None):

        '''Return the status of the cluster managers in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        result = {}
        if not nodelist:
            nodelist = self.env["nodes"]
        for node in nodelist:
            if self.stat_cm(node):
                result[node] = "up"
            else:
                result[node] = "down"
        return result

    def isolate_node(self, target, nodes=None):
        '''isolate the communication between the nodes'''
        if not nodes:
            nodes = self.env["nodes"]

        for node in nodes:
            if node == target:
                continue

            (rc, _) = self.rsh(target, self.templates["BreakCommCmd"] % self.key_for_node(node))
            if rc != 0:
                self._logger.log("Could not break the communication between %s and %s: %d" % (target, node, rc))
                return False

            self.debug("Communication cut between %s and %s" % (target, node))

        return True

    def unisolate_node(self, target, nodes=None):
        '''fix the communication between the nodes'''
        if not nodes:
            nodes = self.env["nodes"]

        for node in nodes:
            if node == target:
                continue

            # Limit the amount of time we have asynchronous connectivity for
            # Restore both sides as simultaneously as possible
            self.rsh(target, self.templates["FixCommCmd"] % self.key_for_node(node), synchronous=False)
            self.rsh(node, self.templates["FixCommCmd"] % self.key_for_node(target), synchronous=False)
            self.debug("Communication restored between %s and %s" % (target, node))

    def oprofile_start(self, node=None):
        if not node:
            for n in self.env["oprofile"]:
                self.oprofile_start(n)

        elif node in self.env["oprofile"]:
            self.debug("Enabling oprofile on %s" % node)
            self.rsh(node, "opcontrol --init")
            self.rsh(node, "opcontrol --setup --no-vmlinux --separate=lib --callgraph=20 --image=all")
            self.rsh(node, "opcontrol --start")
            self.rsh(node, "opcontrol --reset")

    def oprofile_save(self, test, node=None):
        if not node:
            for n in self.env["oprofile"]:
                self.oprofile_save(test, n)

        elif node in self.env["oprofile"]:
            self.rsh(node, "opcontrol --dump")
            self.rsh(node, "opcontrol --save=cts.%d" % test)
            # Read back with: opreport -l session:cts.0 image:<directory>/c*
            self.oprofile_stop(node)
            self.oprofile_start(node)

    def oprofile_stop(self, node=None):
        if not node:
            for n in self.env["oprofile"]:
                self.oprofile_stop(n)

        elif node in self.env["oprofile"]:
            self.debug("Stopping oprofile on %s" % node)
            self.rsh(node, "opcontrol --reset")
            self.rsh(node, "opcontrol --shutdown 2>&1 > /dev/null")

    def install_config(self, node):
        if not self.ns.wait_for_node(node):
            self.log("Node %s is not up." % node)
            return

        if node in self._cib_sync or not self.env["ClobberCIB"]:
            return

        self._cib_sync[node] = True
        self.rsh(node, "rm -f %s/cib*" % BuildOptions.CIB_DIR)

        # Only install the CIB on the first node, all the other ones will pick it up from there
        if self._cib_installed:
            return

        self._cib_installed = True
        if self.env["CIBfilename"] is None:
            self.log("Installing Generated CIB on node %s" % node)
            self._cib.install(node)

        else:
            self.log("Installing CIB (%s) on node %s" % (self.env["CIBfilename"], node))

            rc = self.rsh.copy(self.env["CIBfilename"], "root@" + (self.templates["CIBfile"] % node))

            if rc != 0:
                raise ValueError("Can not scp file to %s %d" % (node, rc))

        self.rsh(node, "chown %s %s/cib.xml" % (BuildOptions.DAEMON_USER, BuildOptions.CIB_DIR))

    def prepare(self):
        '''Finish the Initialization process. Prepare to test...'''

        self.partitions_expected = 1
        for node in self.env["nodes"]:
            self.expected_status[node] = ""
            if self.env["experimental-tests"]:
                self.unisolate_node(node)
            self.stat_cm(node)

    def test_node_cm(self, node):
        '''Report the status of the cluster manager on a given node'''

        watchpats = [ "Current ping state: (S_IDLE|S_NOT_DC)",
                      self.templates["Pat:NonDC_started"] % node,
                      self.templates["Pat:DC_started"] % node ]

        idle_watch = LogWatcher(self.env["LogFileName"], watchpats, [node], self.env["LogWatcher"], "ClusterIdle")
        idle_watch.set_watch()

        (_, out) = self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

        if not out:
            out = ""
        else:
            out = out[0].strip()

        self.debug("Node %s status: '%s'" % (node, out))

        if out.find('ok') < 0:
            if self.expected_status[node] == "up":
                self.log(
                    "Node status for %s is %s but we think it should be %s"
                    % (node, "down", self.expected_status[node]))
            self.expected_status[node] = "down"
            return 0

        if self.expected_status[node] == "down":
            self.log(
                "Node status for %s is %s but we think it should be %s: %s"
                % (node, "up", self.expected_status[node], out))

        self.expected_status[node] = "up"

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

        return self.test_node_cm(node) > 0

    # Being up and being stable is not the same question...
    def node_stable(self, node):
        '''Report the status of the cluster manager on a given node'''

        if self.test_node_cm(node) == 2:
            return True
        self.log("Warn: Node %s not stable" % node)
        return False

    def partition_stable(self, nodes, timeout=None):
        watchpats = [ "Current ping state: S_IDLE",
                      self.templates["Pat:DC_IDLE"] ]

        self.debug("Waiting for cluster stability...")

        if timeout is None:
            timeout = self.env["DeadTime"]

        if len(nodes) < 3:
            self.debug("Cluster is inactive")
            return True

        idle_watch = LogWatcher(self.env["LogFileName"], watchpats, nodes.split(), self.env["LogWatcher"], "ClusterStable", timeout)
        idle_watch.set_watch()

        for node in nodes.split():
            # have each node dump its current state
            self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

        ret = idle_watch.look()
        while ret:
            self.debug(ret)
            for node in nodes.split():
                if re.search(node, ret):
                    return True
            ret = idle_watch.look()

        self.debug("Warn: Partition %r not IDLE after %ds" % (nodes, timeout))
        return False

    def cluster_stable(self, timeout=None, double_check=False):
        partitions = self.find_partitions()

        for partition in partitions:
            if not self.partition_stable(partition, timeout):
                return False

        if not double_check:
            return True

        # Make sure we are really stable and that all resources,
        # including those that depend on transient node attributes,
        # are started if they were going to be
        time.sleep(5)
        for partition in partitions:
            if not self.partition_stable(partition, timeout):
                return False

        return True

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

    def resource_location(self, rid):
        resource_nodes = []
        for node in self.env["nodes"]:
            if self.expected_status[node] != "up":
                continue

            cmd = self.templates["RscRunning"] % rid
            (rc, lines) = self.rsh(node, cmd)

            if rc == 127:
                self.log("Command '%s' failed. Binary or pacemaker-cts package not installed?" % cmd)
                for line in lines:
                    self.log("Output: %s " % line)
            elif rc == 0:
                resource_nodes.append(node)

        return resource_nodes

    def find_partitions(self):
        ccm_partitions = []

        for node in self.env["nodes"]:
            if self.expected_status[node] != "up":
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
            node_list = self.env["nodes"]

        for node in node_list:
            if self.expected_status[node] != "up":
                continue

            (_, quorum) = self.rsh(node, self.templates["QuorumCmd"], verbose=1)
            quorum = quorum[0].strip()

            if quorum.find("1") != -1:
                return True

            if quorum.find("0") != -1:
                return False

            self.debug("WARN: Unexpected quorum test result from %s:%s" % (node, quorum))

        return False

    @property
    def components(self):
        raise NotImplementedError

    def standby_status(self, node):
        (_, out) = self.rsh(node, self.templates["StandbyQueryCmd"] % node, verbose=1)
        if not out:
            return "off"
        out = out[0].strip()
        self.debug("Standby result: %s" % out)
        return out

    # status == "on" : Enter Standby mode
    # status == "off": Enter Active mode
    def set_standby_mode(self, node, status):
        current_status = self.standby_status(node)

        if current_status == status:
            return True

        cmd = self.templates["StandbyCmd"] % (node, status)
        (rc, _) = self.rsh(node, cmd)
        return rc == 0

    def add_dummy_rsc(self, node, rid):
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

    def remove_dummy_rsc(self, node, rid):
        constraint = "\"//rsc_location[@rsc='%s']\"" % rid
        rsc = "\"//primitive[@id='%s']\"" % rid

        self.rsh(node, self.templates['CibDelXpath'] % constraint)
        self.rsh(node, self.templates['CibDelXpath'] % rsc)
