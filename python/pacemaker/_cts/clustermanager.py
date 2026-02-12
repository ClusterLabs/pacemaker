"""ClusterManager class for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["ClusterManager"]
__copyright__ = """Copyright 2000-2026 the Pacemaker project contributors.
Certain portions by Huang Zhen <zhenhltc@cn.ibm.com> are copyright 2004
International Business Machines. The version control history for this file
may have further details."""
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import os
import re
import time

from collections import UserDict

from pacemaker.buildoptions import BuildOptions
from pacemaker.exitstatus import ExitStatus
from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.cib import ConfigFactory
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts import logging
from pacemaker._cts.patterns import PatternSelector
from pacemaker._cts.remote import RemoteExec
from pacemaker._cts.watcher import LogWatcher

# ClusterManager has a lot of methods.
# pylint: disable=too-many-public-methods


class ClusterManager(UserDict):
    """
    An abstract base class for managing the cluster.

    This class implements high-level operations on the cluster and/or its cluster
    managers.  Actual cluster-specific management classes should be subclassed
    from this one.

    Among other things, this class tracks the state every node is expected to be in.
    """

    def __init__(self):
        """Create a new ClusterManager instance."""
        # Eventually, ClusterManager should not be a UserDict subclass.  Until
        # that point...
        # pylint: disable=super-init-not-called
        self.__instance_errors_to_ignore = []

        self._cib_installed = False

        self.env = EnvFactory().getInstance()
        self.expected_status = {}
        self.name = self.env["Name"]
        # pylint: disable=invalid-name
        self.ns = NodeStatus(self.env)
        self.our_node = os.uname()[1].lower()
        self.partitions_expected = 1
        self.rsh = RemoteExec()
        self.templates = PatternSelector(self.name)

        self._cib_factory = ConfigFactory(self)
        self._cib = self._cib_factory.create_config(self.env["Schema"])
        self._cib_sync = {}

    def clear_instance_errors_to_ignore(self):
        """Reset instance-specific errors to ignore on each iteration."""
        self.__instance_errors_to_ignore = []

    @property
    def instance_errors_to_ignore(self):
        """Return a list of known errors that should be ignored for a specific test instance."""
        return self.__instance_errors_to_ignore

    @property
    def errors_to_ignore(self):
        """Return a list of known error messages that should be ignored."""
        return self.templates.get_patterns("BadNewsIgnore")

    def log(self, args):
        """Log a message."""
        logging.log(args)

    def debug(self, args):
        """Log a debug message."""
        logging.debug(args)

    def upcount(self):
        """Return how many nodes are up."""
        count = 0

        for node in self.env["nodes"]:
            if self.expected_status[node] == "up":
                count += 1

        return count

    def install_support(self, command="install"):
        """
        Install or uninstall the CTS support files.

        This includes various init scripts and data, daemons, fencing agents, etc.
        """
        for node in self.env["nodes"]:
            self.rsh(node, f"{BuildOptions.DAEMON_DIR}/cts-support {command}")

    def prepare_fencing_watcher(self):
        """Return a LogWatcher object that watches for fencing log messages."""
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

            stonith_pats.extend([
                self.templates["Pat:Fencing_ok"] % peer,
                self.templates["Pat:Fencing_start"] % peer,
            ])

        stonith = LogWatcher(self.env["LogFileName"], stonith_pats, self.env["nodes"],
                             self.env["log_kind"], "StartupFencing", 0)
        stonith.set_watch()
        return stonith

    def fencing_cleanup(self, node, stonith):
        """Wait for a previously fenced node to return to the cluster."""
        peer_list = []
        peer_state = {}

        self.debug(f"Looking for nodes that were fenced as a result of {node} starting")

        # If we just started a node, we may now have quorum (and permission to fence)
        if not stonith:
            self.debug("Nothing to do")
            return peer_list

        q = self.has_quorum(None)
        if not q and len(self.env["nodes"]) > 2:
            # We didn't gain quorum - we shouldn't have shot anyone
            self.debug(f"Quorum: {q} Len: {len(self.env['nodes'])}")
            return peer_list

        for n in self.env["nodes"]:
            peer_state[n] = "unknown"

        # Now see if any states need to be updated
        self.debug(f"looking for: {stonith.regexes!r}")
        shot = stonith.look(0)

        while shot:
            self.debug(f"Found: {shot!r}")
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
                logging.log(f"ERROR: Unknown stonith match: {shot!r}")

            elif peer not in peer_list:
                self.debug(f"Found peer: {peer}")
                peer_list.append(peer)

            # Get the next one
            shot = stonith.look(60)

        for peer in peer_list:
            self.debug(f"   Peer {peer} was fenced as a result of {node} starting: {peer_state[peer]}")
            if self.env["at-boot"]:
                self.expected_status[peer] = "up"
            else:
                self.expected_status[peer] = "down"

            if peer_state[peer] == "in-progress":
                # Wait for any in-progress operations to complete
                shot = stonith.look(60)

                while stonith.regexes and shot:
                    self.debug(f"Found: {shot!r}")
                    del stonith.regexes[stonith.whichmatch]
                    shot = stonith.look(60)

            # Now make sure the node is alive too
            self.ns.wait_for_node(peer, self.env["dead_time"])

            # Poll until it comes up
            if self.env["at-boot"]:
                if not self.stat_cm(peer):
                    time.sleep(self.env["start_time"])

                if not self.stat_cm(peer):
                    logging.log(f"ERROR: Peer {peer} failed to restart after being fenced")
                    return None

        return peer_list

    def _install_config(self, node):
        """Remove and re-install the CIB on the first node in the cluster."""
        if not self.ns.wait_for_node(node):
            self.log(f"Node {node} is not up.")
            return

        if node in self._cib_sync or not self.env["overwrite_cib"]:
            return

        self._cib_sync[node] = True
        self.rsh(node, f"rm -f {BuildOptions.CIB_DIR}/cib*")

        # Only install the CIB on the first node, all the other ones will pick it up from there
        if self._cib_installed:
            return

        self._cib_installed = True
        if self.env["CIBfilename"]:
            self.log(f"Installing CIB ({self.env['CIBfilename']}) on node {node}")

            rc = self.rsh.copy(self.env["CIBfilename"], "root@" + (self.templates["CIBfile"] % node))

            if rc != 0:
                raise ValueError(f"Can not scp file to {node} {rc}")

        else:
            self.log(f"Installing Generated CIB on node {node}")
            self._cib.install(node)

        self.rsh(node, f"chown {BuildOptions.DAEMON_USER} {BuildOptions.CIB_DIR}/cib.xml")

    def start_cm(self, node, verbose=False):
        """Start up the cluster manager on a given node."""
        log_fn = logging.log if verbose else self.debug
        log_fn(f"Starting {self.name} on node {node}")

        if node not in self.expected_status:
            self.expected_status[node] = "down"

        if self.expected_status[node] != "down":
            return True

        # Technically we should always be able to notice ourselves starting
        patterns = [
            self.templates["Pat:Local_started"] % node,
        ]

        if self.upcount() == 0:
            patterns.append(self.templates["Pat:DC_started"] % node)
        else:
            patterns.append(self.templates["Pat:NonDC_started"] % node)

        watch = LogWatcher(self.env["LogFileName"], patterns,
                           self.env["nodes"], self.env["log_kind"],
                           "StartaCM", self.env["start_time"] + 10)

        self._install_config(node)

        self.expected_status[node] = "any"

        if self.stat_cm(node) and self.cluster_stable(self.env["dead_time"]):
            logging.log(f"{node} was already started")
            return True

        stonith = self.prepare_fencing_watcher()
        watch.set_watch()

        (rc, _) = self.rsh(node, self.templates["StartCmd"])
        if rc != 0:
            logging.log(f"Warn: Start command failed on node {node}")
            self.fencing_cleanup(node, stonith)
            return False

        self.expected_status[node] = "up"
        watch_result = watch.look_for_all()

        if watch.unmatched:
            for regex in watch.unmatched:
                logging.log(f"Warn: Startup pattern not found: {regex}")

        if watch_result and self.cluster_stable(self.env["dead_time"]):
            self.fencing_cleanup(node, stonith)
            return True

        if self.stat_cm(node) and self.cluster_stable(self.env["dead_time"]):
            self.fencing_cleanup(node, stonith)
            return True

        logging.log(f"Warn: Start failed for node {node}")
        return False

    def start_cm_async(self, node, verbose=False):
        """Start up the cluster manager on a given node without blocking."""
        log_fn = logging.log if verbose else self.debug
        log_fn(f"Starting {self.name} on node {node}")

        self._install_config(node)
        self.rsh.call_async(node, self.templates["StartCmd"])
        self.expected_status[node] = "up"

    def stop_cm(self, node, verbose=False, force=False):
        """Stop the cluster manager on a given node."""
        log_fn = logging.log if verbose else self.debug
        log_fn(f"Stopping {self.name} on node {node}")

        if self.expected_status[node] != "up" and not force:
            return True

        (rc, _) = self.rsh(node, self.templates["StopCmd"])
        if rc == 0:
            # Make sure we can continue even if corosync leaks
            self.expected_status[node] = "down"
            self.cluster_stable(self.env["dead_time"])
            return True

        logging.log(f"ERROR: Could not stop {self.name} on node {node}")
        return False

    def stop_cm_async(self, node):
        """Stop the cluster manager on a given node without blocking."""
        self.debug(f"Stopping {self.name} on node {node}")

        self.rsh.call_async(node, self.templates["StopCmd"])
        self.expected_status[node] = "down"

    def startall(self, nodelist=None, verbose=False, quick=False):
        """Start the cluster manager on every node in the cluster, or on every node in nodelist."""
        if not nodelist:
            nodelist = self.env["nodes"]

        for node in nodelist:
            if self.expected_status[node] == "down":
                self.ns.wait_for_all_nodes(nodelist, 300)

        if not quick:
            # This is used for "basic sanity checks", so only start one node ...
            return self.start_cm(nodelist[0], verbose=verbose)

        # Approximation of SimulStartList for --boot
        watchpats = [
            self.templates["Pat:DC_IDLE"],
        ]
        for node in nodelist:
            watchpats.extend([
                self.templates["Pat:InfraUp"] % node,
                self.templates["Pat:PacemakerUp"] % node,
                self.templates["Pat:Local_started"] % node,
                self.templates["Pat:They_up"] % (nodelist[0], node),
            ])

        #   Start all the nodes - at about the same time...
        watch = LogWatcher(self.env["LogFileName"], watchpats, self.env["nodes"],
                           self.env["log_kind"], "fast-start",
                           self.env["dead_time"] + 10)
        watch.set_watch()

        if not self.start_cm(nodelist[0], verbose=verbose):
            return False

        for node in nodelist:
            self.start_cm_async(node, verbose=verbose)

        watch.look_for_all()
        if watch.unmatched:
            for regex in watch.unmatched:
                logging.log(f"Warn: Startup pattern not found: {regex}")

        if not self.cluster_stable():
            logging.log("Cluster did not stabilize")
            return False

        return True

    def stopall(self, nodelist=None, verbose=False, force=False):
        """Stop the cluster manager on every node in the cluster, or on every node in nodelist."""
        ret = True

        if not nodelist:
            nodelist = self.env["nodes"]

        for node in self.env["nodes"]:
            if self.expected_status[node] == "up" or force:
                if not self.stop_cm(node, verbose=verbose, force=force):
                    ret = False

        return ret

    def statall(self, nodelist=None):
        """Return the status of the cluster manager on every node in the cluster, or on every node in nodelist."""
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
        """Break communication between the target node and all other nodes in the cluster, or nodes."""
        if not nodes:
            nodes = self.env["nodes"]

        for node in nodes:
            if node == target:
                continue

            (rc, _) = self.rsh(target, self.templates["BreakCommCmd"] % node)
            if rc != 0:
                logging.log(f"Could not break the communication between {target} and {node}: {rc}")
                return False

            self.debug(f"Communication cut between {target} and {node}")

        return True

    def unisolate_node(self, target, nodes=None):
        """Re-establish communication between the target node and all other nodes in the cluster, or nodes."""
        if not nodes:
            nodes = self.env["nodes"]

        for node in nodes:
            if node == target:
                continue

            # Limit the amount of time we have asynchronous connectivity for
            # Restore both sides as simultaneously as possible
            self.rsh.call_async(target, self.templates["FixCommCmd"] % node)
            self.rsh.call_async(node, self.templates["FixCommCmd"] % target)
            self.debug(f"Communication restored between {target} and {node}")

    def prepare(self):
        """
        Finish initialization.

        Clear out the expected status and record the current status of every
        node in the cluster.
        """
        self.partitions_expected = 1
        for node in self.env["nodes"]:
            self.expected_status[node] = ""

            # This used to be conditional on whether SplitBrainTest was
            # allowed to run. SplitBrainTest is supposed to unisolate
            # the nodes, so this shouldn't be necessary here. However,
            # SplitBrainTest was flagged as "experimental" from 2009 to
            # 2025 and wasn't allowed to run by default. So uncomment
            # this if problems emerge.
            #
            # @COMPAT Delete this comment if no problems emerge after a
            # while.
            #
            # self.unisolate_node(node)

            self.stat_cm(node)

    def test_node_cm(self, node):
        """
        Check the status of a given node.

        Returns 0 if the node is down, 1 if the node is up but unstable, and 2
        if the node is up and stable.
        """
        watchpats = [
            "Current ping state: (S_IDLE|S_NOT_DC)",
            self.templates["Pat:NonDC_started"] % node,
            self.templates["Pat:DC_started"] % node,
        ]

        idle_watch = LogWatcher(self.env["LogFileName"], watchpats, [node],
                                self.env["log_kind"], "ClusterIdle")
        idle_watch.set_watch()

        (_, out) = self.rsh(node, self.templates["StatusCmd"] % node, verbose=1)

        if not out:
            out = ""
        else:
            out = out[0].strip()

        self.debug(f"Node {node} status: '{out}'")

        if out.find('ok') < 0:
            if self.expected_status[node] == "up":
                self.log(f"Node status for {node} is down but we think it should be {self.expected_status[node]}")

            self.expected_status[node] = "down"
            return 0

        if self.expected_status[node] == "down":
            self.log(f"Node status for {node} is up but we think it should be {self.expected_status[node]}: {out}")

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
            self.debug(f"Warn: Node {node} is unstable: {out}")
            return 1

        # Up and stable
        return 2

    def stat_cm(self, node):
        """Report the status of the cluster manager on a given node."""
        return self.test_node_cm(node) > 0

    # Being up and being stable is not the same question...
    def node_stable(self, node):
        """Return whether or not the given node is stable."""
        if self.test_node_cm(node) == 2:
            return True

        self.log(f"Warn: Node {node} not stable")
        return False

    def _partition_stable(self, nodes, timeout=None):
        """Return whether or not all nodes in the given partition are stable."""
        watchpats = [
            "Current ping state: S_IDLE",
            self.templates["Pat:DC_IDLE"],
        ]

        self.debug("Waiting for cluster stability...")

        if timeout is None:
            timeout = self.env["dead_time"]

        if len(nodes) < 3:
            self.debug("Cluster is inactive")
            return True

        idle_watch = LogWatcher(self.env["LogFileName"], watchpats, nodes.split(),
                                self.env["log_kind"], "ClusterStable", timeout)
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

        self.debug(f"Warn: Partition {nodes!r} not IDLE after {timeout}s")
        return False

    def cluster_stable(self, timeout=None, double_check=False):
        """Return whether or not all nodes in the cluster are stable."""
        partitions = self.find_partitions()

        for partition in partitions:
            if not self._partition_stable(partition, timeout):
                return False

        if not double_check:
            return True

        # Make sure we are really stable and that all resources,
        # including those that depend on transient node attributes,
        # are started if they were going to be
        time.sleep(5)
        for partition in partitions:
            if not self._partition_stable(partition, timeout):
                return False

        return True

    def is_node_dc(self, node, status_line=None):
        """
        Return whether or not the given node is the cluster DC.

        Check the given status_line, or query the cluster if None.
        """
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
        """Return a list of primitive resources active on the given node."""
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
        """Return a list of nodes on which the given resource is running."""
        resource_nodes = []
        for node in self.env["nodes"]:
            if self.expected_status[node] != "up":
                continue

            cmd = self.templates["RscRunning"] % rid
            (rc, lines) = self.rsh(node, cmd)

            if rc == 127:
                self.log(f"Command '{cmd}' failed. Binary or pacemaker-cts package not installed?")
                for line in lines:
                    self.log(f"Output: {line} ")

            elif rc == 0:
                resource_nodes.append(node)

        return resource_nodes

    def find_partitions(self):
        """
        Return a list of all partitions in the cluster.

        Each element of the list is itself a list of all active nodes in that
        partition.
        """
        ccm_partitions = []

        for node in self.env["nodes"]:
            if self.expected_status[node] != "up":
                self.debug(f"Node {node} is down... skipping")
                continue

            (_, out) = self.rsh(node, self.templates["PartitionCmd"], verbose=1)

            if not out:
                self.log(f"no partition details for {node}")
                continue

            partition = out[0].strip()

            if len(partition) <= 2:
                self.log(f"bad partition details for {node}")
                continue

            nodes = partition.split()
            nodes.sort()
            partition = ' '.join(nodes)

            found = 0
            for a_partition in ccm_partitions:
                if partition == a_partition:
                    found = 1

            if found == 0:
                self.debug(f"Adding partition from {node}: {partition}")
                ccm_partitions.append(partition)
            else:
                self.debug(f"Partition '{partition}' from {node} is consistent with existing entries")

        self.debug(f"Found partitions: {ccm_partitions!r}")
        return ccm_partitions

    def has_quorum(self, node_list):
        """Return whether or not the cluster has quorum."""
        # If we are auditing a partition, then one side will
        #   have quorum and the other not.
        # So the caller needs to tell us which we are checking
        # If no value for node_list is specified... assume all nodes
        if not node_list:
            node_list = self.env["nodes"]

        for node in node_list:
            if self.expected_status[node] != "up":
                continue

            (rc, quorum) = self.rsh(node, self.templates["QuorumCmd"], verbose=1)
            if rc != ExitStatus.OK:
                self.debug(f"WARN: Quorum check on {node} returned error ({rc})")
                continue

            quorum = quorum[0].strip()
            if quorum.find("1") != -1:
                return True
            if quorum.find("0") != -1:
                return False
            self.debug(f"WARN: Unexpected quorum test result from {node}:{quorum}")

        return False

    @property
    def components(self):
        """
        Return a list of all patterns that should be ignored for the cluster's components.

        This must be provided by all subclasses.
        """
        raise NotImplementedError

    def in_standby_mode(self, node):
        """Return whether or not the node is in Standby."""
        (_, out) = self.rsh(node, self.templates["StandbyQueryCmd"] % node, verbose=1)

        if not out:
            return False

        out = out[0].strip()
        self.debug(f"Standby result: {out}")
        return out == "on"

    def set_standby_mode(self, node, status):
        """
        Set node to Standby if status is True, or Active if status is False.

        Return whether the node is now in the requested status.
        """
        current_status = self.in_standby_mode(node)

        if current_status == status:
            return True

        if status:
            cmd = self.templates["StandbyCmd"] % (node, "on")
        else:
            cmd = self.templates["StandbyCmd"] % (node, "off")

        (rc, _) = self.rsh(node, cmd)
        return rc == 0

    def add_dummy_rsc(self, node, rid):
        """Add a dummy resource with the given ID to the given node."""
        rsc_xml = f""" '<resources>
                <primitive class=\"ocf\" id=\"{rid}\" provider=\"pacemaker\" type=\"Dummy\">
                    <operations>
                        <op id=\"{rid}-interval-10s\" interval=\"10s\" name=\"monitor\"/>
                    </operations>
                </primitive>
            </resources>'"""

        constraint_xml = f""" '<constraints>
                <rsc_location id=\"location-{rid}-{node}\" node=\"{node}\" rsc=\"{rid}\" score=\"INFINITY\"/>
            </constraints>'"""

        self.rsh(node, self.templates['CibAddXml'] % rsc_xml)
        self.rsh(node, self.templates['CibAddXml'] % constraint_xml)

    def remove_dummy_rsc(self, node, rid):
        """Remove the previously added dummy resource given by rid on the given node."""
        constraint = f"\"//rsc_location[@rsc='{rid}']\""
        rsc = f"\"//primitive[@id='{rid}']\""

        self.rsh(node, self.templates['CibDelXpath'] % constraint)
        self.rsh(node, self.templates['CibDelXpath'] % rsc)
