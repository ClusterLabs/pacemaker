"""Base classes for CTS tests."""

__all__ = ["RemoteDriver"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import os
import time
import subprocess
import tempfile

from pacemaker._cts import logging
from pacemaker._cts.CTS import Process
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.tests.stoptest import StopTest
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable


class RemoteDriver(CTSTest):
    """
    A specialized base class for cluster tests that run on Pacemaker Remote nodes.

    This builds on top of CTSTest to provide methods for starting and stopping
    services and resources, and managing remote nodes.  This is still just an
    abstract class -- specific tests need to implement their own specialized
    behavior.
    """

    def __init__(self, cm):
        """
        Create a new RemoteDriver instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.name = "RemoteDriver"

        self._corosync_enabled = False
        self._pacemaker_enabled = False
        self._remote_node = None
        self._remote_rsc = "remote-rsc"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)
        self._stop = StopTest(cm)

        self.reset()

    def reset(self):
        """Reset the state of this test back to what it was before the test was run."""
        self.failed = False
        self.fail_string = ""

        self._pcmk_started = False
        self._remote_node_added = False
        self._remote_rsc_added = False
        self._remote_use_reconnect_interval = self._env.random_gen.choice([True, False])

    def fail(self, msg):
        """Mark test as failed."""
        self.failed = True

        # Always log the failure.
        logging.log(msg)

        # Use first failure as test status, as it's likely to be most useful.
        if not self.fail_string:
            self.fail_string = msg

    def _get_other_node(self, node):
        """
        Get the first cluster node out of the environment that is not the given node.

        Typically, this is used to find some node that will still be active that
        we can run cluster commands on.
        """
        for othernode in self._env["nodes"]:
            if othernode == node:
                # we don't want to try and use the cib that we just shutdown.
                # find a cluster node that is not our soon to be remote-node.
                continue

            return othernode

    def _del_rsc(self, node, rsc):
        """
        Delete the given named resource from the cluster.

        The given `node` is the cluster node on which we should *not* run the
        delete command.
        """
        othernode = self._get_other_node(node)
        (rc, _) = self._rsh(othernode, f"crm_resource -D -r {rsc} -t primitive")
        if rc != 0:
            self.fail(f"Removal of resource '{rsc}' failed")

    def _add_rsc(self, node, rsc_xml):
        """
        Add a resource given in XML format to the cluster.

        The given `node` is the cluster node on which we should *not* run the
        add command.
        """
        othernode = self._get_other_node(node)
        (rc, _) = self._rsh(othernode, f"cibadmin -C -o resources -X '{rsc_xml}'")
        if rc != 0:
            self.fail("resource creation failed")

    def _add_primitive_rsc(self, node):
        """
        Add a primitive heartbeat resource for the remote node to the cluster.

        The given `node` is the cluster node on which we should *not* run the
        add command.
        """
        rsc_xml = f"""
<primitive class="ocf" id="{self._remote_rsc}" provider="heartbeat" type="Dummy">
  <meta_attributes id="{self._remote_rsc}-meta_attributes"/>
  <operations>
    <op id="{self._remote_rsc}-monitor-interval-20s" interval="20s" name="monitor"/>
  </operations>
</primitive>"""

        self._add_rsc(node, rsc_xml)
        if not self.failed:
            self._remote_rsc_added = True

    def _add_connection_rsc(self, node):
        """
        Add a primitive connection resource for the remote node to the cluster.

        The given `node` is the cluster node on which we should *not* run the
        add command.
        """
        rsc_xml = f"""
<primitive class="ocf" id="{self._remote_node}" provider="pacemaker" type="remote">
  <instance_attributes id="{self._remote_node}-instance_attributes">
    <nvpair id="{self._remote_node}-instance_attributes-server" name="server" value="{node}"/>
"""

        if self._remote_use_reconnect_interval:
            # Set reconnect interval on resource
            rsc_xml += f"""
    <nvpair id="{self._remote_node}-instance_attributes-reconnect_interval" name="reconnect_interval" value="60s"/>
"""

        rsc_xml += f"""
  </instance_attributes>
  <operations>
    <op id="{self._remote_node}-start"       name="start"   interval="0"   timeout="120s"/>
    <op id="{self._remote_node}-monitor-20s" name="monitor" interval="20s" timeout="45s"/>
  </operations>
</primitive>
"""

        self._add_rsc(node, rsc_xml)
        if not self.failed:
            self._remote_node_added = True

    def _disable_services(self, node):
        """Disable the corosync and pacemaker services on the given node."""
        self._corosync_enabled = self._env.service_is_enabled(node, "corosync")
        if self._corosync_enabled:
            self._env.disable_service(node, "corosync")

        self._pacemaker_enabled = self._env.service_is_enabled(node, "pacemaker")
        if self._pacemaker_enabled:
            self._env.disable_service(node, "pacemaker")

    def _enable_services(self, node):
        """Enable the corosync and pacemaker services on the given node."""
        if self._corosync_enabled:
            self._env.enable_service(node, "corosync")

        if self._pacemaker_enabled:
            self._env.enable_service(node, "pacemaker")

    def _stop_pcmk_remote(self, node):
        """Stop the Pacemaker Remote service on the given node."""
        for _ in range(10):
            (rc, _) = self._rsh(node, "service pacemaker_remote stop")
            if rc != 0:
                time.sleep(6)
            else:
                break

    def _start_pcmk_remote(self, node):
        """Start the Pacemaker Remote service on the given node."""
        for _ in range(10):
            (rc, _) = self._rsh(node, "service pacemaker_remote start")
            if rc != 0:
                time.sleep(6)
            else:
                self._pcmk_started = True
                break

    def _freeze_pcmk_remote(self, node):
        """Simulate a Pacemaker Remote daemon failure."""
        Process(self._cm, "pacemaker-remoted").signal("STOP", node)

    def _resume_pcmk_remote(self, node):
        """Simulate the Pacemaker Remote daemon recovering."""
        Process(self._cm, "pacemaker-remoted").signal("CONT", node)

    def _start_metal(self, node):
        """
        Set up a Pacemaker Remote configuration.

        Remove any existing connection resources or nodes.  Start the
        pacemaker_remote service.  Create a connection resource.
        """
        # Cluster nodes are reused as remote nodes in remote tests. If cluster
        # services were enabled at boot, in case the remote node got fenced, the
        # cluster node would join instead of the expected remote one. Meanwhile
        # pacemaker_remote would not be able to start. Depending on the chances,
        # the situations might not be able to be orchestrated gracefully any more.
        #
        # Temporarily disable any enabled cluster serivces.
        self._disable_services(node)

        # make sure the resource doesn't already exist for some reason
        self._rsh(node, f"crm_resource -D -r {self._remote_rsc} -t primitive")
        self._rsh(node, f"crm_resource -D -r {self._remote_node} -t primitive")

        if not self._stop(node):
            self.fail(f"Failed to shutdown cluster node {node}")
            return

        self._start_pcmk_remote(node)

        if not self._pcmk_started:
            self.fail(f"Failed to start pacemaker_remote on node {node}")
            return

        # Convert node to baremetal now that it has shutdown the cluster stack
        pats = []
        watch = self.create_watch(pats, 120)
        watch.set_watch()

        pats.extend([
            self._cm.templates["Pat:RscOpOK"] % ("start", self._remote_node),
            self._cm.templates["Pat:DC_IDLE"]
        ])

        self._add_connection_rsc(node)

        with Timer(self.name, "remoteMetalInit"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")

    def migrate_connection(self, node):
        """Move the remote connection resource to any other available node."""
        if self.failed:
            return

        pats = [
            self._cm.templates["Pat:RscOpOK"] % ("migrate_to", self._remote_node),
            self._cm.templates["Pat:RscOpOK"] % ("migrate_from", self._remote_node),
            self._cm.templates["Pat:DC_IDLE"]
        ]

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        (rc, _) = self._rsh(node, f"crm_resource -M -r {self._remote_node}", verbose=1)
        if rc != 0:
            self.fail("failed to move remote node connection resource")
            return

        with Timer(self.name, "remoteMetalMigrate"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")

    def fail_rsc(self, node):
        """
        Cause the dummy resource running on a Pacemaker Remote node to fail.

        Verify that the failure is logged correctly.
        """
        if self.failed:
            return

        watchpats = [
            self._cm.templates["Pat:RscRemoteOpOK"] % ("stop", self._remote_rsc, self._remote_node),
            self._cm.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node),
            self._cm.templates["Pat:DC_IDLE"]
        ]

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        self.debug("causing dummy rsc to fail.")

        self._rsh(node, "rm -f /var/run/resource-agents/Dummy*")

        with Timer(self.name, "remoteRscFail"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns during rsc fail: {watch.unmatched}")

    def fail_connection(self, node):
        """
        Cause the remote connection resource to fail.

        Verify that the node is fenced and the connection resource is restarted
        on another node.
        """
        if self.failed:
            return

        watchpats = [
            self._cm.templates["Pat:Fencing_ok"] % self._remote_node,
            self._cm.templates["Pat:NodeFenced"] % self._remote_node
        ]

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        # freeze the pcmk remote daemon. this will result in fencing
        self.debug("Force stopped active remote node")
        self._freeze_pcmk_remote(node)

        self.debug("Waiting for remote node to be fenced.")

        with Timer(self.name, "remoteMetalFence"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")
            return

        self.debug("Waiting for the remote node to come back up")
        self._cm.ns.wait_for_node(node, 120)

        pats = []

        watch = self.create_watch(pats, 240)
        watch.set_watch()

        pats.append(self._cm.templates["Pat:RscOpOK"] % ("start", self._remote_node))

        if self._remote_rsc_added:
            pats.append(self._cm.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node))

        # start the remote node again watch it integrate back into cluster.
        self._start_pcmk_remote(node)
        if not self._pcmk_started:
            self.fail(f"Failed to start pacemaker_remote on node {node}")
            return

        self.debug("Waiting for remote node to rejoin cluster after being fenced.")

        with Timer(self.name, "remoteMetalRestart"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")

    def _add_dummy_rsc(self, node):
        """Add a dummy resource that runs on the Pacemaker Remote node."""
        if self.failed:
            return

        # verify we can put a resource on the remote node
        pats = []
        watch = self.create_watch(pats, 120)
        watch.set_watch()

        pats.extend([
            self._cm.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node),
            self._cm.templates["Pat:DC_IDLE"]
        ])

        # Add a resource that must live on remote-node
        self._add_primitive_rsc(node)

        # force that rsc to prefer the remote node.
        (rc, _) = self._cm.rsh(node, f"crm_resource -M -r {self._remote_rsc} -N {self._remote_node} -f", verbose=1)
        if rc != 0:
            self.fail("Failed to place remote resource on remote node.")
            return

        with Timer(self.name, "remoteMetalRsc"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")

    def test_attributes(self, node):
        """Verify that attributes can be set on the Pacemaker Remote node."""
        if self.failed:
            return

        # This verifies permanent attributes can be set on a remote-node. It also
        # verifies the remote-node can edit its own cib node section remotely.
        (rc, line) = self._cm.rsh(node, f"crm_attribute -l forever -n testattr -v testval -N {self._remote_node}", verbose=1)
        if rc != 0:
            self.fail(f"Failed to set remote-node attribute. rc:{rc} output:{line}")
            return

        (rc, _) = self._cm.rsh(node, f"crm_attribute -l forever -n testattr -q -N {self._remote_node}", verbose=1)
        if rc != 0:
            self.fail("Failed to get remote-node attribute")
            return

        (rc, _) = self._cm.rsh(node, f"crm_attribute -l forever -n testattr -D -N {self._remote_node}", verbose=1)
        if rc != 0:
            self.fail("Failed to delete remote-node attribute")

    def cleanup_metal(self, node):
        """
        Clean up the Pacemaker Remote node configuration previously created by _setup_metal.

        Stop and remove dummy resources and connection resources.  Stop the
        pacemaker_remote service.  Remove the remote node itself.
        """
        self._enable_services(node)

        if not self._pcmk_started:
            return

        pats = []

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        if self._remote_rsc_added:
            pats.append(self._cm.templates["Pat:RscOpOK"] % ("stop", self._remote_rsc))

        if self._remote_node_added:
            pats.append(self._cm.templates["Pat:RscOpOK"] % ("stop", self._remote_node))

        with Timer(self.name, "remoteMetalCleanup"):
            self._resume_pcmk_remote(node)

            if self._remote_rsc_added:
                # Remove dummy resource added for remote node tests
                self.debug("Cleaning up dummy rsc put on remote node")
                self._rsh(self._get_other_node(node), f"crm_resource -U -r {self._remote_rsc}")
                self._del_rsc(node, self._remote_rsc)

            if self._remote_node_added:
                # Remove remote node's connection resource
                self.debug("Cleaning up remote node connection resource")
                self._rsh(self._get_other_node(node), f"crm_resource -U -r {self._remote_node}")
                self._del_rsc(node, self._remote_node)

            watch.look_for_all()

        if watch.unmatched:
            self.fail(f"Unmatched patterns: {watch.unmatched}")

        self._stop_pcmk_remote(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        if self._remote_node_added:
            # Remove remote node itself
            self.debug("Cleaning up node entry for remote node")
            self._rsh(self._get_other_node(node), f"crm_node --force --remove {self._remote_node}")

    def _setup_env(self, node):
        """
        Set up the environment to allow Pacemaker Remote to function.

        This involves generating a key and copying it to all nodes in the cluster.
        """
        self._remote_node = f"remote-{node}"

        # we are assuming if all nodes have a key, that it is
        # the right key... If any node doesn't have a remote
        # key, we regenerate it everywhere.
        if self._rsh.exists_on_all("/etc/pacemaker/authkey", self._env["nodes"]):
            return

        # create key locally
        (handle, keyfile) = tempfile.mkstemp(".cts")
        os.close(handle)
        subprocess.check_call(["dd", "if=/dev/urandom", f"of={keyfile}", "bs=4096", "count=1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # sync key throughout the cluster
        for n in self._env["nodes"]:
            self._rsh(n, "mkdir -p --mode=0750 /etc/pacemaker")
            self._rsh.copy(keyfile, f"root@{n}:/etc/pacemaker/authkey")
            self._rsh(n, "chgrp haclient /etc/pacemaker /etc/pacemaker/authkey")
            self._rsh(n, "chmod 0640 /etc/pacemaker/authkey")

        os.unlink(keyfile)

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        if not CTSTest.is_applicable(self):
            return False

        for node in self._env["nodes"]:
            (rc, _) = self._rsh(node, "which pacemaker-remoted >/dev/null 2>&1")
            if rc != 0:
                return False

        return True

    def start_new_test(self, node):
        """Prepare a remote test for running by setting up its environment and resources."""
        self.incr("calls")
        self.reset()

        ret = self._startall(None)
        if not ret:
            return self.failure("setup failed: could not start all nodes")

        self._setup_env(node)
        self._start_metal(node)
        self._add_dummy_rsc(node)
        return True

    def __call__(self, node):
        """Perform this test."""
        raise NotImplementedError

    @property
    def errors_to_ignore(self):
        """Return list of errors which should be ignored."""
        return [
            r"""is running on remote.*which isn't allowed""",
            r"""Connection terminated""",
            r"""Could not send remote"""
        ]
