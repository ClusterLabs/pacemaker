""" Base classes for CTS tests """

__all__ = ["CTSTest", "RemoteDriver", "SimulStartLite", "SimulStopLite", "StartTest", "StopTest"]
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

import os
import re
import time
import subprocess
import tempfile

from pacemaker._cts.audits import AuditConstraint, AuditResource
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.patterns import PatternSelector
from pacemaker._cts.remote import RemoteFactory
from pacemaker._cts.timer import Timer
from pacemaker._cts.watcher import LogWatcher

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable
# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class CTSTest:
    '''
    A Cluster test.
    We implement the basic set of properties and behaviors for a generic
    cluster test.

    Cluster tests track their own statistics.
    We keep each of the kinds of counts we track as separate {name,value}
    pairs.
    '''

    def __init__(self, cm):
        # pylint: disable=invalid-name

        self.audits = []
        self.name = None
        self.templates = PatternSelector(cm["Name"])

        self.stats = { "auditfail": 0,
                      "calls": 0,
                      "failure": 0,
                      "skipped": 0,
                      "success": 0 }

        self._cm = cm
        self._env = EnvFactory().getInstance()
        self._r_o2cb = None
        self._r_ocfs2 = []
        self._rsh = RemoteFactory().getInstance()
        self._logger = LogFactory()
        self._timers = {}

        self.benchmark = True  # which tests to benchmark
        self.failed = False
        self.is_container = False
        self.is_experimental = False
        self.is_loop = False
        self.is_unsafe = False
        self.is_valgrind = False
        self.passed = True

    def log(self, args):
        self._logger.log(args)

    def debug(self, args):
        self._logger.debug(args)

    def get_timer(self, key="test"):
        try:
            return self._timers[key].start_time
        except KeyError:
            return 0

    def set_timer(self, key="test"):

        if key not in self._timers:
            self._timers[key] = Timer(self._logger, self.name, key)

        self._timers[key].start()
        return self._timers[key].start_time

    def log_timer(self, key="test"):
        if key not in self._timers:
            return

        elapsed = self._timers[key].elapsed
        self.debug("%s:%s runtime: %.2f" % (self.name, key, elapsed))
        del self._timers[key]

    def incr(self, name):
        if name not in self.stats:
            self.stats[name] = 0

        self.stats[name] += 1

        # Reset the test passed boolean
        if name == "calls":
            self.passed = True

    def failure(self, reason="none"):
        '''Increment the failure count'''

        self.passed = False
        self.incr("failure")
        self._logger.log(("Test %s" % self.name).ljust(35) + " FAILED: %s" % reason)

        return False

    def success(self):
        '''Increment the success count'''

        self.incr("success")
        return True

    def skipped(self):
        '''Increment the skipped count'''

        self.incr("skipped")
        return True

    def __call__(self, node):
        """ Perform the given test """

        raise NotImplementedError

    def audit(self):
        passed = 1

        for audit in self.audits:
            if not audit():
                self._logger.log("Internal %s Audit %s FAILED." % (self.name, audit.name))
                self.incr("auditfail")
                passed = 0

        return passed

    def setup(self, node):
        '''Setup the given test'''

        # node is used in subclasses
        # pylint: disable=unused-argument

        return self.success()

    def teardown(self, node):
        '''Tear down the given test'''

        # node is used in subclasses
        # pylint: disable=unused-argument

        return self.success()

    def create_watch(self, patterns, timeout, name=None):
        if not name:
            name = self.name

        return LogWatcher(self._env["LogFileName"], patterns, self._env["nodes"], self._env["LogWatcher"], name, timeout)

    def local_badnews(self, prefix, watch, local_ignore=None):
        errcount = 0
        if not prefix:
            prefix = "LocalBadNews:"

        ignorelist = [" CTS: ", prefix]

        if local_ignore:
            ignorelist += local_ignore

        while errcount < 100:
            match = watch.look(0)
            if match:
                add_err = True

                for ignore in ignorelist:
                    if add_err and re.search(ignore, match):
                        add_err = False

                if add_err:
                    self._logger.log("%s %s" % (prefix, match))
                    errcount += 1
            else:
                break
        else:
            self._logger.log("Too many errors!")

        watch.end()
        return errcount

    def is_applicable(self):
        return self.is_applicable_common()

    def is_applicable_common(self):
        '''Return True if we are applicable in the current test configuration'''

        if self.is_loop and not self._env["loop-tests"]:
            return False

        if self.is_unsafe and not self._env["unsafe-tests"]:
            return False

        if self.is_valgrind and not self._env["valgrind-tests"]:
            return False

        if self.is_experimental and not self._env["experimental-tests"]:
            return False

        if self.is_container and not self._env["container-tests"]:
            return False

        if self._env["benchmark"] and not self.benchmark:
            return False

        return True

    def _find_ocfs2_resources(self, node):
        self._r_o2cb = None
        self._r_ocfs2 = []

        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self._cm, line)

                if r.rtype == "o2cb" and r.parent != "NA":
                    self.debug("Found o2cb: %s" % self._r_o2cb)
                    self._r_o2cb = r.parent

            if re.search("^Constraint", line):
                c = AuditConstraint(self._cm, line)

                if c.type == "rsc_colocation" and c.target == self._r_o2cb:
                    self._r_ocfs2.append(c.rsc)

        self.debug("Found ocfs2 filesystems: %s" % self._r_ocfs2)
        return len(self._r_ocfs2)

    def can_run_now(self, node):
        """ Return True if we can meaningfully run right now """

        # node is used in subclasses
        # pylint: disable=unused-argument

        return True

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return []


class RemoteDriver(CTSTest):

    def __init__(self, cm):
        CTSTest.__init__(self,cm)
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
        self.failed = False
        self.fail_string = ""

        self._pcmk_started = False
        self._remote_node_added = False
        self._remote_rsc_added = False
        self._remote_use_reconnect_interval = self._env.random_gen.choice([True,False])

    def fail(self, msg):
        """ Mark test as failed. """

        self.failed = True

        # Always log the failure.
        self._logger.log(msg)

        # Use first failure as test status, as it's likely to be most useful.
        if not self.fail_string:
            self.fail_string = msg

    def _get_other_node(self, node):
        for othernode in self._env["nodes"]:
            if othernode == node:
                # we don't want to try and use the cib that we just shutdown.
                # find a cluster node that is not our soon to be remote-node.
                continue

            return othernode

    def _del_rsc(self, node, rsc):
        othernode = self._get_other_node(node)
        (rc, _) = self._rsh(othernode, "crm_resource -D -r %s -t primitive" % rsc)
        if rc != 0:
            self.fail("Removal of resource '%s' failed" % rsc)

    def _add_rsc(self, node, rsc_xml):
        othernode = self._get_other_node(node)
        (rc, _) = self._rsh(othernode, "cibadmin -C -o resources -X '%s'" % rsc_xml)
        if rc != 0:
            self.fail("resource creation failed")

    def _add_primitive_rsc(self, node):
        rsc_xml = """
<primitive class="ocf" id="%(node)s" provider="heartbeat" type="Dummy">
  <meta_attributes id="%(node)s-meta_attributes"/>
  <operations>
    <op id="%(node)s-monitor-interval-20s" interval="20s" name="monitor"/>
  </operations>
</primitive>""" % { "node": self._remote_rsc }

        self._add_rsc(node, rsc_xml)
        if not self.failed:
            self._remote_rsc_added = True

    def _add_connection_rsc(self, node):
        rsc_xml = """
<primitive class="ocf" id="%(node)s" provider="pacemaker" type="remote">
  <instance_attributes id="%(node)s-instance_attributes">
    <nvpair id="%(node)s-instance_attributes-server" name="server" value="%(server)s"/>
""" % { "node": self._remote_node, "server": node }

        if self._remote_use_reconnect_interval:
            # Set reconnect interval on resource
            rsc_xml += """
    <nvpair id="%s-instance_attributes-reconnect_interval" name="reconnect_interval" value="60s"/>
""" % self._remote_node

        rsc_xml += """
  </instance_attributes>
  <operations>
    <op id="%(node)s-start"       name="start"   interval="0"   timeout="120s"/>
    <op id="%(node)s-monitor-20s" name="monitor" interval="20s" timeout="45s"/>
  </operations>
</primitive>
""" % { "node": self._remote_node }

        self._add_rsc(node, rsc_xml)
        if not self.failed:
            self._remote_node_added = True

    def _disable_services(self, node):
        self._corosync_enabled = self._env.service_is_enabled(node, "corosync")
        if self._corosync_enabled:
            self._env.disable_service(node, "corosync")

        self._pacemaker_enabled = self._env.service_is_enabled(node, "pacemaker")
        if self._pacemaker_enabled:
            self._env.disable_service(node, "pacemaker")

    def _enable_services(self, node):
        if self._corosync_enabled:
            self._env.enable_service(node, "corosync")

        if self._pacemaker_enabled:
            self._env.enable_service(node, "pacemaker")

    def _stop_pcmk_remote(self, node):
        # disable pcmk remote
        for _ in range(10):
            (rc, _) = self._rsh(node, "service pacemaker_remote stop")
            if rc != 0:
                time.sleep(6)
            else:
                break

    def _start_pcmk_remote(self, node):
        for _ in range(10):
            (rc, _) = self._rsh(node, "service pacemaker_remote start")
            if rc != 0:
                time.sleep(6)
            else:
                self._pcmk_started = True
                break

    def _freeze_pcmk_remote(self, node):
        """ Simulate a Pacemaker Remote daemon failure. """

        # We freeze the process.
        self._rsh(node, "killall -STOP pacemaker-remoted")

    def _resume_pcmk_remote(self, node):
        # We resume the process.
        self._rsh(node, "killall -CONT pacemaker-remoted")

    def _start_metal(self, node):
        # Cluster nodes are reused as remote nodes in remote tests. If cluster
        # services were enabled at boot, in case the remote node got fenced, the
        # cluster node would join instead of the expected remote one. Meanwhile
        # pacemaker_remote would not be able to start. Depending on the chances,
        # the situations might not be able to be orchestrated gracefully any more.
        #
        # Temporarily disable any enabled cluster serivces.
        self._disable_services(node)

        # make sure the resource doesn't already exist for some reason
        self._rsh(node, "crm_resource -D -r %s -t primitive" % self._remote_rsc)
        self._rsh(node, "crm_resource -D -r %s -t primitive" % self._remote_node)

        if not self._stop(node):
            self.fail("Failed to shutdown cluster node %s" % node)
            return

        self._start_pcmk_remote(node)

        if not self._pcmk_started:
            self.fail("Failed to start pacemaker_remote on node %s" % node)
            return

        # Convert node to baremetal now that it has shutdown the cluster stack
        pats = [ self.templates["Pat:RscOpOK"] % ("start", self._remote_node),
                 self.templates["Pat:DC_IDLE"] ]
        watch = self.create_watch(pats, 120)
        watch.set_watch()

        self._add_connection_rsc(node)

        with Timer(self._logger, self.name, "remoteMetalInit"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def migrate_connection(self, node):
        if self.failed:
            return

        pats = [ self.templates["Pat:RscOpOK"] % ("migrate_to", self._remote_node),
                 self.templates["Pat:RscOpOK"] % ("migrate_from", self._remote_node),
                 self.templates["Pat:DC_IDLE"] ]

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        (rc, _) = self._rsh(node, "crm_resource -M -r %s" % self._remote_node, verbose=1)
        if rc != 0:
            self.fail("failed to move remote node connection resource")
            return

        with Timer(self._logger, self.name, "remoteMetalMigrate"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def fail_rsc(self, node):
        if self.failed:
            return

        watchpats = [ self.templates["Pat:RscRemoteOpOK"] % ("stop", self._remote_rsc, self._remote_node),
                      self.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node),
                      self.templates["Pat:DC_IDLE"] ]

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        self.debug("causing dummy rsc to fail.")

        self._rsh(node, "rm -f /var/run/resource-agents/Dummy*")

        with Timer(self._logger, self.name, "remoteRscFail"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns during rsc fail: %s" % watch.unmatched)

    def fail_connection(self, node):
        if self.failed:
            return

        watchpats = [ self.templates["Pat:Fencing_ok"] % self._remote_node,
                      self.templates["Pat:NodeFenced"] % self._remote_node ]

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        # freeze the pcmk remote daemon. this will result in fencing
        self.debug("Force stopped active remote node")
        self._freeze_pcmk_remote(node)

        self.debug("Waiting for remote node to be fenced.")

        with Timer(self._logger, self.name, "remoteMetalFence"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)
            return

        self.debug("Waiting for the remote node to come back up")
        self._cm.ns.wait_for_node(node, 120)

        pats = [ self.templates["Pat:RscOpOK"] % ("start", self._remote_node) ]

        if self._remote_rsc_added:
            pats.append(self.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node))

        watch = self.create_watch([], 240)
        watch.set_watch()

        # start the remote node again watch it integrate back into cluster.
        self._start_pcmk_remote(node)
        if not self._pcmk_started:
            self.fail("Failed to start pacemaker_remote on node %s" % node)
            return

        self.debug("Waiting for remote node to rejoin cluster after being fenced.")

        with Timer(self._logger, self.name, "remoteMetalRestart"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def _add_dummy_rsc(self, node):
        if self.failed:
            return

        # verify we can put a resource on the remote node
        pats = [ self.templates["Pat:RscRemoteOpOK"] % ("start", self._remote_rsc, self._remote_node),
                 self.templates["Pat:DC_IDLE"] ]

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        # Add a resource that must live on remote-node
        self._add_primitive_rsc(node)

        # force that rsc to prefer the remote node.
        (rc, _) = self._cm.rsh(node, "crm_resource -M -r %s -N %s -f" % (self._remote_rsc, self._remote_node), verbose=1)
        if rc != 0:
            self.fail("Failed to place remote resource on remote node.")
            return

        with Timer(self._logger, self.name, "remoteMetalRsc"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def test_attributes(self, node):
        if self.failed:
            return

        # This verifies permanent attributes can be set on a remote-node. It also
        # verifies the remote-node can edit its own cib node section remotely.
        (rc, line) = self._cm.rsh(node, "crm_attribute -l forever -n testattr -v testval -N %s" % self._remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to set remote-node attribute. rc:%s output:%s" % (rc, line))
            return

        (rc, _) = self._cm.rsh(node, "crm_attribute -l forever -n testattr -q -N %s" % self._remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to get remote-node attribute")
            return

        (rc, _) = self._cm.rsh(node, "crm_attribute -l forever -n testattr -D -N %s" % self._remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to delete remote-node attribute")

    def cleanup_metal(self, node):
        self._enable_services(node)

        if not self._pcmk_started:
            return

        pats = [ ]

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        if self._remote_rsc_added:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self._remote_rsc))

        if self._remote_node_added:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self._remote_node))

        with Timer(self._logger, self.name, "remoteMetalCleanup"):
            self._resume_pcmk_remote(node)

            if self._remote_rsc_added:
                # Remove dummy resource added for remote node tests
                self.debug("Cleaning up dummy rsc put on remote node")
                self._rsh(self._get_other_node(node), "crm_resource -U -r %s" % self._remote_rsc)
                self._del_rsc(node, self._remote_rsc)

            if self._remote_node_added:
                # Remove remote node's connection resource
                self.debug("Cleaning up remote node connection resource")
                self._rsh(self._get_other_node(node), "crm_resource -U -r %s" % self._remote_node)
                self._del_rsc(node, self._remote_node)

            watch.look_for_all()

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

        self._stop_pcmk_remote(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        if self._remote_node_added:
            # Remove remote node itself
            self.debug("Cleaning up node entry for remote node")
            self._rsh(self._get_other_node(node), "crm_node --force --remove %s" % self._remote_node)

    def _setup_env(self, node):
        self._remote_node = "remote-%s" % node

        # we are assuming if all nodes have a key, that it is
        # the right key... If any node doesn't have a remote
        # key, we regenerate it everywhere.
        if self._rsh.exists_on_all("/etc/pacemaker/authkey", self._env["nodes"]):
            return

        # create key locally
        (handle, keyfile) = tempfile.mkstemp(".cts")
        os.close(handle)
        subprocess.check_call(["dd", "if=/dev/urandom", "of=%s" % keyfile, "bs=4096", "count=1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # sync key throughout the cluster
        for n in self._env["nodes"]:
            self._rsh(n, "mkdir -p --mode=0750 /etc/pacemaker")
            self._rsh.copy(keyfile, "root@%s:/etc/pacemaker/authkey" % n)
            self._rsh(n, "chgrp haclient /etc/pacemaker /etc/pacemaker/authkey")
            self._rsh(n, "chmod 0640 /etc/pacemaker/authkey")

        os.unlink(keyfile)

    def is_applicable(self):
        if not self.is_applicable_common():
            return False

        for node in self._env["nodes"]:
            (rc, _) = self._rsh(node, "which pacemaker-remoted >/dev/null 2>&1")
            if rc != 0:
                return False

        return True

    def start_new_test(self, node):
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
        """ Perform the given test """

        raise NotImplementedError

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"""is running on remote.*which isn't allowed""",
                 r"""Connection terminated""",
                 r"""Could not send remote""" ]


class SimulStartLite(CTSTest):
    '''Start any stopped nodes ~ simultaneously'''

    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStartLite"

    def __call__(self, dummy):
        '''Perform the 'SimulStartList' setup work. '''

        self.incr("calls")
        self.debug("Setup: %s" % self.name)

        # We ignore the "node" parameter...
        node_list = []
        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "down":
                self.incr("WasStopped")
                node_list.append(node)

        self.set_timer()
        while len(node_list) > 0:
            # Repeat until all nodes come up
            uppat = self.templates["Pat:NonDC_started"]
            if self._cm.upcount() == 0:
                uppat = self.templates["Pat:Local_started"]

            watchpats = [ self.templates["Pat:DC_IDLE"] ]
            for node in node_list:
                watchpats.extend([uppat % node,
                                  self.templates["Pat:InfraUp"] % node,
                                  self.templates["Pat:PacemakerUp"] % node])

            #   Start all the nodes - at about the same time...
            watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
            watch.set_watch()

            stonith = self._cm.prepare_fencing_watcher(self.name)

            for node in node_list:
                self._cm.StartaCMnoBlock(node)

            watch.look_for_all()

            node_list = self._cm.fencing_cleanup(self.name, stonith)

            if node_list is None:
                return self.failure("Cluster did not stabilize")

            # Remove node_list messages from watch.unmatched
            for node in node_list:
                self._logger.debug("Dealing with stonith operations for %s" % node_list)
                if watch.unmatched:
                    try:
                        watch.unmatched.remove(uppat % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (uppat % node))

                    try:
                        watch.unmatched.remove(self.templates["Pat:InfraUp"] % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (self.templates["Pat:InfraUp"] % node))

                    try:
                        watch.unmatched.remove(self.templates["Pat:PacemakerUp"] % node)
                    except ValueError:
                        self.debug("Already matched: %s" % (self.templates["Pat:PacemakerUp"] % node))

            if watch.unmatched:
                for regex in watch.unmatched:
                    self._logger.log ("Warn: Startup pattern not found: %s" % regex)

            if not self._cm.cluster_stable():
                return self.failure("Cluster did not stabilize")

        did_fail = False
        unstable = []
        for node in self._env["nodes"]:
            if self._cm.StataCM(node) == 0:
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure("Unstarted nodes exist: %s" % unstable)

        unstable = []
        for node in self._env["nodes"]:
            if not self._cm.node_stable(node):
                did_fail = True
                unstable.append(node)

        if did_fail:
            return self.failure("Unstable cluster nodes exist: %s" % unstable)

        return self.success()

    def is_applicable(self):
        '''SimulStartLite is a setup test and never applicable'''

        return False


class SimulStopLite(CTSTest):
    '''Stop any active nodes ~ simultaneously'''

    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStopLite"

    def __call__(self, dummy):
        '''Perform the 'SimulStopLite' setup work. '''

        self.incr("calls")
        self.debug("Setup: %s" % self.name)

        # We ignore the "node" parameter...
        watchpats = []

        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self.incr("WasStarted")
                watchpats.append(self.templates["Pat:We_stopped"] % node)

        if len(watchpats) == 0:
            return self.success()

        # Stop all the nodes - at about the same time...
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)

        watch.set_watch()
        self.set_timer()
        for node in self._env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self._cm.StopaCMnoBlock(node)

        if watch.look_for_all():
            # Make sure they're completely down with no residule
            for node in self._env["nodes"]:
                self._rsh(node, self.templates["StopCmd"])

            return self.success()

        did_fail = False
        up_nodes = []
        for node in self._env["nodes"]:
            if self._cm.StataCM(node) == 1:
                did_fail = True
                up_nodes.append(node)

        if did_fail:
            return self.failure("Active nodes exist: %s" % up_nodes)

        self._logger.log("Warn: All nodes stopped but CTS didn't detect: %s" % watch.unmatched)
        return self.failure("Missing log message: %s " % watch.unmatched)

    def is_applicable(self):
        '''SimulStopLite is a setup test and never applicable'''

        return False


class StartTest(CTSTest):
    '''Start (activate) the cluster manager on a node'''

    def __init__(self, cm, debug=None):
        CTSTest.__init__(self,cm)
        self.name = "Start"
        self.debug = debug

    def __call__(self, node):
        '''Perform the 'start' test. '''

        self.incr("calls")

        if self._cm.upcount() == 0:
            self.incr("us")
        else:
            self.incr("them")

        if self._cm.ShouldBeStatus[node] != "down":
            return self.skipped()

        if self._cm.StartaCM(node):
            return self.success()

        return self.failure("Startup %s on node %s failed"
                            % (self._env["Name"], node))


class StopTest(CTSTest):
    '''Stop (deactivate) the cluster manager on a node'''

    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name = "Stop"

    def __call__(self, node):
        '''Perform the 'stop' test. '''

        self.incr("calls")
        if self._cm.ShouldBeStatus[node] != "up":
            return self.skipped()

        # Technically we should always be able to notice ourselves stopping
        patterns = [ self.templates["Pat:We_stopped"] % node ]

        # Any active node needs to notice this one left
        # (note that this won't work if we have multiple partitions)
        for other in self._env["nodes"]:
            if self._cm.ShouldBeStatus[other] == "up" and other != node:
                patterns.append(self.templates["Pat:They_stopped"] %(other, self._cm.key_for_node(node)))

        watch = self.create_watch(patterns, self._env["DeadTime"])
        watch.set_watch()

        if node == self._cm.OurNode:
            self.incr("us")
        else:
            if self._cm.upcount() <= 1:
                self.incr("all")
            else:
                self.incr("them")

        self._cm.StopaCM(node)
        watch.look_for_all()

        failreason = None
        unmatched_str = "||"

        if watch.unmatched:
            (_, output) = self._rsh(node, "/bin/ps axf", verbose=1)
            for line in output:
                self.debug(line)

            (_, output) = self._rsh(node, "/usr/sbin/dlm_tool dump 2>/dev/null", verbose=1)
            for line in output:
                self.debug(line)

            for regex in watch.unmatched:
                self._logger.log ("ERROR: Shutdown pattern not found: %s" % regex)
                unmatched_str +=  "%s||" % regex
                failreason = "Missing shutdown pattern"

        self._cm.cluster_stable(self._env["DeadTime"])

        if not watch.unmatched or self._cm.upcount() == 0:
            return self.success()

        if len(watch.unmatched) >= self._cm.upcount():
            return self.failure("no match against (%s)" % unmatched_str)

        if failreason is None:
            return self.success()

        return self.failure(failreason)
