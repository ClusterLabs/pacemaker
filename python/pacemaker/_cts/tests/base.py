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
        self.Stats = {"calls":0
        ,        "success":0
        ,        "failure":0
        ,        "skipped":0
        ,        "auditfail":0}

        self.CM = cm
        self.Env = EnvFactory().getInstance()
        self.rsh = RemoteFactory().getInstance()
        self.logger = LogFactory()
        self.templates = PatternSelector(cm["Name"])
        self.Audits = []
        self.timer = {}  # timers

        self.benchmark = True  # which tests to benchmark
        self.failed = False
        self.is_container = False
        self.is_experimental = False
        self.is_loop = False
        self.is_unsafe = False
        self.is_valgrind = False
        self.passed = True

    def log(self, args):
        self.logger.log(args)

    def debug(self, args):
        self.logger.debug(args)

    def has_key(self, key):
        return key in self.Stats

    def __setitem__(self, key, value):
        self.Stats[key] = value

    def __getitem__(self, key):
        if str(key) == "0":
            raise ValueError("Bad call to 'foo in X', should reference 'foo in X.Stats' instead")

        if key in self.Stats:
            return self.Stats[key]
        return None

    def log_mark(self, msg):
        self.debug("MARK: test %s %s %d" % (self.name,msg,time.time()))

    def get_timer(self,key = "test"):
        try:
            return self.timer[key]
        except:
            return 0

    def set_timer(self,key = "test"):
        self.timer[key] = time.time()
        return self.timer[key]

    def log_timer(self,key = "test"):
        elapsed = 0
        if key in self.timer:
            elapsed = time.time() - self.timer[key]
            s = key == "test" and self.name or "%s:%s" % (self.name,key)
            self.debug("%s runtime: %.2f" % (s, elapsed))
            del self.timer[key]
        return elapsed

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not name in self.Stats:
            self.Stats[name] = 0
        self.Stats[name] += 1

        # Reset the test passed boolean
        if name == "calls":
            self.passed = True

    def failure(self, reason="none"):
        '''Increment the failure count'''
        self.passed = False
        self.incr("failure")
        self.logger.log(("Test %s" % self.name).ljust(35) + " FAILED: %s" % reason)
        return None

    def success(self):
        '''Increment the success count'''
        self.incr("success")
        return 1

    def skipped(self):
        '''Increment the skipped count'''
        self.incr("skipped")
        return 1

    def __call__(self, node):
        '''Perform the given test'''
        raise ValueError("Abstract Class member (__call__)")

    def audit(self):
        passed = 1
        if len(self.Audits) > 0:
            for audit in self.Audits:
                if not audit():
                    self.logger.log("Internal %s Audit %s FAILED." % (self.name, audit.name))
                    self.incr("auditfail")
                    passed = 0
        return passed

    def setup(self, node):
        '''Setup the given test'''
        return self.success()

    def teardown(self, node):
        '''Tear down the given test'''
        return self.success()

    def create_watch(self, patterns, timeout, name=None):
        if not name:
            name = self.name
        return LogWatcher(self.Env["LogFileName"], patterns, self.Env["nodes"], self.Env["LogWatcher"], name, timeout)

    def local_badnews(self, prefix, watch, local_ignore=[]):
        errcount = 0
        if not prefix:
            prefix = "LocalBadNews:"

        ignorelist = []
        ignorelist.append(" CTS: ")
        ignorelist.append(prefix)
        ignorelist.extend(local_ignore)

        while errcount < 100:
            match = watch.look(0)
            if match:
                add_err = 1
                for ignore in ignorelist:
                    if add_err == 1 and re.search(ignore, match):
                        add_err = 0
                if add_err == 1:
                    self.logger.log(prefix + " " + match)
                    errcount += 1
            else:
                break
        else:
            self.logger.log("Too many errors!")

        watch.end()
        return errcount

    def is_applicable(self):
        return self.is_applicable_common()

    def is_applicable_common(self):
        '''Return True if we are applicable in the current test configuration'''

        if self.is_loop and not self.Env["loop-tests"]:
            return False

        if self.is_unsafe and not self.Env["unsafe-tests"]:
            return False

        if self.is_valgrind and not self.Env["valgrind-tests"]:
            return False

        if self.is_experimental and not self.Env["experimental-tests"]:
            return False

        if self.is_container and not self.Env["container-tests"]:
            return False

        if self.Env["benchmark"] and not self.benchmark:
            return False

        return True

    def find_ocfs2_resources(self, node):
        self.r_o2cb = None
        self.r_ocfs2 = []

        (_, lines) = self.rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self.CM, line)
                if r.rtype == "o2cb" and r.parent != "NA":
                    self.debug("Found o2cb: %s" % self.r_o2cb)
                    self.r_o2cb = r.parent
            if re.search("^Constraint", line):
                c = AuditConstraint(self.CM, line)
                if c.type == "rsc_colocation" and c.target == self.r_o2cb:
                    self.r_ocfs2.append(c.rsc)

        self.debug("Found ocfs2 filesystems: %s" % repr(self.r_ocfs2))
        return len(self.r_ocfs2)

    def canrunnow(self, node):
        '''Return TRUE if we can meaningfully run right now'''
        return 1

    def errorstoignore(self):
        '''Return list of errors which are 'normal' and should be ignored'''
        return []


class RemoteDriver(CTSTest):

    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = self.__class__.__name__
        self.start = StartTest(cm)
        self.startall = SimulStartLite(cm)
        self.stop = StopTest(cm)
        self.remote_rsc = "remote-rsc"
        self.cib_cmd = """cibadmin -C -o %s -X '%s' """
        self.reset()

    def reset(self):
        self.pcmk_started = 0
        self.failed = False
        self.fail_string = ""
        self.remote_node_added = 0
        self.remote_rsc_added = 0
        self.remote_use_reconnect_interval = self.Env.random_gen.choice([True,False])

    def fail(self, msg):
        """ Mark test as failed. """

        self.failed = True

        # Always log the failure.
        self.logger.log(msg)

        # Use first failure as test status, as it's likely to be most useful.
        if not self.fail_string:
            self.fail_string = msg

    def get_othernode(self, node):
        for othernode in self.Env["nodes"]:
            if othernode == node:
                # we don't want to try and use the cib that we just shutdown.
                # find a cluster node that is not our soon to be remote-node.
                continue

            return othernode

    def del_rsc(self, node, rsc):
        othernode = self.get_othernode(node)
        (rc, _) = self.rsh(othernode, "crm_resource -D -r %s -t primitive" % rsc)
        if rc != 0:
            self.fail("Removal of resource '%s' failed" % rsc)

    def add_rsc(self, node, rsc_xml):
        othernode = self.get_othernode(node)
        (rc, _) = self.rsh(othernode, self.cib_cmd % ("resources", rsc_xml))
        if rc != 0:
            self.fail("resource creation failed")

    def add_primitive_rsc(self, node):
        rsc_xml = """
<primitive class="ocf" id="%(node)s" provider="heartbeat" type="Dummy">
  <meta_attributes id="%(node)s-meta_attributes"/>
  <operations>
    <op id="%(node)s-monitor-interval-20s" interval="20s" name="monitor"/>
  </operations>
</primitive>""" % { "node": self.remote_rsc }
        self.add_rsc(node, rsc_xml)
        if not self.failed:
            self.remote_rsc_added = 1

    def add_connection_rsc(self, node):
        rsc_xml = """
<primitive class="ocf" id="%(node)s" provider="pacemaker" type="remote">
  <instance_attributes id="%(node)s-instance_attributes">
    <nvpair id="%(node)s-instance_attributes-server" name="server" value="%(server)s"/>
""" % { "node": self.remote_node, "server": node }

        if self.remote_use_reconnect_interval:
            # Set reconnect interval on resource
            rsc_xml += """
    <nvpair id="%s-instance_attributes-reconnect_interval" name="reconnect_interval" value="60s"/>
""" % self.remote_node

        rsc_xml += """
  </instance_attributes>
  <operations>
    <op id="%(node)s-start"       name="start"   interval="0"   timeout="120s"/>
    <op id="%(node)s-monitor-20s" name="monitor" interval="20s" timeout="45s"/>
  </operations>
</primitive>
""" % { "node": self.remote_node }

        self.add_rsc(node, rsc_xml)
        if not self.failed:
            self.remote_node_added = 1

    def disable_services(self, node):
        self.corosync_enabled = self.Env.service_is_enabled(node, "corosync")
        if self.corosync_enabled:
            self.Env.disable_service(node, "corosync")

        self.pacemaker_enabled = self.Env.service_is_enabled(node, "pacemaker")
        if self.pacemaker_enabled:
            self.Env.disable_service(node, "pacemaker")

    def restore_services(self, node):
        if self.corosync_enabled:
            self.Env.enable_service(node, "corosync")

        if self.pacemaker_enabled:
            self.Env.enable_service(node, "pacemaker")

    def stop_pcmk_remote(self, node):
        # disable pcmk remote
        for _ in range(10):
            (rc, _) = self.rsh(node, "service pacemaker_remote stop")
            if rc != 0:
                time.sleep(6)
            else:
                break

    def start_pcmk_remote(self, node):
        for _ in range(10):
            (rc, _) = self.rsh(node, "service pacemaker_remote start")
            if rc != 0:
                time.sleep(6)
            else:
                self.pcmk_started = 1
                break

    def freeze_pcmk_remote(self, node):
        """ Simulate a Pacemaker Remote daemon failure. """

        # We freeze the process.
        self.rsh(node, "killall -STOP pacemaker-remoted")

    def resume_pcmk_remote(self, node):
        # We resume the process.
        self.rsh(node, "killall -CONT pacemaker-remoted")

    def start_metal(self, node):
        # Cluster nodes are reused as remote nodes in remote tests. If cluster
        # services were enabled at boot, in case the remote node got fenced, the
        # cluster node would join instead of the expected remote one. Meanwhile
        # pacemaker_remote would not be able to start. Depending on the chances,
        # the situations might not be able to be orchestrated gracefully any more.
        #
        # Temporarily disable any enabled cluster serivces.
        self.disable_services(node)

        # make sure the resource doesn't already exist for some reason
        self.rsh(node, "crm_resource -D -r %s -t primitive" % self.remote_rsc)
        self.rsh(node, "crm_resource -D -r %s -t primitive" % self.remote_node)

        if not self.stop(node):
            self.fail("Failed to shutdown cluster node %s" % node)
            return

        self.start_pcmk_remote(node)

        if self.pcmk_started == 0:
            self.fail("Failed to start pacemaker_remote on node %s" % node)
            return

        # Convert node to baremetal now that it has shutdown the cluster stack
        pats = [ ]
        watch = self.create_watch(pats, 120)
        watch.set_watch()
        pats.append(self.templates["Pat:RscOpOK"] % ("start", self.remote_node))
        pats.append(self.templates["Pat:DC_IDLE"])

        self.add_connection_rsc(node)

        self.set_timer("remoteMetalInit")
        watch.look_for_all()
        self.log_timer("remoteMetalInit")
        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def migrate_connection(self, node):
        if self.failed:
            return

        pats = [ ]
        pats.append(self.templates["Pat:RscOpOK"] % ("migrate_to", self.remote_node))
        pats.append(self.templates["Pat:RscOpOK"] % ("migrate_from", self.remote_node))
        pats.append(self.templates["Pat:DC_IDLE"])
        watch = self.create_watch(pats, 120)
        watch.set_watch()

        (rc, _) = self.rsh(node, "crm_resource -M -r %s" % self.remote_node, verbose=1)
        if rc != 0:
            self.fail("failed to move remote node connection resource")
            return

        self.set_timer("remoteMetalMigrate")
        watch.look_for_all()
        self.log_timer("remoteMetalMigrate")

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)
            return

    def fail_rsc(self, node):
        if self.failed:
            return

        watchpats = [ ]
        watchpats.append(self.templates["Pat:RscRemoteOpOK"] % ("stop", self.remote_rsc, self.remote_node))
        watchpats.append(self.templates["Pat:RscRemoteOpOK"] % ("start", self.remote_rsc, self.remote_node))
        watchpats.append(self.templates["Pat:DC_IDLE"])

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        self.debug("causing dummy rsc to fail.")

        self.rsh(node, "rm -f /var/run/resource-agents/Dummy*")

        self.set_timer("remoteRscFail")
        watch.look_for_all()
        self.log_timer("remoteRscFail")
        if watch.unmatched:
            self.fail("Unmatched patterns during rsc fail: %s" % watch.unmatched)

    def fail_connection(self, node):
        if self.failed:
            return

        watchpats = [ ]
        watchpats.append(self.templates["Pat:Fencing_ok"] % self.remote_node)
        watchpats.append(self.templates["Pat:NodeFenced"] % self.remote_node)

        watch = self.create_watch(watchpats, 120)
        watch.set_watch()

        # freeze the pcmk remote daemon. this will result in fencing
        self.debug("Force stopped active remote node")
        self.freeze_pcmk_remote(node)

        self.debug("Waiting for remote node to be fenced.")
        self.set_timer("remoteMetalFence")
        watch.look_for_all()
        self.log_timer("remoteMetalFence")
        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)
            return

        self.debug("Waiting for the remote node to come back up")
        self.CM.ns.wait_for_node(node, 120)

        pats = [ ]
        watch = self.create_watch(pats, 240)
        watch.set_watch()
        pats.append(self.templates["Pat:RscOpOK"] % ("start", self.remote_node))
        if self.remote_rsc_added == 1:
            pats.append(self.templates["Pat:RscRemoteOpOK"] % ("start", self.remote_rsc, self.remote_node))

        # start the remote node again watch it integrate back into cluster.
        self.start_pcmk_remote(node)
        if self.pcmk_started == 0:
            self.fail("Failed to start pacemaker_remote on node %s" % node)
            return

        self.debug("Waiting for remote node to rejoin cluster after being fenced.")
        self.set_timer("remoteMetalRestart")
        watch.look_for_all()
        self.log_timer("remoteMetalRestart")
        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)
            return

    def add_dummy_rsc(self, node):
        if self.failed:
            return

        # verify we can put a resource on the remote node
        pats = [ ]
        watch = self.create_watch(pats, 120)
        watch.set_watch()
        pats.append(self.templates["Pat:RscRemoteOpOK"] % ("start", self.remote_rsc, self.remote_node))
        pats.append(self.templates["Pat:DC_IDLE"])

        # Add a resource that must live on remote-node
        self.add_primitive_rsc(node)

        # force that rsc to prefer the remote node.
        (rc, _) = self.CM.rsh(node, "crm_resource -M -r %s -N %s -f" % (self.remote_rsc, self.remote_node), verbose=1)
        if rc != 0:
            self.fail("Failed to place remote resource on remote node.")
            return

        self.set_timer("remoteMetalRsc")
        watch.look_for_all()
        self.log_timer("remoteMetalRsc")
        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

    def test_attributes(self, node):
        if self.failed:
            return

        # This verifies permanent attributes can be set on a remote-node. It also
        # verifies the remote-node can edit its own cib node section remotely.
        (rc, line) = self.CM.rsh(node, "crm_attribute -l forever -n testattr -v testval -N %s" % self.remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to set remote-node attribute. rc:%s output:%s" % (rc, line))
            return

        (rc, _) = self.CM.rsh(node, "crm_attribute -l forever -n testattr -q -N %s" % self.remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to get remote-node attribute")
            return

        (rc, _) = self.CM.rsh(node, "crm_attribute -l forever -n testattr -D -N %s" % self.remote_node, verbose=1)
        if rc != 0:
            self.fail("Failed to delete remote-node attribute")
            return

    def cleanup_metal(self, node):
        self.restore_services(node)

        if self.pcmk_started == 0:
            return

        pats = [ ]

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        if self.remote_rsc_added == 1:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.remote_rsc))
        if self.remote_node_added == 1:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.remote_node))

        self.set_timer("remoteMetalCleanup")

        self.resume_pcmk_remote(node)

        if self.remote_rsc_added == 1:

            # Remove dummy resource added for remote node tests
            self.debug("Cleaning up dummy rsc put on remote node")
            self.rsh(self.get_othernode(node), "crm_resource -U -r %s" % self.remote_rsc)
            self.del_rsc(node, self.remote_rsc)

        if self.remote_node_added == 1:

            # Remove remote node's connection resource
            self.debug("Cleaning up remote node connection resource")
            self.rsh(self.get_othernode(node), "crm_resource -U -r %s" % self.remote_node)
            self.del_rsc(node, self.remote_node)

        watch.look_for_all()
        self.log_timer("remoteMetalCleanup")

        if watch.unmatched:
            self.fail("Unmatched patterns: %s" % watch.unmatched)

        self.stop_pcmk_remote(node)

        self.debug("Waiting for the cluster to recover")
        self.CM.cluster_stable()

        if self.remote_node_added == 1:
            # Remove remote node itself
            self.debug("Cleaning up node entry for remote node")
            self.rsh(self.get_othernode(node), "crm_node --force --remove %s" % self.remote_node)

    def setup_env(self, node):
        self.remote_node = "remote-%s" % node

        # we are assuming if all nodes have a key, that it is
        # the right key... If any node doesn't have a remote
        # key, we regenerate it everywhere.
        if self.rsh.exists_on_all("/etc/pacemaker/authkey", self.Env["nodes"]):
            return

        # create key locally
        (handle, keyfile) = tempfile.mkstemp(".cts")
        os.close(handle)
        subprocess.check_call(["dd", "if=/dev/urandom", "of=%s" % keyfile, "bs=4096", "count=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # sync key throughout the cluster
        for node in self.Env["nodes"]:
            self.rsh(node, "mkdir -p --mode=0750 /etc/pacemaker")
            self.rsh.copy(keyfile, "root@%s:/etc/pacemaker/authkey" % node)
            self.rsh(node, "chgrp haclient /etc/pacemaker /etc/pacemaker/authkey")
            self.rsh(node, "chmod 0640 /etc/pacemaker/authkey")
        os.unlink(keyfile)

    def is_applicable(self):
        if not self.is_applicable_common():
            return False

        for node in self.Env["nodes"]:
            (rc, _) = self.rsh(node, "which pacemaker-remoted >/dev/null 2>&1")
            if rc != 0:
                return False
        return True

    def start_new_test(self, node):
        self.incr("calls")
        self.reset()

        ret = self.startall(None)
        if not ret:
            return self.failure("setup failed: could not start all nodes")

        self.setup_env(node)
        self.start_metal(node)
        self.add_dummy_rsc(node)
        return True

    def __call__(self, node):
        return self.failure("This base class is not meant to be called directly.")

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''
        return [ r"""is running on remote.*which isn't allowed""",
                 r"""Connection terminated""",
                 r"""Could not send remote""",
                ]


class SimulStartLite(CTSTest):
    '''Start any stopped nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStartLite"

    def __call__(self, dummy):
        '''Perform the 'SimulStartList' setup work. '''
        self.incr("calls")
        self.debug("Setup: " + self.name)

        #        We ignore the "node" parameter...
        node_list = []
        for node in self.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "down":
                self.incr("WasStopped")
                node_list.append(node)

        self.set_timer()
        while len(node_list) > 0:
            # Repeat until all nodes come up
            watchpats = [ ]

            uppat = self.templates["Pat:NonDC_started"]
            if self.CM.upcount() == 0:
                uppat = self.templates["Pat:Local_started"]

            watchpats.append(self.templates["Pat:DC_IDLE"])
            for node in node_list:
                watchpats.append(uppat % node)
                watchpats.append(self.templates["Pat:InfraUp"] % node)
                watchpats.append(self.templates["Pat:PacemakerUp"] % node)

            #   Start all the nodes - at about the same time...
            watch = self.create_watch(watchpats, self.Env["DeadTime"]+10)
            watch.set_watch()

            stonith = self.CM.prepare_fencing_watcher(self.name)

            for node in node_list:
                self.CM.StartaCMnoBlock(node)

            watch.look_for_all()

            node_list = self.CM.fencing_cleanup(self.name, stonith)

            if node_list == None:
                return self.failure("Cluster did not stabilize")

            # Remove node_list messages from watch.unmatched
            for node in node_list:
                self.logger.debug("Dealing with stonith operations for %s" % repr(node_list))
                if watch.unmatched:
                    try:
                        watch.unmatched.remove(uppat % node)
                    except:
                        self.debug("Already matched: %s" % (uppat % node))
                    try:
                        watch.unmatched.remove(self.templates["Pat:InfraUp"] % node)
                    except:
                        self.debug("Already matched: %s" % (self.templates["Pat:InfraUp"] % node))
                    try:
                        watch.unmatched.remove(self.templates["Pat:PacemakerUp"] % node)
                    except:
                        self.debug("Already matched: %s" % (self.templates["Pat:PacemakerUp"] % node))

            if watch.unmatched:
                for regex in watch.unmatched:
                    self.logger.log ("Warn: Startup pattern not found: %s" % regex)

            if not self.CM.cluster_stable():
                return self.failure("Cluster did not stabilize")

        did_fail = 0
        unstable = []
        for node in self.Env["nodes"]:
            if self.CM.StataCM(node) == 0:
                did_fail = 1
                unstable.append(node)

        if did_fail:
            return self.failure("Unstarted nodes exist: " + repr(unstable))

        unstable = []
        for node in self.Env["nodes"]:
            if not self.CM.node_stable(node):
                did_fail = 1
                unstable.append(node)

        if did_fail:
            return self.failure("Unstable cluster nodes exist: " + repr(unstable))

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

        self.debug("Setup: " + self.name)

        #     We ignore the "node" parameter...
        watchpats = [ ]

        for node in self.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "up":
                self.incr("WasStarted")
                watchpats.append(self.templates["Pat:We_stopped"] % node)

        if len(watchpats) == 0:
            return self.success()

        #     Stop all the nodes - at about the same time...
        watch = self.create_watch(watchpats, self.Env["DeadTime"]+10)

        watch.set_watch()
        self.set_timer()
        for node in self.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "up":
                self.CM.StopaCMnoBlock(node)
        if watch.look_for_all():
            # Make sure they're completely down with no residule
            for node in self.Env["nodes"]:
                self.rsh(node, self.templates["StopCmd"])

            return self.success()

        did_fail = 0
        up_nodes = []
        for node in self.Env["nodes"]:
            if self.CM.StataCM(node) == 1:
                did_fail = 1
                up_nodes.append(node)

        if did_fail:
            return self.failure("Active nodes exist: " + repr(up_nodes))

        self.logger.log("Warn: All nodes stopped but CTS didn't detect: "
                    + repr(watch.unmatched))

        return self.failure("Missing log message: "+repr(watch.unmatched))

    def is_applicable(self):
        '''SimulStopLite is a setup test and never applicable'''
        return False


class StartTest(CTSTest):
    '''Start (activate) the cluster manager on a node'''
    def __init__(self, cm, debug=None):
        CTSTest.__init__(self,cm)
        self.name = "start"
        self.debug = debug

    def __call__(self, node):
        '''Perform the 'start' test. '''
        self.incr("calls")

        if self.CM.upcount() == 0:
            self.incr("us")
        else:
            self.incr("them")

        if self.CM.ShouldBeStatus[node] != "down":
            return self.skipped()

        if self.CM.StartaCM(node):
            return self.success()

        return self.failure("Startup %s on node %s failed"
                            % (self.Env["Name"], node))


class StopTest(CTSTest):
    '''Stop (deactivate) the cluster manager on a node'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name = "Stop"

    def __call__(self, node):
        '''Perform the 'stop' test. '''
        self.incr("calls")
        if self.CM.ShouldBeStatus[node] != "up":
            return self.skipped()

        patterns = []
        # Technically we should always be able to notice ourselves stopping
        patterns.append(self.templates["Pat:We_stopped"] % node)

        # Any active node needs to notice this one left
        # (note that this won't work if we have multiple partitions)
        for other in self.Env["nodes"]:
            if self.CM.ShouldBeStatus[other] == "up" and other != node:
                patterns.append(self.templates["Pat:They_stopped"] %(other, self.CM.key_for_node(node)))

        watch = self.create_watch(patterns, self.Env["DeadTime"])
        watch.set_watch()

        if node == self.CM.OurNode:
            self.incr("us")
        else:
            if self.CM.upcount() <= 1:
                self.incr("all")
            else:
                self.incr("them")

        self.CM.StopaCM(node)
        watch.look_for_all()

        failreason = None
        UnmatchedList = "||"
        if watch.unmatched:
            (_, output) = self.rsh(node, "/bin/ps axf", verbose=1)
            for line in output:
                self.debug(line)

            (_, output) = self.rsh(node, "/usr/sbin/dlm_tool dump 2>/dev/null", verbose=1)
            for line in output:
                self.debug(line)

            for regex in watch.unmatched:
                self.logger.log ("ERROR: Shutdown pattern not found: %s" % regex)
                UnmatchedList +=  regex + "||"
                failreason = "Missing shutdown pattern"

        self.CM.cluster_stable(self.Env["DeadTime"])

        if not watch.unmatched or self.CM.upcount() == 0:
            return self.success()

        if len(watch.unmatched) >= self.CM.upcount():
            return self.failure("no match against (%s)" % UnmatchedList)

        if failreason == None:
            return self.success()

        return self.failure(failreason)
