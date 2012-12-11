'''CTS: Cluster Testing System: Tests module

There are a few things we want to do here:

 '''

__copyright__='''
Copyright (C) 2000, 2001 Alan Robertson <alanr@unix.sh>
Licensed under the GNU GPL.

Add RecourceRecover testcase Zhao Kai <zhaokai@cn.ibm.com>
'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

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

import time, os, re, types, string, tempfile, sys
from stat import *
from cts import CTS
from cts.CTSaudits import *

AllTestClasses = [ ]

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
        #self.name="the unnamed test"
        self.Stats = {"calls":0
        ,        "success":0
        ,        "failure":0
        ,        "skipped":0
        ,        "auditfail":0}

#        if not issubclass(cm.__class__, ClusterManager):
#            raise ValueError("Must be a ClusterManager object")
        self.CM = cm
        self.Audits = []
        self.timeout=120
        self.passed = 1
        self.is_loop = 0
        self.is_unsafe = 0
        self.is_experimental = 0
        self.is_valgrind = 0
        self.benchmark = 0  # which tests to benchmark
        self.timer = {}  # timers

    def has_key(self, key):
        return self.Stats.has_key(key)

    def __setitem__(self, key, value):
        self.Stats[key] = value
        
    def __getitem__(self, key):
        return self.Stats[key]

    def log_mark(self, msg):
        self.CM.debug("MARK: test %s %s %d" % (self.name,msg,time.time()))
        return

    def get_timer(self,key = "test"):
        try: return self.timer[key]
        except: return 0

    def set_timer(self,key = "test"):
        self.timer[key] = time.time()
        return self.timer[key]

    def log_timer(self,key = "test"):
        elapsed = 0
        if key in self.timer:
            elapsed = time.time() - self.timer[key]
            s = key == "test" and self.name or "%s:%s" %(self.name,key)
            self.CM.debug("%s runtime: %.2f" % (s, elapsed))
            del self.timer[key]
        return elapsed

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not self.Stats.has_key(name):
            self.Stats[name]=0
        self.Stats[name] = self.Stats[name]+1

        # Reset the test passed boolean
        if name == "calls":
            self.passed = 1

    def failure(self, reason="none"):
        '''Increment the failure count'''
        self.passed = 0
        self.incr("failure")
        self.CM.log(("Test %s" % self.name).ljust(35)  +" FAILED: %s" % reason)
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
        self.incr("calls")
        return self.failure()

    def audit(self):
        passed = 1
        if len(self.Audits) > 0:
            for audit in self.Audits:
                if not audit():
                    self.CM.log("Internal %s Audit %s FAILED." % (self.name, audit.name()))
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
        return CTS.LogWatcher(self.CM.Env, self.CM["LogFileName"], patterns, name, timeout)

    def local_badnews(self, prefix, watch, local_ignore=[]):
        errcount = 0
        if not prefix:
            prefix = "LocalBadNews:"

        ignorelist = []                
        ignorelist.append(" CTS: ")
        ignorelist.append(prefix)
        ignorelist.extend(local_ignore)

        while errcount < 100:
            match=watch.look(0)
            if match:
               add_err = 1
               for ignore in ignorelist:
                   if add_err == 1 and re.search(ignore, match):
                       add_err = 0
               if add_err == 1:
                   self.CM.log(prefix + " " + match)
                   errcount=errcount+1
            else:
              break
        else:
            self.CM.log("Too many errors!")

        return errcount

    def is_applicable(self):
        return self.is_applicable_common()

    def is_applicable_common(self):
        '''Return TRUE if we are applicable in the current test configuration'''
        #raise ValueError("Abstract Class member (is_applicable)")

        if self.is_loop and not self.CM.Env["loop-tests"]:
            return 0
        elif self.is_unsafe and not self.CM.Env["unsafe-tests"]:
            return 0
        elif self.is_valgrind and not self.CM.Env["valgrind-tests"]:
            return 0
        elif self.is_experimental and not self.CM.Env["experimental-tests"]:
            return 0
        elif self.CM.Env["benchmark"] and self.benchmark == 0:
            return 0

        return 1

    def find_ocfs2_resources(self, node):
        self.r_o2cb = None
        self.r_ocfs2 = []

        (rc, lines) = self.CM.rsh(node, "crm_resource -c", None)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self.CM, line)
                if r.rtype == "o2cb" and r.parent != "NA":
                    self.CM.debug("Found o2cb: %s" % self.r_o2cb)
                    self.r_o2cb = r.parent
            if re.search("^Constraint", line):
                c = AuditConstraint(self.CM, line)
                if c.type == "rsc_colocation" and c.target == self.r_o2cb:
                    self.r_ocfs2.append(c.rsc)

        self.CM.debug("Found ocfs2 filesystems: %s" % repr(self.r_ocfs2))
        return len(self.r_ocfs2)

    def canrunnow(self, node):
        '''Return TRUE if we can meaningfully run right now'''
        return 1

    def errorstoignore(self):
        '''Return list of errors which are 'normal' and should be ignored'''
        return []

###################################################################
class StopTest(CTSTest):
###################################################################
    '''Stop (deactivate) the cluster manager on a node'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name="Stop"

    def __call__(self, node):
        '''Perform the 'stop' test. '''
        self.incr("calls")
        if self.CM.ShouldBeStatus[node] != "up":
            return self.skipped()

        patterns = []
        # Technically we should always be able to notice ourselves stopping
        patterns.append(self.CM["Pat:We_stopped"] % node)

        #if self.CM.Env["use_logd"]:
        #    patterns.append(self.CM["Pat:Logd_stopped"] % node)

        # Any active node needs to notice this one left
        # NOTE: This wont work if we have multiple partitions
        for other in self.CM.Env["nodes"]:
            if self.CM.ShouldBeStatus[other] == "up" and other != node:
                patterns.append(self.CM["Pat:They_stopped"] %(other, self.CM.key_for_node(node)))
                #self.debug("Checking %s will notice %s left"%(other, node))
                
        watch = self.create_watch(patterns, self.CM["DeadTime"])
        watch.setwatch()

        if node == self.CM.OurNode:
            self.incr("us")
        else:
            if self.CM.upcount() <= 1:
                self.incr("all")
            else:
                self.incr("them")

        self.CM.StopaCM(node)
        watch_result = watch.lookforall()

        failreason=None
        UnmatchedList = "||"
        if watch.unmatched:
            (rc, output) = self.CM.rsh(node, "/bin/ps axf", None)
            for line in output:
                self.CM.debug(line)
                
            (rc, output) = self.CM.rsh(node, "/usr/sbin/dlm_tool dump", None)
            for line in output:
                self.CM.debug(line)

            for regex in watch.unmatched:
                self.CM.log ("ERROR: Shutdown pattern not found: %s" % (regex))
                UnmatchedList +=  regex + "||";
                failreason="Missing shutdown pattern"

        self.CM.cluster_stable(self.CM["DeadTime"])

        if not watch.unmatched or self.CM.upcount() == 0:
            return self.success()

        if len(watch.unmatched) >= self.CM.upcount():
            return self.failure("no match against (%s)" % UnmatchedList)

        if failreason == None:
            return self.success()
        else:
            return self.failure(failreason)
#
# We don't register StopTest because it's better when called by
# another test...
#

###################################################################
class StartTest(CTSTest):
###################################################################
    '''Start (activate) the cluster manager on a node'''
    def __init__(self, cm, debug=None):
        CTSTest.__init__(self,cm)
        self.name="start"
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
        elif self.CM.StartaCM(node):
            return self.success()
        else:
            return self.failure("Startup %s on node %s failed"
                                %(self.CM["Name"], node))

#
# We don't register StartTest because it's better when called by
# another test...
#

###################################################################
class FlipTest(CTSTest):
###################################################################
    '''If it's running, stop it.  If it's stopped start it.
       Overthrow the status quo...
    '''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="Flip"
        self.start = StartTest(cm)
        self.stop = StopTest(cm)

    def __call__(self, node):
        '''Perform the 'Flip' test. '''
        self.incr("calls")
        if self.CM.ShouldBeStatus[node] == "up":
            self.incr("stopped")
            ret = self.stop(node)
            type="up->down"
            # Give the cluster time to recognize it's gone...
            time.sleep(self.CM["StableTime"])
        elif self.CM.ShouldBeStatus[node] == "down":
            self.incr("started")
            ret = self.start(node)
            type="down->up"
        else:
            return self.skipped()

        self.incr(type)
        if ret:
            return self.success()
        else:
            return self.failure("%s failure" % type)

#        Register FlipTest as a good test to run
AllTestClasses.append(FlipTest)

###################################################################
class RestartTest(CTSTest):
###################################################################
    '''Stop and restart a node'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="Restart"
        self.start = StartTest(cm)
        self.stop = StopTest(cm)
        self.benchmark = 1

    def __call__(self, node):
        '''Perform the 'restart' test. '''
        self.incr("calls")

        self.incr("node:" + node)
        
        ret1 = 1
        if self.CM.StataCM(node):
            self.incr("WasStopped")
            if not self.start(node):
                return self.failure("start (setup) failure: "+node)

        self.set_timer()
        if not self.stop(node):
            return self.failure("stop failure: "+node)
        if not self.start(node):
            return self.failure("start failure: "+node)
        return self.success()

#        Register RestartTest as a good test to run
AllTestClasses.append(RestartTest)

###################################################################
class StonithdTest(CTSTest):
###################################################################
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name="Stonithd"
        self.startall = SimulStartLite(cm)
        self.benchmark = 1

    def __call__(self, node):
        self.incr("calls")
        if len(self.CM.Env["nodes"]) < 2:
            return self.skipped()

        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        is_dc = self.CM.is_node_dc(node)

        watchpats = []
        watchpats.append("log_operation: Operation .* for host '%s' with device .* returned: 0" % node)
        watchpats.append("tengine_stonith_notify: Peer %s was terminated .*: OK" % node)

        if self.CM.Env["at-boot"] == 0:
            self.CM.debug("Expecting %s to stay down" % node)
            self.CM.ShouldBeStatus[node]="down"
        else:
            self.CM.debug("Expecting %s to come up again %d" % (node, self.CM.Env["at-boot"]))
            watchpats.append("%s .*do_state_transition: .* S_STARTING -> S_PENDING" % node)
            watchpats.append("%s .*do_state_transition: .* S_PENDING -> S_NOT_DC" % node)

        watch = self.create_watch(watchpats, 30 + self.CM["DeadTime"] + self.CM["StableTime"] + self.CM["StartTime"])
        watch.setwatch()

        origin = self.CM.Env.RandomGen.choice(self.CM.Env["nodes"])

        rc = self.CM.rsh(origin, "stonith_admin --reboot %s -VVVVVV" % node)

        if rc == 194:
            # 194 - 256 = -62 = Timer expired
            #
            # Look for the patterns, usually this means the required
            # device was running on the node to be fenced - or that
            # the required devices were in the process of being loaded
            # and/or moved
            #
            # Effectively the node committed suicide so there will be
            # no confirmation, but pacemaker should be watching and
            # fence the node again

            self.CM.log("Fencing command on %s to fence %s timed out" % (origin, node))

        elif origin != node and rc != 0:
            self.CM.debug("Waiting for the cluster to recover")
            self.CM.cluster_stable()

            self.CM.debug("Waiting STONITHd node to come back up")
            self.CM.ns.WaitForAllNodesToComeUp(self.CM.Env["nodes"], 600)

            self.CM.log("Fencing command on %s failed to fence %s (rc=%d)" % (origin, node, rc))

        elif origin == node and rc != 255:
            # 255 == broken pipe, ie. the node was fenced as epxected
            self.CM.log("Logcally originated fencing returned %d" % rc)


        self.set_timer("fence")
        matched = watch.lookforall()
        self.log_timer("fence")
        self.set_timer("reform")
        if watch.unmatched:
            self.CM.log("Patterns not found: " + repr(watch.unmatched))

        self.CM.debug("Waiting for the cluster to recover")
        self.CM.cluster_stable()

        self.CM.debug("Waiting STONITHd node to come back up")
        self.CM.ns.WaitForAllNodesToComeUp(self.CM.Env["nodes"], 600)

        self.CM.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self.CM.cluster_stable(self.CM["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected patterns")
        elif not is_stable:
            return self.failure("Cluster did not become stable")

        self.log_timer("reform")
        return self.success()

    def errorstoignore(self):
        return [ 
            self.CM["Pat:Fencing_start"] % ".*", 
            self.CM["Pat:Fencing_ok"] % ".*",
            "error: native_create_actions: Resource .*stonith::.* is active on 2 nodes attempting recovery",
            "error: remote_op_done: Operation reboot of .*by .* for stonith_admin.*: Timer expired",
            ]

    def is_applicable(self):
        if not self.is_applicable_common():
            return 0

        if self.CM.Env.has_key("DoFencing"):
            return self.CM.Env["DoFencing"]

        return 1
           
AllTestClasses.append(StonithdTest)

###################################################################
class StartOnebyOne(CTSTest):
###################################################################
    '''Start all the nodes ~ one by one'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="StartOnebyOne"
        self.stopall = SimulStopLite(cm)
        self.start = StartTest(cm)
        self.ns=CTS.NodeStatus(cm.Env)

    def __call__(self, dummy):
        '''Perform the 'StartOnebyOne' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Test setup failed")

        failed=[]
        self.set_timer()
        for node in self.CM.Env["nodes"]:
            if not self.start(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to start: " + repr(failed))

        return self.success()

#        Register StartOnebyOne as a good test to run
AllTestClasses.append(StartOnebyOne)

###################################################################
class SimulStart(CTSTest):
###################################################################
    '''Start all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="SimulStart"
        self.stopall = SimulStopLite(cm)
        self.startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStart' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")
        
        self.CM.clear_all_caches()
 
        if not self.startall(None):
            return self.failure("Startall failed")

        return self.success()

#        Register SimulStart as a good test to run
AllTestClasses.append(SimulStart)

###################################################################
class SimulStop(CTSTest):
###################################################################
    '''Stop all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="SimulStop"
        self.startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStop' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self.stopall(None):
            return self.failure("Stopall failed")

        return self.success()

#     Register SimulStop as a good test to run
AllTestClasses.append(SimulStop)

###################################################################
class StopOnebyOne(CTSTest):
###################################################################
    '''Stop all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="StopOnebyOne"
        self.startall = SimulStartLite(cm)
        self.stop = StopTest(cm)

    def __call__(self, dummy):
        '''Perform the 'StopOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        failed=[]
        self.set_timer()
        for node in self.CM.Env["nodes"]:
            if not self.stop(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to stop: " + repr(failed))

        self.CM.clear_all_caches()
        return self.success()

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(StopOnebyOne)

###################################################################
class RestartOnebyOne(CTSTest):
###################################################################
    '''Restart all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="RestartOnebyOne"
        self.startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'RestartOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        did_fail=[]
        self.set_timer()
        self.restart = RestartTest(self.CM)
        for node in self.CM.Env["nodes"]:
            if not self.restart(node):
                did_fail.append(node)

        if did_fail:
            return self.failure("Could not restart %d nodes: %s" 
                                %(len(did_fail), repr(did_fail)))
        return self.success()

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(RestartOnebyOne)

###################################################################
class PartialStart(CTSTest):
###################################################################
    '''Start a node - but tell it to stop before it finishes starting up'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="PartialStart"
        self.startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)
        self.stop = StopTest(cm)
        #self.is_unsafe = 1

    def __call__(self, node):
        '''Perform the 'PartialStart' test. '''
        self.incr("calls")

        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")

#   FIXME!  This should use the CM class to get the pattern
#       then it would be applicable in general
        watchpats = []
        watchpats.append("crmd.*Connecting to cluster infrastructure")
        watch = self.create_watch(watchpats, self.CM["DeadTime"]+10)
        watch.setwatch()

        self.CM.StartaCMnoBlock(node)
        ret = watch.lookforall()
        if not ret:
            self.CM.log("Patterns not found: " + repr(watch.unmatched))
            return self.failure("Setup of %s failed" % node) 

        ret = self.stop(node)
        if not ret:
            return self.failure("%s did not stop in time" % node)

        return self.success()

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''

        # We might do some fencing in the 2-node case if we make it up far enough
        return [ """Executing reboot fencing operation""" ]

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(PartialStart)

#######################################################################
class StandbyTest(CTSTest):
#######################################################################
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="Standby"
        self.benchmark = 1
            
        self.start = StartTest(cm)
        self.startall = SimulStartLite(cm)
        
    # make sure the node is active
    # set the node to standby mode
    # check resources, none resource should be running on the node
    # set the node to active mode
    # check resouces, resources should have been migrated back (SHOULD THEY?)
    
    def __call__(self, node):
    
        self.incr("calls")
        ret=self.startall(None)
        if not ret:
            return self.failure("Start all nodes failed")
        
        self.CM.debug("Make sure node %s is active" % node)    
        if self.CM.StandbyStatus(node) != "off":
            if not self.CM.SetStandbyMode(node, "off"):
                return self.failure("can't set node %s to active mode" % node)

        self.CM.cluster_stable()

        status = self.CM.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))

        self.CM.debug("Getting resources running on node %s" % node)
        rsc_on_node = self.CM.active_resources(node)

        watchpats = []
        watchpats.append("do_state_transition:.*-> S_POLICY_ENGINE")
        watch = self.create_watch(watchpats, self.CM["DeadTime"]+10)
        watch.setwatch()

        self.CM.debug("Setting node %s to standby mode" % node) 
        if not self.CM.SetStandbyMode(node, "on"):
            return self.failure("can't set node %s to standby mode" % node)

        self.set_timer("on")

        ret = watch.lookforall()
        if not ret:
            self.CM.log("Patterns not found: " + repr(watch.unmatched))
            self.CM.SetStandbyMode(node, "off")
            return self.failure("cluster didn't react to standby change on %s" % node) 

        self.CM.cluster_stable()

        status = self.CM.StandbyStatus(node)
        if status != "on":
            return self.failure("standby status of %s is [%s] but we expect [on]" % (node, status))
        self.log_timer("on")

        self.CM.debug("Checking resources")
        bad_run = self.CM.active_resources(node)
        if len(bad_run) > 0:
            rc = self.failure("%s set to standby, %s is still running on it" % (node, repr(bad_run)))
            self.CM.debug("Setting node %s to active mode" % node) 
            self.CM.SetStandbyMode(node, "off")
            return rc

        self.CM.debug("Setting node %s to active mode" % node) 
        if not self.CM.SetStandbyMode(node, "off"):
            return self.failure("can't set node %s to active mode" % node)

        self.set_timer("off")
        self.CM.cluster_stable()

        status = self.CM.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))
        self.log_timer("off")

        return self.success()

AllTestClasses.append(StandbyTest)

#######################################################################
class ValgrindTest(CTSTest):
#######################################################################
    '''Check for memory leaks'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="Valgrind"
        self.stopall = SimulStopLite(cm)
        self.startall = SimulStartLite(cm)
        self.is_valgrind = 1
        self.is_loop = 1

    def setup(self, node):
        self.incr("calls")
        
        ret=self.stopall(None)
        if not ret:
            return self.failure("Stop all nodes failed")

        # Enable valgrind
        self.logPat = "/tmp/%s-*.valgrind" % self.name

        self.CM.Env["valgrind-prefix"] = self.name

        self.CM.rsh(node, "rm -f %s" % self.logPat, None)
        
        ret=self.startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        for node in self.CM.Env["nodes"]:
            (rc, output) = self.CM.rsh(node, "ps u --ppid `pidofproc aisexec`", None)
            for line in output:
                self.CM.debug(line)

        return self.success()

    def teardown(self, node):
        # Disable valgrind
        self.CM.Env["valgrind-prefix"] = None

        # Return all nodes to normal
        ret=self.stopall(None)
        if not ret:
            return self.failure("Stop all nodes failed")

        return self.success()

    def find_leaks(self):
        # Check for leaks
        leaked = []
        self.stop = StopTest(self.CM)

        for node in self.CM.Env["nodes"]:
            (rc, ps_out) = self.CM.rsh(node, "ps u --ppid `pidofproc aisexec`", None)
            rc = self.stop(node)
            if not rc:
                self.failure("Couldn't shut down %s" % node)

            rc = self.CM.rsh(node, "grep -e indirectly.*lost:.*[1-9] -e definitely.*lost:.*[1-9] -e (ERROR|error).*SUMMARY:.*[1-9].*errors %s" % self.logPat, 0)
            if rc != 1:
                leaked.append(node)
                self.failure("Valgrind errors detected on %s" % node)
                for line in ps_out:
                    self.CM.log(line)
                (rc, output) = self.CM.rsh(node, "grep -e lost: -e SUMMARY: %s" % self.logPat, None)
                for line in output:
                    self.CM.log(line)
                (rc, output) = self.CM.rsh(node, "cat %s" % self.logPat, None)
                for line in output:
                    self.CM.debug(line)

        self.CM.rsh(node, "rm -f %s" % self.logPat, None)
        return leaked

    def __call__(self, node):
        leaked = self.find_leaks()
        if len(leaked) > 0:
            return self.failure("Nodes %s leaked" % repr(leaked))            

        return self.success()

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''
        return [ """cib:.*readCibXmlFile:""", """HA_VALGRIND_ENABLED""" ]

#######################################################################
class StandbyLoopTest(ValgrindTest):
#######################################################################
    '''Check for memory leaks by putting a node in and out of standby for an hour'''
    def __init__(self, cm):
        ValgrindTest.__init__(self,cm)
        self.name="StandbyLoop"
        
    def __call__(self, node):
    
        lpc = 0
        delay = 2
        failed = 0
        done=time.time() + self.CM.Env["loop-minutes"]*60
        while time.time() <= done and not failed:
            lpc = lpc + 1

            time.sleep(delay)
            if not self.CM.SetStandbyMode(node, "on"):
                self.failure("can't set node %s to standby mode" % node)
                failed = lpc

            time.sleep(delay)
            if not self.CM.SetStandbyMode(node, "off"):
                self.failure("can't set node %s to active mode" % node)
                failed = lpc

        leaked = self.find_leaks()
        if failed:
            return self.failure("Iteration %d failed" % failed)
        elif len(leaked) > 0:
            return self.failure("Nodes %s leaked" % repr(leaked))

        return self.success()

AllTestClasses.append(StandbyLoopTest)

##############################################################################
class BandwidthTest(CTSTest):
##############################################################################
#        Tests should not be cluster-manager-specific
#        If you need to find out cluster manager configuration to do this, then
#        it should be added to the generic cluster manager API.
    '''Test the bandwidth which heartbeat uses'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name = "Bandwidth"
        self.start = StartTest(cm)
        self.__setitem__("min",0)
        self.__setitem__("max",0)
        self.__setitem__("totalbandwidth",0)
        self.tempfile = tempfile.mktemp(".cts")
        self.startall = SimulStartLite(cm)
        
    def __call__(self, node):
        '''Perform the Bandwidth test'''
        self.incr("calls")
        
        if self.CM.upcount()<1:
            return self.skipped()

        Path = self.CM.InternalCommConfig()
        if "ip" not in Path["mediatype"]:
             return self.skipped()

        port = Path["port"][0]
        port = int(port)

        ret = self.startall(None)
        if not ret:
            return self.failure("Test setup failed")
        time.sleep(5)  # We get extra messages right after startup.


        fstmpfile = "/var/run/band_estimate"
        dumpcmd = "tcpdump -p -n -c 102 -i any udp port %d > %s 2>&1" \
        %                (port, fstmpfile)
 
        rc = self.CM.rsh(node, dumpcmd)
        if rc == 0:
            farfile = "root@%s:%s" % (node, fstmpfile)
            self.CM.rsh.cp(farfile, self.tempfile)
            Bandwidth = self.countbandwidth(self.tempfile)
            if not Bandwidth:
                self.CM.log("Could not compute bandwidth.")
                return self.success()
            intband = int(Bandwidth + 0.5)
            self.CM.log("...bandwidth: %d bits/sec" % intband)
            self.Stats["totalbandwidth"] = self.Stats["totalbandwidth"] + Bandwidth
            if self.Stats["min"] == 0:
                self.Stats["min"] = Bandwidth
            if Bandwidth > self.Stats["max"]:
                self.Stats["max"] = Bandwidth
            if Bandwidth < self.Stats["min"]:
                self.Stats["min"] = Bandwidth
            self.CM.rsh(node, "rm -f %s" % fstmpfile)
            os.unlink(self.tempfile)
            return self.success()
        else:
            return self.failure("no response from tcpdump command [%d]!" % rc)

    def countbandwidth(self, file):
        fp = open(file, "r")
        fp.seek(0)
        count = 0
        sum = 0
        while 1:
            line = fp.readline()
            if not line:
                return None
            if re.search("udp",line) or re.search("UDP,", line):
                count=count+1
                linesplit = string.split(line," ")
                for j in range(len(linesplit)-1):
                    if linesplit[j]=="udp": break
                    if linesplit[j]=="length:": break
                        
                try:
                    sum = sum + int(linesplit[j+1])
                except ValueError:
                    self.CM.log("Invalid tcpdump line: %s" % line)
                    return None
                T1 = linesplit[0]
                timesplit = string.split(T1,":")
                time2split = string.split(timesplit[2],".")
                time1 = (long(timesplit[0])*60+long(timesplit[1]))*60+long(time2split[0])+long(time2split[1])*0.000001
                break

        while count < 100:
            line = fp.readline()
            if not line:
                return None
            if re.search("udp",line) or re.search("UDP,", line):
                count = count+1
                linessplit = string.split(line," ")
                for j in range(len(linessplit)-1):
                    if linessplit[j] =="udp": break
                    if linesplit[j]=="length:": break
                try:
                    sum=int(linessplit[j+1])+sum
                except ValueError:
                    self.CM.log("Invalid tcpdump line: %s" % line)
                    return None

        T2 = linessplit[0]
        timesplit = string.split(T2,":")
        time2split = string.split(timesplit[2],".")
        time2 = (long(timesplit[0])*60+long(timesplit[1]))*60+long(time2split[0])+long(time2split[1])*0.000001
        time = time2-time1
        if (time <= 0):
            return 0
        return (sum*8)/time

    def is_applicable(self):
        '''BandwidthTest never applicable'''
        return 0

AllTestClasses.append(BandwidthTest)

###################################################################
class ResourceRecover(CTSTest):
###################################################################
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="ResourceRecover"
        self.start = StartTest(cm)
        self.startall = SimulStartLite(cm)
        self.max=30
        self.rid=None
        self.rid_alt=None
        #self.is_unsafe = 1
        self.benchmark = 1

        # these are the values used for the new LRM API call
        self.action = "asyncmon"
        self.interval = 0

    def __call__(self, node):
        '''Perform the 'ResourceRecover' test. '''
        self.incr("calls")
        
        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        resourcelist = self.CM.active_resources(node)
        # if there are no resourcelist, return directly
        if len(resourcelist)==0:
            self.CM.log("No active resources on %s" % node)
            return self.skipped()

        self.rid = self.CM.Env.RandomGen.choice(resourcelist)
        self.rid_alt = self.rid

        rsc = None
        (rc, lines) = self.CM.rsh(node, "crm_resource -c", None)
        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self.CM, line)
                if tmp.id == self.rid:
                    rsc = tmp
                    # Handle anonymous clones that get renamed
                    self.rid = rsc.clone_id
                    break

        if not rsc:
            return self.failure("Could not find %s in the resource list" % self.rid)

        self.CM.debug("Shooting %s aka. %s" % (rsc.clone_id, rsc.id))

        pats = []
        pats.append("Updating failcount for %s on .* after .* %s"
                    % (self.rid, self.action))

        if rsc.managed():
            pats.append("process_lrm_event: LRM operation %s_stop_0.*confirmed.*ok" % self.rid)
            if rsc.unique():
                pats.append("process_lrm_event: LRM operation %s_start_0.*confirmed.*ok" % self.rid)
            else:
                # Anonymous clones may get restarted with a different clone number
                pats.append("process_lrm_event: LRM operation .*_start_0.*confirmed.*ok")

        watch = self.create_watch(pats, 60)
        watch.setwatch()
        
        self.CM.rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self.rid, node))

        self.set_timer("recover")
        watch.lookforall()
        self.log_timer("recover")

        self.CM.cluster_stable()
        recovered=self.CM.ResourceLocation(self.rid)

        if watch.unmatched: 
            return self.failure("Patterns not found: %s" % repr(watch.unmatched))

        elif rsc.unique() and len(recovered) > 1:
            return self.failure("%s is now active on more than one node: %s"%(self.rid, repr(recovered)))

        elif len(recovered) > 0:
            self.CM.debug("%s is running on: %s" %(self.rid, repr(recovered)))

        elif rsc.managed():
            return self.failure("%s was not recovered and is inactive" % self.rid)

        return self.success()

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''
        return [ """Updating failcount for %s""" % self.rid,
                 """LogActions: Recover %s""" % self.rid,
                 """LogActions: Recover %s""" % self.rid_alt,
                 """Unknown operation: fail""",
                 """(ERROR|error): sending stonithRA op to stonithd failed.""",
                 """(ERROR|error): process_lrm_event: LRM operation %s_%s_%d""" % (self.rid, self.action, self.interval),
                 """(ERROR|error): process_graph_event: Action %s_%s_%d .* initiated outside of a transition""" % (self.rid, self.action, self.interval),
                 ]

AllTestClasses.append(ResourceRecover)

###################################################################
class ComponentFail(CTSTest):
###################################################################
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="ComponentFail"
        self.startall = SimulStartLite(cm)
        self.complist = cm.Components()
        self.patterns = []
        self.okerrpatterns = []
        self.is_unsafe = 1

    def __call__(self, node):
        '''Perform the 'ComponentFail' test. '''
        self.incr("calls")
        self.patterns = []
        self.okerrpatterns = []

        # start all nodes
        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self.CM.cluster_stable(self.CM["StableTime"]):
            return self.failure("Setup failed - unstable")

        node_is_dc = self.CM.is_node_dc(node, None)

        # select a component to kill
        chosen = self.CM.Env.RandomGen.choice(self.complist)
        while chosen.dc_only == 1 and node_is_dc == 0:
            chosen = self.CM.Env.RandomGen.choice(self.complist)

        self.CM.debug("...component %s (dc=%d,boot=%d)" % (chosen.name, node_is_dc,chosen.triggersreboot))
        self.incr(chosen.name)
        
        if chosen.name != "aisexec":
            if self.CM["Name"] != "crm-lha" or chosen.name != "pengine":
                self.patterns.append(self.CM["Pat:ChildKilled"] %(node, chosen.name))
                self.patterns.append(self.CM["Pat:ChildRespawn"] %(node, chosen.name))

        self.patterns.extend(chosen.pats)
        if node_is_dc:
          self.patterns.extend(chosen.dc_pats)

        # In an ideal world, this next stuff should be in the "chosen" object as a member function
        if self.CM["Name"] == "crm-lha" and chosen.triggersreboot:
            # Make sure the node goes down and then comes back up if it should reboot...
            for other in self.CM.Env["nodes"]:
                if other != node:
                    self.patterns.append(self.CM["Pat:They_stopped"] %(other, self.CM.key_for_node(node)))
            self.patterns.append(self.CM["Pat:Slave_started"] % node)
            self.patterns.append(self.CM["Pat:Local_started"] % node)

            if chosen.dc_only: 
                # Sometimes these will be in the log, and sometimes they won't...
                self.okerrpatterns.append("%s .*Process %s:.* exited" %(node, chosen.name))
                self.okerrpatterns.append("%s .*I_ERROR.*crmdManagedChildDied" %node)
                self.okerrpatterns.append("%s .*The %s subsystem terminated unexpectedly" %(node, chosen.name))
                self.okerrpatterns.append("(ERROR|error): Client .* exited with return code")
            else:
                # Sometimes this won't be in the log...
                self.okerrpatterns.append(self.CM["Pat:ChildKilled"] %(node, chosen.name))
                self.okerrpatterns.append(self.CM["Pat:ChildRespawn"] %(node, chosen.name))
                self.okerrpatterns.append(self.CM["Pat:ChildExit"])

        # supply a copy so self.patterns doesnt end up empty
        tmpPats = []
        tmpPats.extend(self.patterns)
        self.patterns.extend(chosen.badnews_ignore)

        # Look for STONITH ops, depending on Env["at-boot"] we might need to change the nodes status
        stonithPats = []
        stonithPats.append(self.CM["Pat:Fencing_ok"] % node)
        stonith = self.create_watch(stonithPats, 0)
        stonith.setwatch()

        # set the watch for stable
        watch = self.create_watch(
            tmpPats, self.CM["DeadTime"] + self.CM["StableTime"] + self.CM["StartTime"])
        watch.setwatch()
        
        # kill the component
        chosen.kill(node)

        self.CM.debug("Waiting for the cluster to recover")
        self.CM.cluster_stable()

        self.CM.debug("Waiting for any STONITHd node to come back up")
        self.CM.ns.WaitForAllNodesToComeUp(self.CM.Env["nodes"], 600)

        self.CM.debug("Waiting for the cluster to re-stabilize with all nodes")
        self.CM.cluster_stable(self.CM["StartTime"])

        self.CM.debug("Checking if %s was shot" % node)
        shot = stonith.look(60)
        if shot:
            self.CM.debug("Found: "+ repr(shot))
            self.okerrpatterns.append(self.CM["Pat:Fencing_start"] % node)

            if self.CM.Env["at-boot"] == 0:
                self.CM.ShouldBeStatus[node]="down"

            # If fencing occurred, chances are many (if not all) the expected logs
            # will not be sent - or will be lost when the node reboots
            return self.success()

        # check for logs indicating a graceful recovery
        matched = watch.lookforall(allow_multiple_matches=1)
        if watch.unmatched:
            self.CM.log("Patterns not found: " + repr(watch.unmatched))

        self.CM.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self.CM.cluster_stable(self.CM["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected patterns")
        elif not is_stable:
            return self.failure("Cluster did not become stable")

        return self.success()

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''
    # Note that okerrpatterns refers to the last time we ran this test
    # The good news is that this works fine for us...
        self.okerrpatterns.extend(self.patterns)
        return self.okerrpatterns
    
AllTestClasses.append(ComponentFail)

####################################################################
class SplitBrainTest(CTSTest):
####################################################################
    '''It is used to test split-brain. when the path between the two nodes break
       check the two nodes both take over the resource'''
    def __init__(self,cm):
        CTSTest.__init__(self,cm)
        self.name = "SplitBrain"
        self.start = StartTest(cm)
        self.startall = SimulStartLite(cm)
        self.is_experimental = 1

    def isolate_partition(self, partition):
        other_nodes = []
        other_nodes.extend(self.CM.Env["nodes"])
        
        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self.CM.log("Node "+node+" not in " + repr(self.CM.Env["nodes"]) + " from " +repr(partition))
                
        if len(other_nodes) == 0:
            return 1

        self.CM.debug("Creating partition: " + repr(partition))
        self.CM.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            if not self.CM.isolate_node(node, other_nodes):
                self.CM.log("Could not isolate %s" % node)
                return 0

        return 1

    def heal_partition(self, partition):
        other_nodes = []
        other_nodes.extend(self.CM.Env["nodes"])

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self.CM.log("Node "+node+" not in " + repr(self.CM.Env["nodes"]))

        if len(other_nodes) == 0:
            return 1

        self.CM.debug("Healing partition: " + repr(partition))
        self.CM.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            self.CM.unisolate_node(node, other_nodes)

    def __call__(self, node):
        '''Perform split-brain test'''
        self.incr("calls")
        self.passed = 1
        partitions = {}

        ret = self.startall(None)
        if not ret:
            return self.failure("Setup failed")        

        while 1:
            # Retry until we get multiple partitions
            partitions = {}
            p_max = len(self.CM.Env["nodes"])
            for node in self.CM.Env["nodes"]:
                p = self.CM.Env.RandomGen.randint(1, p_max)
                if not partitions.has_key(p):
                    partitions[p]= []
                partitions[p].append(node)
            p_max = len(partitions.keys())
            if p_max > 1:
                break
            # else, try again
            
        self.CM.debug("Created %d partitions" % p_max)
        for key in partitions.keys():
            self.CM.debug("Partition["+str(key)+"]:\t"+repr(partitions[key]))

        # Disabling STONITH to reduce test complexity for now
        self.CM.rsh(node, "crm_attribute -V -n stonith-enabled -v false")

        for key in partitions.keys():
            self.isolate_partition(partitions[key])

        count = 30
        while count > 0: 
            if len(self.CM.find_partitions()) != p_max:
                time.sleep(10)
            else:
                break
        else:
            self.failure("Expected partitions were not created")
            
        # Target number of partitions formed - wait for stability
        if not self.CM.cluster_stable():
            self.failure("Partitioned cluster not stable")

        # Now audit the cluster state
        self.CM.partitions_expected = p_max
        if not self.audit():
            self.failure("Audits failed")
        self.CM.partitions_expected = 1

        # And heal them again
        for key in partitions.keys():
            self.heal_partition(partitions[key])

        # Wait for a single partition to form
        count = 30
        while count > 0: 
            if len(self.CM.find_partitions()) != 1:
                time.sleep(10)
                count -= 1
            else:
                break
        else:
            self.failure("Cluster did not reform")

        # Wait for it to have the right number of members
        count = 30
        while count > 0: 
            members = []

            partitions = self.CM.find_partitions()
            if len(partitions) > 0:
                members = partitions[0].split()

            if len(members) != len(self.CM.Env["nodes"]):
                time.sleep(10)
                count -= 1
            else:
                break
        else:
            self.failure("Cluster did not completely reform")

        # Wait up to 20 minutes - the delay is more preferable than
        # trying to continue with in a messed up state
        if not self.CM.cluster_stable(1200):
            self.failure("Reformed cluster not stable")
            answer = raw_input('Continue? [nY]')
            if answer and answer == "n":
                raise ValueError("Reformed cluster not stable")

        # Turn fencing back on
        if self.CM.Env["DoFencing"]:
            self.CM.rsh(node, "crm_attribute -V -D -n stonith-enabled")
        
        self.CM.cluster_stable()

        if self.passed:
            return self.success()
        return self.failure("See previous errors")

    def errorstoignore(self):
        '''Return list of errors which are 'normal' and should be ignored'''
        return [
            "Another DC detected:",
            "(ERROR|error): attrd_cib_callback: .*Application of an update diff failed",
            "crmd_ha_msg_callback:.*not in our membership list",
            "CRIT:.*node.*returning after partition",
            ]

    def is_applicable(self):
        if not self.is_applicable_common():
            return 0
        return len(self.CM.Env["nodes"]) > 2

AllTestClasses.append(SplitBrainTest)

####################################################################
class Reattach(CTSTest):
####################################################################
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="Reattach"
        self.startall = SimulStartLite(cm)
        self.restart1 = RestartTest(cm)
        self.stopall = SimulStopLite(cm)
        self.is_unsafe = 0 # Handled by canrunnow()

    def setup(self, node):
        attempt=0
        if not self.startall(None):
            return None

        # Make sure we are really _really_ stable and that all
        # resources, including those that depend on transient node
        # attributes, are started
        while not self.CM.cluster_stable(double_check=True):
            if attempt < 5:
                attempt += 1
                self.CM.debug("Not stable yet, re-testing")
            else:
                self.CM.log("Cluster is not stable")
                return None

        return 1

    def teardown(self, node):
        
        # Make sure 'node' is up
        start = StartTest(self.CM)
        start(node)

        is_managed = self.CM.rsh(node, "crm_attribute -Q -G -t crm_config -n is-managed-default -d true", 1)
        is_managed = is_managed[:-1] # Strip off the newline
        if is_managed != "true":
            self.CM.log("Attempting to re-enable resource management on %s (%s)" % (node, is_managed))
            managed = self.create_watch(["is-managed-default"], 60)
            managed.setwatch()
            
            self.CM.rsh(node, "crm_attribute -V -D -n is-managed-default")
            
            if not managed.lookforall():
                self.CM.log("Patterns not found: " + repr(managed.unmatched))
                self.CM.log("Could not re-enable resource management")
                return 0

        return 1

    def canrunnow(self, node):
        '''Return TRUE if we can meaningfully run right now'''
        if self.find_ocfs2_resources(node):
            self.CM.log("Detach/Reattach scenarios are not possible with OCFS2 services present")
            return 0
        return 1

    def __call__(self, node):
        self.incr("calls")

        pats = []
        managed = self.create_watch(["is-managed-default"], 60)
        managed.setwatch()
        
        self.CM.debug("Disable resource management")
        self.CM.rsh(node, "crm_attribute -V -n is-managed-default -v false")

        if not managed.lookforall():
            self.CM.log("Patterns not found: " + repr(managed.unmatched))
            return self.failure("Resource management not disabled")

        pats = []
        pats.append("process_lrm_event: .*_stop")
        pats.append("process_lrm_event: .*_start")
        pats.append("process_lrm_event: .*_promote")
        pats.append("process_lrm_event: .*_demote")
        pats.append("process_lrm_event: .*_migrate")

        watch = self.create_watch(pats, 60, "ShutdownActivity")
        watch.setwatch()

        self.CM.debug("Shutting down the cluster")
        ret = self.stopall(None)
        if not ret:
            self.CM.debug("Re-enable resource management")
            self.CM.rsh(node, "crm_attribute -V -D -n is-managed-default")
            return self.failure("Couldn't shut down the cluster")

        self.CM.debug("Bringing the cluster back up")
        ret = self.startall(None)
        time.sleep(5) # allow ping to update the CIB
        if not ret:
            self.CM.debug("Re-enable resource management")
            self.CM.rsh(node, "crm_attribute -V -D -n is-managed-default")
            return self.failure("Couldn't restart the cluster")

        if self.local_badnews("ResourceActivity:", watch):
            self.CM.debug("Re-enable resource management")
            self.CM.rsh(node, "crm_attribute -V -D -n is-managed-default")
            return self.failure("Resources stopped or started during cluster restart")

        watch = self.create_watch(pats, 60, "StartupActivity")
        watch.setwatch()

        managed = self.create_watch(["is-managed-default"], 60)
        managed.setwatch()
        
        self.CM.debug("Re-enable resource management")
        self.CM.rsh(node, "crm_attribute -V -D -n is-managed-default")

        if not managed.lookforall():
            self.CM.log("Patterns not found: " + repr(managed.unmatched))
            return self.failure("Resource management not enabled")

        self.CM.cluster_stable()

        # Ignore actions for STONITH resources
        ignore = []
        (rc, lines) = self.CM.rsh(node, "crm_resource -c", None)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self.CM, line)
                if r.rclass == "stonith":

                    self.CM.debug("Ignoring start actions for %s" % r.id)
                    ignore.append("process_lrm_event: LRM operation %s_start_0.*confirmed.*ok" % r.id)
        
        if self.local_badnews("ResourceActivity:", watch, ignore):
            return self.failure("Resources stopped or started after resource management was re-enabled")

        return ret

    def errorstoignore(self):
        '''Return list of errors which should be ignored'''
        return [ 
            "You may ignore this error if it is unmanaged.",
            "pingd: .*(ERROR|error): send_ipc_message:",
            "pingd: .*(ERROR|error): send_update:",
            "lrmd: .*(ERROR|error): notify_client:",
            ]

    def is_applicable(self):
        if self.CM["Name"] == "crm-lha":
            return None
        return 1

AllTestClasses.append(Reattach)

####################################################################
class SpecialTest1(CTSTest):
####################################################################
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="SpecialTest1"
        self.startall = SimulStartLite(cm)
        self.restart1 = RestartTest(cm)
        self.stopall = SimulStopLite(cm)

    def __call__(self, node):
        '''Perform the 'SpecialTest1' test for Andrew. '''
        self.incr("calls")

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Could not stop all nodes")

        #        Start the selected node
        ret = self.restart1(node)
        if not ret:
            return self.failure("Could not start "+node)

        #        Start all remaining nodes
        ret = self.startall(None)
        if not ret:
            return self.failure("Could not start the remaining nodes")

        return self.success()

AllTestClasses.append(SpecialTest1)

####################################################################
class HAETest(CTSTest):
####################################################################
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="HAETest"
        self.stopall = SimulStopLite(cm)
        self.startall = SimulStartLite(cm)
        self.is_loop = 1

    def setup(self, node):
        #  Start all remaining nodes
        ret = self.startall(None)
        if not ret:
            return self.failure("Couldn't start all nodes")
        return self.success()

    def teardown(self, node):
        # Stop everything
        ret = self.stopall(None)
        if not ret: 
            return self.failure("Couldn't stop all nodes")
        return self.success()

    def wait_on_state(self, node, resource, expected_clones, attempts=240):
        while attempts > 0:
            active=0
            (rc, lines) = self.CM.rsh(node, "crm_resource -r %s -W -Q" % resource, stdout=None)

            # Hack until crm_resource does the right thing
            if rc == 0 and lines:
                active = len(lines)
                
            if len(lines) == expected_clones:
                return 1
                
            elif rc == 1:
                self.CM.debug("Resource %s is still inactive" % resource)

            elif rc == 234:
                self.CM.log("Unknown resource %s" % resource)
                return 0

            elif rc == 246:
                self.CM.log("Cluster is inactive")
                return 0

            elif rc != 0:
                self.CM.log("Call to crm_resource failed, rc=%d" % rc)
                return 0

            else:
                self.CM.debug("Resource %s is active on %d times instead of %d" % (resource, active, expected_clones))

            attempts -= 1
            time.sleep(1)

        return 0

    def find_dlm(self, node):
        self.r_dlm = None

        (rc, lines) = self.CM.rsh(node, "crm_resource -c", None)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self.CM, line)
                if r.rtype == "controld" and r.parent != "NA":
                    self.CM.debug("Found dlm: %s" % self.r_dlm)
                    self.r_dlm = r.parent
                    return 1
        return 0

    def find_hae_resources(self, node):
        self.r_dlm = None
        self.r_o2cb = None
        self.r_ocfs2 = []

        if self.find_dlm(node):
            self.find_ocfs2_resources(node)

    def is_applicable(self):
        if not self.is_applicable_common():
            return 0
        if self.CM.Env["Schema"] == "hae":
            return 1
        return None

####################################################################
class HAERoleTest(HAETest):
####################################################################
    def __init__(self, cm):
        '''Lars' mount/unmount test for the HA extension. '''
        HAETest.__init__(self,cm)
        self.name="HAERoleTest"

    def change_state(self, node, resource, target):
        rc = self.CM.rsh(node, "crm_resource -V -r %s -p target-role -v %s  --meta" % (resource, target))
        return rc

    def __call__(self, node):
        self.incr("calls")
        lpc = 0
        failed = 0
        delay = 2
        done=time.time() + self.CM.Env["loop-minutes"]*60
        self.find_hae_resources(node)

        clone_max = len(self.CM.Env["nodes"])
        while time.time() <= done and not failed:
            lpc = lpc + 1

            self.change_state(node, self.r_dlm, "Stopped")
            if not self.wait_on_state(node, self.r_dlm, 0):
                self.failure("%s did not go down correctly" % self.r_dlm)
                failed = lpc

            self.change_state(node, self.r_dlm, "Started")
            if not self.wait_on_state(node, self.r_dlm, clone_max):
                self.failure("%s did not come up correctly" % self.r_dlm)
                failed = lpc

            if not self.wait_on_state(node, self.r_o2cb, clone_max):
                self.failure("%s did not come up correctly" % self.r_o2cb)
                failed = lpc
            
            for fs in self.r_ocfs2:
                if not self.wait_on_state(node, fs, clone_max):
                    self.failure("%s did not come up correctly" % fs)
                    failed = lpc

        if failed:
            return self.failure("iteration %d failed" % failed)
        return self.success()

AllTestClasses.append(HAERoleTest)

####################################################################
class HAEStandbyTest(HAETest):
####################################################################
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        HAETest.__init__(self,cm)
        self.name="HAEStandbyTest"

    def change_state(self, node, resource, target):
        rc = self.CM.rsh(node, "crm_standby -V -l reboot -v %s" % (target))
        return rc

    def __call__(self, node):
        self.incr("calls")

        lpc = 0
        failed = 0
        done=time.time() + self.CM.Env["loop-minutes"]*60
        self.find_hae_resources(node)

        clone_max = len(self.CM.Env["nodes"])
        while time.time() <= done and not failed:
            lpc = lpc + 1

            self.change_state(node, self.r_dlm, "true")
            if not self.wait_on_state(node, self.r_dlm, clone_max-1):
                self.failure("%s did not go down correctly" % self.r_dlm)
                failed = lpc

            self.change_state(node, self.r_dlm, "false")
            if not self.wait_on_state(node, self.r_dlm, clone_max):
                self.failure("%s did not come up correctly" % self.r_dlm)
                failed = lpc

            if not self.wait_on_state(node, self.r_o2cb, clone_max):
                self.failure("%s did not come up correctly" % self.r_o2cb)
                failed = lpc
            
            for fs in self.r_ocfs2:
                if not self.wait_on_state(node, fs, clone_max):
                    self.failure("%s did not come up correctly" % fs)
                    failed = lpc

        if failed:
            return self.failure("iteration %d failed" % failed)
        return self.success()

AllTestClasses.append(HAEStandbyTest)

###################################################################
class NearQuorumPointTest(CTSTest):
###################################################################
    '''
    This test brings larger clusters near the quorum point (50%).
    In addition, it will test doing starts and stops at the same time.

    Here is how I think it should work:
    - loop over the nodes and decide randomly which will be up and which
      will be down  Use a 50% probability for each of up/down.
    - figure out what to do to get into that state from the current state
    - in parallel, bring up those going up  and bring those going down.
    '''
    
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="NearQuorumPoint"

    def __call__(self, dummy):
        '''Perform the 'NearQuorumPoint' test. '''
        self.incr("calls")
        startset = []
        stopset = []
       
        stonith = self.CM.prepare_fencing_watcher("NearQuorumPoint")
        #decide what to do with each node
        for node in self.CM.Env["nodes"]:
            action = self.CM.Env.RandomGen.choice(["start","stop"])
            #action = self.CM.Env.RandomGen.choice(["start","stop","no change"])
            if action == "start" :
                startset.append(node)
            elif action == "stop" :
                stopset.append(node)
                
        self.CM.debug("start nodes:" + repr(startset))
        self.CM.debug("stop nodes:" + repr(stopset))

        #add search patterns
        watchpats = [ ]
        for node in stopset:
            if self.CM.ShouldBeStatus[node] == "up":
                watchpats.append(self.CM["Pat:We_stopped"] % node)
                
        for node in startset:
            if self.CM.ShouldBeStatus[node] == "down":
                #watchpats.append(self.CM["Pat:Slave_started"] % node)
                watchpats.append(self.CM["Pat:Local_started"] % node)
            else:
                for stopping in stopset:
                    if self.CM.ShouldBeStatus[stopping] == "up":
                        watchpats.append(self.CM["Pat:They_stopped"] % (node, self.CM.key_for_node(stopping)))
                
        if len(watchpats) == 0:
            return self.skipped()

        if len(startset) != 0:
            watchpats.append(self.CM["Pat:DC_IDLE"])

        watch = self.create_watch(watchpats, self.CM["DeadTime"]+10)
        
        watch.setwatch()
        
        #begin actions
        for node in stopset:
            if self.CM.ShouldBeStatus[node] == "up":
                self.CM.StopaCMnoBlock(node)
                
        for node in startset:
            if self.CM.ShouldBeStatus[node] == "down":
                self.CM.StartaCMnoBlock(node)
        
        #get the result        
        if watch.lookforall():
            self.CM.cluster_stable()
            self.CM.fencing_cleanup("NearQuorumPoint", stonith)
            return self.success()

        self.CM.log("Warn: Patterns not found: " + repr(watch.unmatched))
        
        #get the "bad" nodes
        upnodes = []        
        for node in stopset:
            if self.CM.StataCM(node) == 1:
                upnodes.append(node)
        
        downnodes = []
        for node in startset:
            if self.CM.StataCM(node) == 0:
                downnodes.append(node)

        self.CM.fencing_cleanup,("NearQuorumPoint", stonith)
        if upnodes == [] and downnodes == []:
            self.CM.cluster_stable()

            # Make sure they're completely down with no residule
            for node in stopset:
                self.CM.rsh(node, self.CM["StopCmd"])

            return self.success()

        if len(upnodes) > 0:
            self.CM.log("Warn: Unstoppable nodes: " + repr(upnodes))
        
        if len(downnodes) > 0:
            self.CM.log("Warn: Unstartable nodes: " + repr(downnodes))
        
        return self.failure()

    def is_applicable(self):
        if self.CM["Name"] == "crm-cman":
            return None
        return 1

AllTestClasses.append(NearQuorumPointTest)

###################################################################
class RollingUpgradeTest(CTSTest):
###################################################################
    '''Perform a rolling upgrade of the cluster'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="RollingUpgrade"
        self.start = StartTest(cm)
        self.stop = StopTest(cm)
        self.stopall = SimulStopLite(cm)
        self.startall = SimulStartLite(cm)

    def setup(self, node):
        #  Start all remaining nodes
        ret = self.stopall(None)
        if not ret:
            return self.failure("Couldn't stop all nodes")

        for node in self.CM.Env["nodes"]:
            if not self.downgrade(node, None):
                return self.failure("Couldn't downgrade %s" % node)

        ret = self.startall(None)
        if not ret:
            return self.failure("Couldn't start all nodes")
        return self.success()

    def teardown(self, node):
        # Stop everything
        ret = self.stopall(None)
        if not ret: 
            return self.failure("Couldn't stop all nodes")

        for node in self.CM.Env["nodes"]:
            if not self.upgrade(node, None):
                return self.failure("Couldn't upgrade %s" % node)

        return self.success()

    def install(self, node, version, start=1, flags="--force"):

        target_dir = "/tmp/rpm-%s" % version
        src_dir = "%s/%s" % (self.CM.Env["rpm-dir"], version)

        self.CM.log("Installing %s on %s with %s" % (version, node, flags))
        if not self.stop(node):
            return self.failure("stop failure: "+node)

        rc = self.CM.rsh(node, "mkdir -p %s" % target_dir)
        rc = self.CM.rsh(node, "rm -f %s/*.rpm" % target_dir)
        (rc, lines) = self.CM.rsh(node, "ls -1 %s/*.rpm" % src_dir, None)
        for line in lines:
            line = line[:-1]
            rc = self.CM.rsh.cp("%s" % (line), "%s:%s/" % (node, target_dir))
        rc = self.CM.rsh(node, "rpm -Uvh %s %s/*.rpm" % (flags, target_dir))

        if start and not self.start(node):
            return self.failure("start failure: "+node)

        return self.success()

    def upgrade(self, node, start=1):
        return self.install(node, self.CM.Env["current-version"], start)

    def downgrade(self, node, start=1):
        return self.install(node, self.CM.Env["previous-version"], start, "--force --nodeps")

    def __call__(self, node):
        '''Perform the 'Rolling Upgrade' test. '''
        self.incr("calls")

        for node in self.CM.Env["nodes"]:
            if self.upgrade(node):
                return self.failure("Couldn't upgrade %s" % node)

            self.CM.cluster_stable()

        return self.success()

    def is_applicable(self):
        if not self.is_applicable_common():
            return None

        if not self.CM.Env.has_key("rpm-dir"):
            return None
        if not self.CM.Env.has_key("current-version"):
            return None
        if not self.CM.Env.has_key("previous-version"):
            return None

        return 1

#        Register RestartTest as a good test to run
AllTestClasses.append(RollingUpgradeTest)

###################################################################
class BSC_AddResource(CTSTest):
###################################################################
    '''Add a resource to the cluster'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name="AddResource"
        self.resource_offset = 0
        self.cib_cmd="""cibadmin -C -o %s -X '%s' """

    def __call__(self, node):
        self.incr("calls")
        self.resource_offset =         self.resource_offset  + 1

        r_id = "bsc-rsc-%s-%d" % (node, self.resource_offset)
        start_pat = "crmd.*%s_start_0.*confirmed.*ok"

        patterns = []
        patterns.append(start_pat % r_id)

        watch = self.create_watch(patterns, self.CM["DeadTime"])
        watch.setwatch()

        fields = string.split(self.CM.Env["IPBase"], '.')
        fields[3] = str(int(fields[3])+1)
        ip = string.join(fields, '.')
        self.CM.Env["IPBase"] = ip

        if not self.make_ip_resource(node, r_id, "ocf", "IPaddr", ip):
            return self.failure("Make resource %s failed" % r_id)

        failed = 0
        watch_result = watch.lookforall()
        if watch.unmatched:
            for regex in watch.unmatched:
                self.CM.log ("Warn: Pattern not found: %s" % (regex))
                failed = 1

        if failed:
            return self.failure("Resource pattern(s) not found")

        if not self.CM.cluster_stable(self.CM["DeadTime"]):
            return self.failure("Unstable cluster")

        return self.success()

    def make_ip_resource(self, node, id, rclass, type, ip):
        self.CM.log("Creating %s::%s:%s (%s) on %s" % (rclass,type,id,ip,node))
        rsc_xml="""
<primitive id="%s" class="%s" type="%s"  provider="heartbeat">
    <instance_attributes id="%s"><attributes>
        <nvpair id="%s" name="ip" value="%s"/>
    </attributes></instance_attributes>
</primitive>""" % (id, rclass, type, id, id, ip)

        node_constraint="""
      <rsc_location id="run_%s" rsc="%s">
        <rule id="pref_run_%s" score="100">
          <expression id="%s_loc_expr" attribute="#uname" operation="eq" value="%s"/>
        </rule>
      </rsc_location>""" % (id, id, id, id, node)

        rc = 0
        (rc, lines) = self.CM.rsh(node, self.cib_cmd % ("constraints", node_constraint), None)
        if rc != 0:
            self.CM.log("Constraint creation failed: %d" % rc)
            return None

        (rc, lines) = self.CM.rsh(node, self.cib_cmd % ("resources", rsc_xml), None)
        if rc != 0:
            self.CM.log("Resource creation failed: %d" % rc)
            return None

        return 1

    def is_applicable(self):
        if self.CM.Env["DoBSC"]:
            return 1
        return None

AllTestClasses.append(BSC_AddResource)

class SimulStopLite(CTSTest):
###################################################################
    '''Stop any active nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="SimulStopLite"

    def __call__(self, dummy):
        '''Perform the 'SimulStopLite' setup work. '''
        self.incr("calls")

        self.CM.debug("Setup: " + self.name)

        #     We ignore the "node" parameter...
        watchpats = [ ]

        for node in self.CM.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "up":
                self.incr("WasStarted")
                watchpats.append(self.CM["Pat:We_stopped"] % node)
                #if self.CM.Env["use_logd"]:
                #    watchpats.append(self.CM["Pat:Logd_stopped"] % node)

        if len(watchpats) == 0:
            self.CM.clear_all_caches()
            return self.success()

        #     Stop all the nodes - at about the same time...
        watch = self.create_watch(watchpats, self.CM["DeadTime"]+10)

        watch.setwatch()
        self.set_timer()
        for node in self.CM.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "up":
                self.CM.StopaCMnoBlock(node)
        if watch.lookforall():
            self.CM.clear_all_caches()

            # Make sure they're completely down with no residule
            for node in self.CM.Env["nodes"]:
                self.CM.rsh(node, self.CM["StopCmd"])

            return self.success()

        did_fail=0
        up_nodes = []
        for node in self.CM.Env["nodes"]:
            if self.CM.StataCM(node) == 1:
                did_fail=1
                up_nodes.append(node)

        if did_fail:
            return self.failure("Active nodes exist: " + repr(up_nodes))

        self.CM.log("Warn: All nodes stopped but CTS didnt detect: " 
                    + repr(watch.unmatched))

        self.CM.clear_all_caches()
        return self.failure("Missing log message: "+repr(watch.unmatched))

    def is_applicable(self):
        '''SimulStopLite is a setup test and never applicable'''
        return 0

###################################################################
class SimulStartLite(CTSTest):
###################################################################
    '''Start any stopped nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name="SimulStartLite"
        
    def __call__(self, dummy):
        '''Perform the 'SimulStartList' setup work. '''
        self.incr("calls")
        self.CM.debug("Setup: " + self.name)

        #        We ignore the "node" parameter...
        node_list = []
        for node in self.CM.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "down":
                self.incr("WasStopped")
                node_list.append(node)

        self.set_timer()
        while len(node_list) > 0:
            watchpats = [ ]

            uppat = self.CM["Pat:Slave_started"]
            if self.CM.upcount() == 0:
                uppat = self.CM["Pat:Local_started"]

            watchpats.append(self.CM["Pat:DC_IDLE"])
            for node in node_list:
                watchpats.append(uppat % node)        
                watchpats.append(self.CM["Pat:InfraUp"] % node)
                watchpats.append(self.CM["Pat:PacemakerUp"] % node)
        
            #   Start all the nodes - at about the same time...
            watch = self.create_watch(watchpats, self.CM["DeadTime"]+10)
            watch.setwatch()
            
            stonith = self.CM.prepare_fencing_watcher(self.name)

            for node in node_list:
                self.CM.StartaCMnoBlock(node)

            watch.lookforall()
            node_list = self.CM.fencing_cleanup(self.name, stonith)

            # Remove node_list messages from watch.unmatched
            for node in node_list:
                if watch.unmatched:
                    watch.unmatched.remove(uppat % node)

            if watch.unmatched:
                for regex in watch.unmatched:
                    self.CM.log ("Warn: Startup pattern not found: %s" %(regex))

            if not self.CM.cluster_stable():
                return self.failure("Cluster did not stabilize")                 

        did_fail=0
        unstable = []
        for node in self.CM.Env["nodes"]:
            if self.CM.StataCM(node) == 0:
                did_fail=1
                unstable.append(node)

        if did_fail:
            return self.failure("Unstarted nodes exist: " + repr(unstable))

        unstable = []
        for node in self.CM.Env["nodes"]:
            if not self.CM.node_stable(node):
                did_fail=1
                unstable.append(node)

        if did_fail:
            return self.failure("Unstable cluster nodes exist: " + repr(unstable))

        return self.success() 


    def is_applicable(self):
        '''SimulStartLite is a setup test and never applicable'''
        return 0

def TestList(cm, audits):
    result = []
    for testclass in AllTestClasses:
        bound_test = testclass(cm)
        if bound_test.is_applicable():
            bound_test.Audits = audits
            result.append(bound_test)
    return result

# vim:ts=4:sw=4:et:
