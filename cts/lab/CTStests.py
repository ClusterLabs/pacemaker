""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

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
import tempfile

from stat import *

from pacemaker import BuildOptions
from pacemaker._cts.CTS import NodeStatus
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests import *
from pacemaker._cts.timer import Timer

AllTestClasses = [ ]
AllTestClasses.append(FlipTest)


class RestartTest(CTSTest):
    '''Stop and restart a node'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "Restart"
        self._start = StartTest(cm)
        self._stop = StopTest(cm)
        self.benchmark = True

    def __call__(self, node):
        '''Perform the 'restart' test. '''
        self.incr("calls")

        self.incr("node:" + node)

        ret1 = 1
        if self._cm.StataCM(node):
            self.incr("WasStopped")
            if not self._start(node):
                return self.failure("start (setup) failure: "+node)

        self.set_timer()
        if not self._stop(node):
            return self.failure("stop failure: "+node)
        if not self._start(node):
            return self.failure("start failure: "+node)
        return self.success()

#        Register RestartTest as a good test to run
AllTestClasses.append(RestartTest)


class StonithdTest(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name = "Stonithd"
        self._startall = SimulStartLite(cm)
        self.benchmark = True

    def __call__(self, node):
        self.incr("calls")
        if len(self._env["nodes"]) < 2:
            return self.skipped()

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        is_dc = self._cm.is_node_dc(node)

        watchpats = []
        watchpats.append(self.templates["Pat:Fencing_ok"] % node)
        watchpats.append(self.templates["Pat:NodeFenced"] % node)

        if not self._env["at-boot"]:
            self.debug("Expecting %s to stay down" % node)
            self._cm.ShouldBeStatus[node] = "down"
        else:
            self.debug("Expecting %s to come up again %d" % (node, self._env["at-boot"]))
            watchpats.append("%s.* S_STARTING -> S_PENDING" % node)
            watchpats.append("%s.* S_PENDING -> S_NOT_DC" % node)

        watch = self.create_watch(watchpats, 30 + self._env["DeadTime"] + self._env["StableTime"] + self._env["StartTime"])
        watch.set_watch()

        origin = self._env.random_gen.choice(self._env["nodes"])

        (rc, _) = self._rsh(origin, "stonith_admin --reboot %s -VVVVVV" % node)

        if rc == 124: # CRM_EX_TIMEOUT
            # Look for the patterns, usually this means the required
            # device was running on the node to be fenced - or that
            # the required devices were in the process of being loaded
            # and/or moved
            #
            # Effectively the node committed suicide so there will be
            # no confirmation, but pacemaker should be watching and
            # fence the node again

            self._logger.log("Fencing command on %s to fence %s timed out" % (origin, node))

        elif origin != node and rc != 0:
            self.debug("Waiting for the cluster to recover")
            self._cm.cluster_stable()

            self.debug("Waiting for fenced node to come back up")
            self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

            self._logger.log("Fencing command on %s failed to fence %s (rc=%d)" % (origin, node, rc))

        elif origin == node and rc != 255:
            # 255 == broken pipe, ie. the node was fenced as expected
            self._logger.log("Locally originated fencing returned %d" % rc)

        with Timer(self._logger, self.name, "fence"):
            matched = watch.look_for_all()

        self.set_timer("reform")
        if watch.unmatched:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected patterns")
        elif not is_stable:
            return self.failure("Cluster did not become stable")

        self.log_timer("reform")
        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ self.templates["Pat:Fencing_start"] % ".*",
                 self.templates["Pat:Fencing_ok"] % ".*",
                 self.templates["Pat:Fencing_active"],
                 r"error.*: Operation 'reboot' targeting .* by .* for stonith_admin.*: Timer expired" ]

    def is_applicable(self):
        if not CTSTest.is_applicable(self):
            return False

        if "DoFencing" in self._env:
            return self._env["DoFencing"]

        return True

AllTestClasses.append(StonithdTest)


class StartOnebyOne(CTSTest):
    '''Start all the nodes ~ one by one'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "StartOnebyOne"
        self.stopall = SimulStopLite(cm)
        self._start = StartTest(cm)
        self.ns = NodeStatus(cm.Env)

    def __call__(self, dummy):
        '''Perform the 'StartOnebyOne' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Test setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._start(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to start: " + repr(failed))

        return self.success()

#        Register StartOnebyOne as a good test to run
AllTestClasses.append(StartOnebyOne)


class SimulStart(CTSTest):
    '''Start all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStart"
        self.stopall = SimulStopLite(cm)
        self._startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStart' test. '''
        self.incr("calls")

        #        We ignore the "node" parameter...

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._startall(None):
            return self.failure("Startall failed")

        return self.success()

#        Register SimulStart as a good test to run
AllTestClasses.append(SimulStart)


class SimulStop(CTSTest):
    '''Stop all the nodes ~ simultaneously'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SimulStop"
        self._startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)

    def __call__(self, dummy):
        '''Perform the 'SimulStop' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self.stopall(None):
            return self.failure("Stopall failed")

        return self.success()

#     Register SimulStop as a good test to run
AllTestClasses.append(SimulStop)


class StopOnebyOne(CTSTest):
    '''Stop all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "StopOnebyOne"
        self._startall = SimulStartLite(cm)
        self._stop = StopTest(cm)

    def __call__(self, dummy):
        '''Perform the 'StopOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        failed = []
        self.set_timer()
        for node in self._env["nodes"]:
            if not self._stop(node):
                failed.append(node)

        if len(failed) > 0:
            return self.failure("Some node failed to stop: " + repr(failed))

        return self.success()

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(StopOnebyOne)


class RestartOnebyOne(CTSTest):
    '''Restart all the nodes in order'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "RestartOnebyOne"
        self._startall = SimulStartLite(cm)

    def __call__(self, dummy):
        '''Perform the 'RestartOnebyOne' test. '''
        self.incr("calls")

        #     We ignore the "node" parameter...

        #     Start up all the nodes...
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        did_fail = []
        self.set_timer()
        self.restart = RestartTest(self._cm)
        for node in self._env["nodes"]:
            if not self.restart(node):
                did_fail.append(node)

        if did_fail:
            return self.failure("Could not restart %d nodes: %s"
                                % (len(did_fail), repr(did_fail)))
        return self.success()

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(RestartOnebyOne)


class PartialStart(CTSTest):
    '''Start a node - but tell it to stop before it finishes starting up'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "PartialStart"
        self._startall = SimulStartLite(cm)
        self.stopall = SimulStopLite(cm)
        self._stop = StopTest(cm)

    def __call__(self, node):
        '''Perform the 'PartialStart' test. '''
        self.incr("calls")

        ret = self.stopall(None)
        if not ret:
            return self.failure("Setup failed")

        watchpats = []
        watchpats.append("pacemaker-controld.*Connecting to .* cluster infrastructure")
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
        watch.set_watch()

        self._cm.StartaCMnoBlock(node)
        ret = watch.look_for_all()
        if not ret:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))
            return self.failure("Setup of %s failed" % node)

        ret = self._stop(node)
        if not ret:
            return self.failure("%s did not stop in time" % node)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        # We might do some fencing in the 2-node case if we make it up far enough
        return [ r"Executing reboot fencing operation",
                 r"Requesting fencing \([^)]+\) targeting node " ]

#     Register StopOnebyOne as a good test to run
AllTestClasses.append(PartialStart)


class StandbyTest(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "Standby"
        self.benchmark = True

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    # make sure the node is active
    # set the node to standby mode
    # check resources, none resource should be running on the node
    # set the node to active mode
    # check resouces, resources should have been migrated back (SHOULD THEY?)

    def __call__(self, node):

        self.incr("calls")
        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        self.debug("Make sure node %s is active" % node)
        if self._cm.StandbyStatus(node) != "off":
            if not self._cm.SetStandbyMode(node, "off"):
                return self.failure("can't set node %s to active mode" % node)

        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))

        self.debug("Getting resources running on node %s" % node)
        rsc_on_node = self._cm.active_resources(node)

        watchpats = []
        watchpats.append(r"State transition .* -> S_POLICY_ENGINE")
        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)
        watch.set_watch()

        self.debug("Setting node %s to standby mode" % node)
        if not self._cm.SetStandbyMode(node, "on"):
            return self.failure("can't set node %s to standby mode" % node)

        self.set_timer("on")

        ret = watch.look_for_all()
        if not ret:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))
            self._cm.SetStandbyMode(node, "off")
            return self.failure("cluster didn't react to standby change on %s" % node)

        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "on":
            return self.failure("standby status of %s is [%s] but we expect [on]" % (node, status))
        self.log_timer("on")

        self.debug("Checking resources")
        bad_run = self._cm.active_resources(node)
        if len(bad_run) > 0:
            rc = self.failure("%s set to standby, %s is still running on it" % (node, repr(bad_run)))
            self.debug("Setting node %s to active mode" % node)
            self._cm.SetStandbyMode(node, "off")
            return rc

        self.debug("Setting node %s to active mode" % node)
        if not self._cm.SetStandbyMode(node, "off"):
            return self.failure("can't set node %s to active mode" % node)

        self.set_timer("off")
        self._cm.cluster_stable()

        status = self._cm.StandbyStatus(node)
        if status != "off":
            return self.failure("standby status of %s is [%s] but we expect [off]" % (node, status))
        self.log_timer("off")

        return self.success()

AllTestClasses.append(StandbyTest)


class ValgrindTest(CTSTest):
    '''Check for memory leaks'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "Valgrind"
        self.stopall = SimulStopLite(cm)
        self._startall = SimulStartLite(cm)
        self.is_valgrind = True
        self.is_loop = True

    def setup(self, node):
        self.incr("calls")

        ret = self.stopall(None)
        if not ret:
            return self.failure("Stop all nodes failed")

        # @TODO Edit /etc/sysconfig/pacemaker on all nodes to enable valgrind,
        # and clear any valgrind logs from previous runs. For now, we rely on
        # the user to do this manually.

        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        return self.success()

    def teardown(self, node):
        # Return all nodes to normal
        # @TODO Edit /etc/sysconfig/pacemaker on all nodes to disable valgrind
        ret = self.stopall(None)
        if not ret:
            return self.failure("Stop all nodes failed")

        return self.success()

    def find_leaks(self):
        # Check for leaks
        # (no longer used but kept in case feature is restored)
        leaked = []
        self._stop = StopTest(self._cm)

        for node in self._env["nodes"]:
            rc = self._stop(node)
            if not rc:
                self.failure("Couldn't shut down %s" % node)

            (rc, _) = self._rsh(node, "grep -e indirectly.*lost:.*[1-9] -e definitely.*lost:.*[1-9] -e (ERROR|error).*SUMMARY:.*[1-9].*errors %s" % self._logger.logPat)
            if rc != 1:
                leaked.append(node)
                self.failure("Valgrind errors detected on %s" % node)
                (_, output) = self._rsh(node, "grep -e lost: -e SUMMARY: %s" % self._logger.logPat, verbose=1)
                for line in output:
                    self._logger.log(line)
                (_, output) = self._rsh(node, "cat %s" % self._logger.logPat, verbose=1)
                for line in output:
                    self.debug(line)

        self._rsh(node, "rm -f %s" % self._logger.logPat, verbose=1)
        return leaked

    def __call__(self, node):
        #leaked = self.find_leaks()
        #if len(leaked) > 0:
        #    return self.failure("Nodes %s leaked" % repr(leaked))

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"pacemaker-based.*: \*\*\*\*\*\*\*\*\*\*\*\*\*",
                 r"pacemaker-based.*: .* avoid confusing Valgrind",
                 r"HA_VALGRIND_ENABLED" ]


class StandbyLoopTest(ValgrindTest):
    '''Check for memory leaks by putting a node in and out of standby for an hour'''
    # @TODO This is not a useful test for memory leaks
    def __init__(self, cm):
        ValgrindTest.__init__(self,cm)
        self.name = "StandbyLoop"

    def __call__(self, node):

        lpc = 0
        delay = 2
        failed = 0
        done = time.time() + self._env["loop-minutes"] * 60
        while time.time() <= done and not failed:
            lpc = lpc + 1

            time.sleep(delay)
            if not self._cm.SetStandbyMode(node, "on"):
                self.failure("can't set node %s to standby mode" % node)
                failed = lpc

            time.sleep(delay)
            if not self._cm.SetStandbyMode(node, "off"):
                self.failure("can't set node %s to active mode" % node)
                failed = lpc

        leaked = self.find_leaks()
        if failed:
            return self.failure("Iteration %d failed" % failed)
        elif len(leaked) > 0:
            return self.failure("Nodes %s leaked" % repr(leaked))

        return self.success()

#AllTestClasses.append(StandbyLoopTest)


class BandwidthTest(CTSTest):
#        Tests should not be cluster-manager-specific
#        If you need to find out cluster manager configuration to do this, then
#        it should be added to the generic cluster manager API.
    '''Test the bandwidth which the cluster uses'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)

        self.stats["min"] = 0
        self.stats["max"] = 0
        self.stats["totalbandwidth"] = 0

        self.name = "Bandwidth"
        self._start = StartTest(cm)
        (handle, self.tempfile) = tempfile.mkstemp(".cts")
        os.close(handle)
        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        '''Perform the Bandwidth test'''
        self.incr("calls")

        if self._cm.upcount() < 1:
            return self.skipped()

        Path = self._cm.InternalCommConfig()
        if "ip" not in Path["mediatype"]:
             return self.skipped()

        port = Path["port"][0]
        port = int(port)

        ret = self._startall(None)
        if not ret:
            return self.failure("Test setup failed")
        time.sleep(5)  # We get extra messages right after startup.

        fstmpfile = "/var/run/band_estimate"
        dumpcmd = "tcpdump -p -n -c 102 -i any udp port %d > %s 2>&1" \
        %                (port, fstmpfile)

        (rc, _) = self._rsh(node, dumpcmd)
        if rc == 0:
            farfile = "root@%s:%s" % (node, fstmpfile)
            self._rsh.copy(farfile, self.tempfile)
            Bandwidth = self.countbandwidth(self.tempfile)
            if not Bandwidth:
                self._logger.log("Could not compute bandwidth.")
                return self.success()
            intband = int(Bandwidth + 0.5)
            self._logger.log("...bandwidth: %d bits/sec" % intband)

            self.stats["totalbandwidth"] += Bandwidth

            if self.stats["min"] == 0:
                self.stats["min"] = Bandwidth

            if Bandwidth > self.stats["max"]:
                self.stats["max"] = Bandwidth

            if Bandwidth < self.stats["min"]:
                self.stats["min"] = Bandwidth

            self._rsh(node, "rm -f %s" % fstmpfile)
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
                count = count + 1
                linesplit = line.split(" ")
                for j in range(len(linesplit)-1):
                    if linesplit[j] == "udp": break
                    if linesplit[j] == "length:": break

                try:
                    sum = sum + int(linesplit[j+1])
                except ValueError:
                    self._logger.log("Invalid tcpdump line: %s" % line)
                    return None
                T1 = linesplit[0]
                timesplit = T1.split(":")
                time2split = timesplit[2].split(".")
                time1 = (int(timesplit[0])*60+int(timesplit[1]))*60+int(time2split[0])+int(time2split[1])*0.000001
                break

        while count < 100:
            line = fp.readline()
            if not line:
                return None
            if re.search("udp",line) or re.search("UDP,", line):
                count = count+1
                linessplit = line.split(" ")
                for j in range(len(linessplit)-1):
                    if linessplit[j] == "udp": break
                    if linessplit[j] == "length:": break
                try:
                    sum = int(linessplit[j+1]) + sum
                except ValueError:
                    self._logger.log("Invalid tcpdump line: %s" % line)
                    return None

        T2 = linessplit[0]
        timesplit = T2.split(":")
        time2split = timesplit[2].split(".")
        time2 = (int(timesplit[0])*60+int(timesplit[1]))*60+int(time2split[0])+int(time2split[1])*0.000001
        time = time2-time1
        if (time <= 0):
            return 0
        return int((sum*8)/time)

    def is_applicable(self):
        '''BandwidthTest never applicable'''
        return False

AllTestClasses.append(BandwidthTest)


###################################################################
class MaintenanceMode(CTSTest):
###################################################################
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "MaintenanceMode"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)
        self.max = 30
        self.benchmark = True
        self.action = "asyncmon"
        self.interval = 0
        self.rid = "maintenanceDummy"

    def toggleMaintenanceMode(self, node, action):
        pats = []
        pats.append(self.templates["Pat:DC_IDLE"])

        # fail the resource right after turning Maintenance mode on
        # verify it is not recovered until maintenance mode is turned off
        if action == "On":
            pats.append(self.templates["Pat:RscOpFail"] % (self.action, self.rid))
        else:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))
            pats.append(self.templates["Pat:RscOpOK"] % ("start", self.rid))

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self.debug("Turning maintenance mode %s" % action)
        self._rsh(node, self.templates["MaintenanceMode%s" % (action)])
        if (action == "On"):
            self._rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self.rid, node))

        with Timer(self._logger, self.name, "recover%s" % action):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when turning maintenance mode %s" % action)
            return repr(watch.unmatched)

        return ""

    def insertMaintenanceDummy(self, node):
        pats = []
        pats.append(("%s.*" % node) + (self.templates["Pat:RscOpOK"] % ("start", self.rid)))

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.AddDummyRsc(node, self.rid)

        with Timer(self._logger, self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding maintenance dummy resource")
            return repr(watch.unmatched)
        return ""

    def removeMaintenanceDummy(self, node):
        pats = []
        pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))

        watch = self.create_watch(pats, 60)
        watch.set_watch()
        self._cm.RemoveDummyRsc(node, self.rid)

        with Timer(self._logger, self.name, "removeDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when removing maintenance dummy resource")
            return repr(watch.unmatched)
        return ""

    def managedRscList(self, node):
        rscList = []
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)
                if tmp.managed:
                    rscList.append(tmp.id)

        return rscList

    def verifyResources(self, node, rscList, managed):
        managedList = list(rscList)
        managed_str = "managed"
        if not managed:
            managed_str = "unmanaged"

        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                tmp = AuditResource(self._cm, line)
                if managed and not tmp.managed:
                    continue
                elif not managed and tmp.managed:
                    continue
                elif managedList.count(tmp.id):
                    managedList.remove(tmp.id)

        if len(managedList) == 0:
            self.debug("Found all %s resources on %s" % (managed_str, node))
            return True

        self._logger.log("Could not find all %s resources on %s. %s" % (managed_str, node, managedList))
        return False

    def __call__(self, node):
        '''Perform the 'MaintenanceMode' test. '''
        self.incr("calls")
        verify_managed = False
        verify_unmanaged = False
        failPat = ""

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        # get a list of all the managed resources. We use this list
        # after enabling maintenance mode to verify all managed resources
        # become un-managed.  After maintenance mode is turned off, we use
        # this list to verify all the resources become managed again.
        managedResources = self.managedRscList(node)
        if len(managedResources) == 0:
            self._logger.log("No managed resources on %s" % node)
            return self.skipped()

        # insert a fake resource we can fail during maintenance mode
        # so we can verify recovery does not take place until after maintenance
        # mode is disabled.
        failPat = failPat + self.insertMaintenanceDummy(node)

        # toggle maintenance mode ON, then fail dummy resource.
        failPat = failPat + self.toggleMaintenanceMode(node, "On")

        # verify all the resources are now unmanaged
        if self.verifyResources(node, managedResources, False):
            verify_unmanaged = True

        # Toggle maintenance mode  OFF, verify dummy is recovered.
        failPat = failPat + self.toggleMaintenanceMode(node, "Off")

        # verify all the resources are now managed again
        if self.verifyResources(node, managedResources, True):
            verify_managed = True

        # Remove our maintenance dummy resource.
        failPat = failPat + self.removeMaintenanceDummy(node)

        self._cm.cluster_stable()

        if failPat != "":
            return self.failure("Unmatched patterns: %s" % (failPat))
        elif verify_unmanaged is False:
            return self.failure("Failed to verify resources became unmanaged during maintenance mode")
        elif verify_managed is False:
            return self.failure("Failed to verify resources switched back to managed after disabling maintenance mode")

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for %s" % self.rid,
                 r"schedulerd.*: Recover\s+%s\s+\(.*\)" % self.rid,
                 r"Unknown operation: fail",
                 self.templates["Pat:RscOpOK"] % (self.action, self.rid),
                 r"(ERROR|error).*: Action %s_%s_%d .* initiated outside of a transition" % (self.rid, self.action, self.interval) ]

AllTestClasses.append(MaintenanceMode)


class ResourceRecover(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "ResourceRecover"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)
        self.max = 30
        self.rid = None
        self.rid_alt = None
        self.benchmark = True

        # these are the values used for the new LRM API call
        self.action = "asyncmon"
        self.interval = 0

    def __call__(self, node):
        '''Perform the 'ResourceRecover' test. '''
        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        # List all resources active on the node (skip test if none)
        resourcelist = self._cm.active_resources(node)
        if len(resourcelist) == 0:
            self._logger.log("No active resources on %s" % node)
            return self.skipped()

        # Choose one resource at random
        rsc = self.choose_resource(node, resourcelist)
        if rsc is None:
            return self.failure("Could not get details of resource '%s'" % self.rid)
        if rsc.id == rsc.clone_id:
            self.debug("Failing " + rsc.id)
        else:
            self.debug("Failing " + rsc.id + " (also known as " + rsc.clone_id + ")")

        # Log patterns to watch for (failure, plus restart if managed)
        pats = []
        pats.append(self.templates["Pat:CloneOpFail"] % (self.action, rsc.id, rsc.clone_id))
        if rsc.managed:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))
            if rsc.unique:
                pats.append(self.templates["Pat:RscOpOK"] % ("start", self.rid))
            else:
                # Anonymous clones may get restarted with a different clone number
                pats.append(self.templates["Pat:RscOpOK"] % ("start", ".*"))

        # Fail resource. (Ideally, we'd fail it twice, to ensure the fail count
        # is incrementing properly, but it might restart on a different node.
        # We'd have to temporarily ban it from all other nodes and ensure the
        # migration-threshold hasn't been reached.)
        if self.fail_resource(rsc, node, pats) is None:
            return None # self.failure() already called

        return self.success()

    def choose_resource(self, node, resourcelist):
        """ Choose a random resource to target """

        self.rid = self._env.random_gen.choice(resourcelist)
        self.rid_alt = self.rid
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if line.startswith("Resource: "):
                rsc = AuditResource(self._cm, line)
                if rsc.id == self.rid:
                    # Handle anonymous clones that get renamed
                    self.rid = rsc.clone_id
                    return rsc
        return None

    def get_failcount(self, node):
        """ Check the fail count of targeted resource on given node """

        (rc, lines) = self._rsh(node,
                               "crm_failcount --quiet --query --resource %s "
                               "--operation %s --interval %d "
                               "--node %s" % (self.rid, self.action,
                               self.interval, node), verbose=1)
        if rc != 0 or len(lines) != 1:
            self._logger.log("crm_failcount on %s failed (%d): %s" % (node, rc,
                            " // ".join(map(str.strip, lines))))
            return -1
        try:
            failcount = int(lines[0])
        except (IndexError, ValueError):
            self._logger.log("crm_failcount output on %s unparseable: %s" % (node,
                            ' '.join(lines)))
            return -1
        return failcount

    def fail_resource(self, rsc, node, pats):
        """ Fail the targeted resource, and verify as expected """

        orig_failcount = self.get_failcount(node)

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self.rid, node))

        with Timer(self._logger, self.name, "recover"):
            watch.look_for_all()

        self._cm.cluster_stable()
        recovered = self._cm.ResourceLocation(self.rid)

        if watch.unmatched:
            return self.failure("Patterns not found: %s" % repr(watch.unmatched))

        elif rsc.unique and len(recovered) > 1:
            return self.failure("%s is now active on more than one node: %s"%(self.rid, repr(recovered)))

        elif len(recovered) > 0:
            self.debug("%s is running on: %s" % (self.rid, repr(recovered)))

        elif rsc.managed:
            return self.failure("%s was not recovered and is inactive" % self.rid)

        new_failcount = self.get_failcount(node)
        if new_failcount != (orig_failcount + 1):
            return self.failure("%s fail count is %d not %d" % (self.rid,
                                new_failcount, orig_failcount + 1))

        return 0 # Anything but None is success

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for %s" % self.rid,
                 r"schedulerd.*: Recover\s+(%s|%s)\s+\(.*\)" % (self.rid, self.rid_alt),
                 r"Unknown operation: fail",
                 self.templates["Pat:RscOpOK"] % (self.action, self.rid),
                 r"(ERROR|error).*: Action %s_%s_%d .* initiated outside of a transition" % (self.rid, self.action, self.interval) ]

AllTestClasses.append(ResourceRecover)


class ComponentFail(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "ComponentFail"
        self._startall = SimulStartLite(cm)
        self.complist = cm.Components()
        self.patterns = []
        self.okerrpatterns = []
        self.is_unsafe = True

    def __call__(self, node):
        '''Perform the 'ComponentFail' test. '''
        self.incr("calls")
        self.patterns = []
        self.okerrpatterns = []

        # start all nodes
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._cm.cluster_stable(self._env["StableTime"]):
            return self.failure("Setup failed - unstable")

        node_is_dc = self._cm.is_node_dc(node, None)

        # select a component to kill
        chosen = self._env.random_gen.choice(self.complist)
        while chosen.dc_only and node_is_dc == 0:
            chosen = self._env.random_gen.choice(self.complist)

        self.debug("...component %s (dc=%d)" % (chosen.name, node_is_dc))
        self.incr(chosen.name)

        if chosen.name != "corosync":
            self.patterns.append(self.templates["Pat:ChildKilled"] %(node, chosen.name))
            self.patterns.append(self.templates["Pat:ChildRespawn"] %(node, chosen.name))

        self.patterns.extend(chosen.pats)
        if node_is_dc:
          self.patterns.extend(chosen.dc_pats)

        # @TODO this should be a flag in the Component
        if chosen.name in [ "corosync", "pacemaker-based", "pacemaker-fenced" ]:
            # Ignore actions for fence devices if fencer will respawn
            # (their registration will be lost, and probes will fail)
            self.okerrpatterns = [ self.templates["Pat:Fencing_active"] ]
            (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
            for line in lines:
                if re.search("^Resource", line):
                    r = AuditResource(self._cm, line)
                    if r.rclass == "stonith":
                        self.okerrpatterns.append(self.templates["Pat:Fencing_recover"] % r.id)
                        self.okerrpatterns.append(self.templates["Pat:Fencing_probe"] % r.id)

        # supply a copy so self.patterns doesn't end up empty
        tmpPats = []
        tmpPats.extend(self.patterns)
        self.patterns.extend(chosen.badnews_ignore)

        # Look for STONITH ops, depending on Env["at-boot"] we might need to change the nodes status
        stonithPats = []
        stonithPats.append(self.templates["Pat:Fencing_ok"] % node)
        stonith = self.create_watch(stonithPats, 0)
        stonith.set_watch()

        # set the watch for stable
        watch = self.create_watch(
            tmpPats, self._env["DeadTime"] + self._env["StableTime"] + self._env["StartTime"])
        watch.set_watch()

        # kill the component
        chosen.kill(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for any fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        self._cm.cluster_stable(self._env["StartTime"])

        self.debug("Checking if %s was shot" % node)
        shot = stonith.look(60)
        if shot:
            self.debug("Found: " + repr(shot))
            self.okerrpatterns.append(self.templates["Pat:Fencing_start"] % node)

            if not self._env["at-boot"]:
                self._cm.ShouldBeStatus[node] = "down"

            # If fencing occurred, chances are many (if not all) the expected logs
            # will not be sent - or will be lost when the node reboots
            return self.success()

        # check for logs indicating a graceful recovery
        matched = watch.look_for_all(allow_multiple_matches=True)
        if watch.unmatched:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected %s patterns" % chosen.name)
        elif not is_stable:
            return self.failure("Cluster did not become stable after killing %s" % chosen.name)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        # Note that okerrpatterns refers to the last time we ran this test
        # The good news is that this works fine for us...
        self.okerrpatterns.extend(self.patterns)
        return self.okerrpatterns

AllTestClasses.append(ComponentFail)


class SplitBrainTest(CTSTest):
    '''It is used to test split-brain. when the path between the two nodes break
       check the two nodes both take over the resource'''
    def __init__(self,cm):
        CTSTest.__init__(self,cm)
        self.name = "SplitBrain"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)
        self.is_experimental = True

    def isolate_partition(self, partition):
        other_nodes = []
        other_nodes.extend(self._env["nodes"])

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self._logger.log("Node "+node+" not in " + repr(self._env["nodes"]) + " from " +repr(partition))

        if len(other_nodes) == 0:
            return 1

        self.debug("Creating partition: " + repr(partition))
        self.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            if not self._cm.isolate_node(node, other_nodes):
                self._logger.log("Could not isolate %s" % node)
                return 0

        return 1

    def heal_partition(self, partition):
        other_nodes = []
        other_nodes.extend(self._env["nodes"])

        for node in partition:
            try:
                other_nodes.remove(node)
            except ValueError:
                self._logger.log("Node "+node+" not in " + repr(self._env["nodes"]))

        if len(other_nodes) == 0:
            return 1

        self.debug("Healing partition: " + repr(partition))
        self.debug("Everyone else: " + repr(other_nodes))

        for node in partition:
            self._cm.unisolate_node(node, other_nodes)

    def __call__(self, node):
        '''Perform split-brain test'''
        self.incr("calls")
        self.passed = True
        partitions = {}

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        while 1:
            # Retry until we get multiple partitions
            partitions = {}
            p_max = len(self._env["nodes"])
            for node in self._env["nodes"]:
                p = self._env.random_gen.randint(1, p_max)
                if not p in partitions:
                    partitions[p] = []
                partitions[p].append(node)
            p_max = len(list(partitions.keys()))
            if p_max > 1:
                break
            # else, try again

        self.debug("Created %d partitions" % p_max)
        for key in list(partitions.keys()):
            self.debug("Partition["+str(key)+"]:\t"+repr(partitions[key]))

        # Disabling STONITH to reduce test complexity for now
        self._rsh(node, "crm_attribute -V -n stonith-enabled -v false")

        for key in list(partitions.keys()):
            self.isolate_partition(partitions[key])

        count = 30
        while count > 0:
            if len(self._cm.find_partitions()) != p_max:
                time.sleep(10)
            else:
                break
        else:
            self.failure("Expected partitions were not created")

        # Target number of partitions formed - wait for stability
        if not self._cm.cluster_stable():
            self.failure("Partitioned cluster not stable")

        # Now audit the cluster state
        self._cm.partitions_expected = p_max
        if not self.audit():
            self.failure("Audits failed")
        self._cm.partitions_expected = 1

        # And heal them again
        for key in list(partitions.keys()):
            self.heal_partition(partitions[key])

        # Wait for a single partition to form
        count = 30
        while count > 0:
            if len(self._cm.find_partitions()) != 1:
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

            partitions = self._cm.find_partitions()
            if len(partitions) > 0:
                members = partitions[0].split()

            if len(members) != len(self._env["nodes"]):
                time.sleep(10)
                count -= 1
            else:
                break
        else:
            self.failure("Cluster did not completely reform")

        # Wait up to 20 minutes - the delay is more preferable than
        # trying to continue with in a messed up state
        if not self._cm.cluster_stable(1200):
            self.failure("Reformed cluster not stable")
            if self._env["continue"]:
                answer = "Y"
            else:
                try:
                    answer = input('Continue? [nY]')
                except EOFError as e:
                    answer = "n" 
            if answer and answer == "n":
                raise ValueError("Reformed cluster not stable")

        # Turn fencing back on
        if self._env["DoFencing"]:
            self._rsh(node, "crm_attribute -V -D -n stonith-enabled")

        self._cm.cluster_stable()

        if self.passed:
            return self.success()
        return self.failure("See previous errors")

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Another DC detected:",
                 r"(ERROR|error).*: .*Application of an update diff failed",
                 r"pacemaker-controld.*:.*not in our membership list",
                 r"CRIT:.*node.*returning after partition" ]

    def is_applicable(self):
        if not CTSTest.is_applicable(self):
            return False
        return len(self._env["nodes"]) > 2

AllTestClasses.append(SplitBrainTest)


class Reattach(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "Reattach"
        self._startall = SimulStartLite(cm)
        self.restart1 = RestartTest(cm)
        self.stopall = SimulStopLite(cm)
        self.is_unsafe = False

    def _is_managed(self, node):
        (_, is_managed) = self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -q -G -d true", verbose=1)
        is_managed = is_managed[0].strip()
        return is_managed == "true"

    def _set_unmanaged(self, node):
        self.debug("Disable resource management")
        self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -v false")

    def _set_managed(self, node):
        self.debug("Re-enable resource management")
        self._rsh(node, "crm_attribute -t rsc_defaults -n is-managed -D")

    def setup(self, node):
        attempt = 0
        if not self._startall(None):
            return None

        # Make sure we are really _really_ stable and that all
        # resources, including those that depend on transient node
        # attributes, are started
        while not self._cm.cluster_stable(double_check=True):
            if attempt < 5:
                attempt += 1
                self.debug("Not stable yet, re-testing")
            else:
                self._logger.log("Cluster is not stable")
                return None

        return 1

    def teardown(self, node):

        # Make sure 'node' is up
        start = StartTest(self._cm)
        start(node)

        if not self._is_managed(node):
            self._logger.log("Attempting to re-enable resource management on %s" % node)
            self._set_managed(node)
            self._cm.cluster_stable()
            if not self._is_managed(node):
                self._logger.log("Could not re-enable resource management")
                return 0

        return 1

    def can_run_now(self, node):
        """ Return True if we can meaningfully run right now"""
        if self._find_ocfs2_resources(node):
            self._logger.log("Detach/Reattach scenarios are not possible with OCFS2 services present")
            return False

        return True

    def __call__(self, node):
        self.incr("calls")

        pats = []
        # Conveniently, the scheduler will display this message when disabling
        # management, even if fencing is not enabled, so we can rely on it.
        managed = self.create_watch(["No fencing will be done"], 60)
        managed.set_watch()

        self._set_unmanaged(node)

        if not managed.look_for_all():
            self._logger.log("Patterns not found: " + repr(managed.unmatched))
            return self.failure("Resource management not disabled")

        pats = []
        pats.append(self.templates["Pat:RscOpOK"] % ("start", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("stop", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("promote", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("demote", ".*"))
        pats.append(self.templates["Pat:RscOpOK"] % ("migrate", ".*"))

        watch = self.create_watch(pats, 60, "ShutdownActivity")
        watch.set_watch()

        self.debug("Shutting down the cluster")
        ret = self.stopall(None)
        if not ret:
            self._set_managed(node)
            return self.failure("Couldn't shut down the cluster")

        self.debug("Bringing the cluster back up")
        ret = self._startall(None)
        time.sleep(5) # allow ping to update the CIB
        if not ret:
            self._set_managed(node)
            return self.failure("Couldn't restart the cluster")

        if self.local_badnews("ResourceActivity:", watch):
            self._set_managed(node)
            return self.failure("Resources stopped or started during cluster restart")

        watch = self.create_watch(pats, 60, "StartupActivity")
        watch.set_watch()

        # Re-enable resource management (and verify it happened).
        self._set_managed(node)
        self._cm.cluster_stable()
        if not self._is_managed(node):
            return self.failure("Could not re-enable resource management")

        # Ignore actions for STONITH resources
        ignore = []
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self._cm, line)
                if r.rclass == "stonith":

                    self.debug("Ignoring start actions for %s" % r.id)
                    ignore.append(self.templates["Pat:RscOpOK"] % ("start", r.id))

        if self.local_badnews("ResourceActivity:", watch, ignore):
            return self.failure("Resources stopped or started after resource management was re-enabled")

        return ret

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"resource( was|s were) active at shutdown" ]

    def is_applicable(self):
        return True

AllTestClasses.append(Reattach)


class SpecialTest1(CTSTest):
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "SpecialTest1"
        self._startall = SimulStartLite(cm)
        self.restart1 = RestartTest(cm)
        self.stopall = SimulStopLite(cm)

    def __call__(self, node):
        '''Perform the 'SpecialTest1' test for Andrew. '''
        self.incr("calls")

        #        Shut down all the nodes...
        ret = self.stopall(None)
        if not ret:
            return self.failure("Could not stop all nodes")

        # Test config recovery when the other nodes come up
        self._rsh(node, "rm -f " + BuildOptions.CIB_DIR + "/cib*")

        #        Start the selected node
        ret = self.restart1(node)
        if not ret:
            return self.failure("Could not start "+node)

        #        Start all remaining nodes
        ret = self._startall(None)
        if not ret:
            return self.failure("Could not start the remaining nodes")

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        # Errors that occur as a result of the CIB being wiped
        return [ r"error.*: v1 patchset error, patch failed to apply: Application of an update diff failed",
                 r"error.*: Resource start-up disabled since no STONITH resources have been defined",
                 r"error.*: Either configure some or disable STONITH with the stonith-enabled option",
                 r"error.*: NOTE: Clusters with shared data need STONITH to ensure data integrity" ]

AllTestClasses.append(SpecialTest1)


class HAETest(CTSTest):
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "HAETest"
        self.stopall = SimulStopLite(cm)
        self._startall = SimulStartLite(cm)
        self.is_loop = True

    def setup(self, node):
        #  Start all remaining nodes
        ret = self._startall(None)
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
            active = 0
            (rc, lines) = self._rsh(node, "crm_resource -r %s -W -Q" % resource, verbose=1)

            # Hack until crm_resource does the right thing
            if rc == 0 and lines:
                active = len(lines)

            if len(lines) == expected_clones:
                return 1

            elif rc == 1:
                self.debug("Resource %s is still inactive" % resource)

            elif rc == 234:
                self._logger.log("Unknown resource %s" % resource)
                return 0

            elif rc == 246:
                self._logger.log("Cluster is inactive")
                return 0

            elif rc != 0:
                self._logger.log("Call to crm_resource failed, rc=%d" % rc)
                return 0

            else:
                self.debug("Resource %s is active on %d times instead of %d" % (resource, active, expected_clones))

            attempts -= 1
            time.sleep(1)

        return 0

    def find_dlm(self, node):
        self.r_dlm = None

        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
        for line in lines:
            if re.search("^Resource", line):
                r = AuditResource(self._cm, line)
                if r.rtype == "controld" and r.parent != "NA":
                    self.debug("Found dlm: %s" % self.r_dlm)
                    self.r_dlm = r.parent
                    return 1
        return 0

    def find_hae_resources(self, node):
        self.r_dlm = None
        self._r_o2cb = None
        self._r_ocfs2 = []

        if self.find_dlm(node):
            self._find_ocfs2_resources(node)

    def is_applicable(self):
        if not CTSTest.is_applicable(self):
            return False
        if self._env["Schema"] == "hae":
            return True
        return None


class HAERoleTest(HAETest):
    def __init__(self, cm):
        '''Lars' mount/unmount test for the HA extension. '''
        HAETest.__init__(self,cm)
        self.name = "HAERoleTest"

    def change_state(self, node, resource, target):
        (rc, _) = self._rsh(node, "crm_resource -V -r %s -p target-role -v %s  --meta" % (resource, target))
        return rc

    def __call__(self, node):
        self.incr("calls")
        lpc = 0
        failed = 0
        delay = 2
        done = time.time() + self._env["loop-minutes"]*60
        self.find_hae_resources(node)

        clone_max = len(self._env["nodes"])
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

            if not self.wait_on_state(node, self._r_o2cb, clone_max):
                self.failure("%s did not come up correctly" % self._r_o2cb)
                failed = lpc

            for fs in self._r_ocfs2:
                if not self.wait_on_state(node, fs, clone_max):
                    self.failure("%s did not come up correctly" % fs)
                    failed = lpc

        if failed:
            return self.failure("iteration %d failed" % failed)
        return self.success()

AllTestClasses.append(HAERoleTest)


class HAEStandbyTest(HAETest):
    '''Set up a custom test to cause quorum failure issues for Andrew'''
    def __init__(self, cm):
        HAETest.__init__(self,cm)
        self.name = "HAEStandbyTest"

    def change_state(self, node, resource, target):
        (rc, _) = self._rsh(node, "crm_standby -V -l reboot -v %s" % (target))
        return rc

    def __call__(self, node):
        self.incr("calls")

        lpc = 0
        failed = 0
        done = time.time() + self._env["loop-minutes"]*60
        self.find_hae_resources(node)

        clone_max = len(self._env["nodes"])
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

            if not self.wait_on_state(node, self._r_o2cb, clone_max):
                self.failure("%s did not come up correctly" % self._r_o2cb)
                failed = lpc

            for fs in self._r_ocfs2:
                if not self.wait_on_state(node, fs, clone_max):
                    self.failure("%s did not come up correctly" % fs)
                    failed = lpc

        if failed:
            return self.failure("iteration %d failed" % failed)
        return self.success()

AllTestClasses.append(HAEStandbyTest)


class NearQuorumPointTest(CTSTest):
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
        self.name = "NearQuorumPoint"

    def __call__(self, dummy):
        '''Perform the 'NearQuorumPoint' test. '''
        self.incr("calls")
        startset = []
        stopset = []

        stonith = self._cm.prepare_fencing_watcher("NearQuorumPoint")
        #decide what to do with each node
        for node in self._env["nodes"]:
            action = self._env.random_gen.choice(["start","stop"])
            #action = self._env.random_gen.choice(["start","stop","no change"])
            if action == "start" :
                startset.append(node)
            elif action == "stop" :
                stopset.append(node)

        self.debug("start nodes:" + repr(startset))
        self.debug("stop nodes:" + repr(stopset))

        #add search patterns
        watchpats = [ ]
        for node in stopset:
            if self._cm.ShouldBeStatus[node] == "up":
                watchpats.append(self.templates["Pat:We_stopped"] % node)

        for node in startset:
            if self._cm.ShouldBeStatus[node] == "down":
                #watchpats.append(self.templates["Pat:NonDC_started"] % node)
                watchpats.append(self.templates["Pat:Local_started"] % node)
            else:
                for stopping in stopset:
                    if self._cm.ShouldBeStatus[stopping] == "up":
                        watchpats.append(self.templates["Pat:They_stopped"] % (node, self._cm.key_for_node(stopping)))

        if len(watchpats) == 0:
            return self.skipped()

        if len(startset) != 0:
            watchpats.append(self.templates["Pat:DC_IDLE"])

        watch = self.create_watch(watchpats, self._env["DeadTime"]+10)

        watch.set_watch()

        #begin actions
        for node in stopset:
            if self._cm.ShouldBeStatus[node] == "up":
                self._cm.StopaCMnoBlock(node)

        for node in startset:
            if self._cm.ShouldBeStatus[node] == "down":
                self._cm.StartaCMnoBlock(node)

        #get the result
        if watch.look_for_all():
            self._cm.cluster_stable()
            self._cm.fencing_cleanup("NearQuorumPoint", stonith)
            return self.success()

        self._logger.log("Warn: Patterns not found: " + repr(watch.unmatched))

        #get the "bad" nodes
        upnodes = []
        for node in stopset:
            if self._cm.StataCM(node) == 1:
                upnodes.append(node)

        downnodes = []
        for node in startset:
            if self._cm.StataCM(node) == 0:
                downnodes.append(node)

        self._cm.fencing_cleanup("NearQuorumPoint", stonith)
        if upnodes == [] and downnodes == []:
            self._cm.cluster_stable()

            # Make sure they're completely down with no residule
            for node in stopset:
                self._rsh(node, self.templates["StopCmd"])

            return self.success()

        if len(upnodes) > 0:
            self._logger.log("Warn: Unstoppable nodes: " + repr(upnodes))

        if len(downnodes) > 0:
            self._logger.log("Warn: Unstartable nodes: " + repr(downnodes))

        return self.failure()

    def is_applicable(self):
        return True

AllTestClasses.append(NearQuorumPointTest)


class RollingUpgradeTest(CTSTest):
    '''Perform a rolling upgrade of the cluster'''
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "RollingUpgrade"
        self._start = StartTest(cm)
        self._stop = StopTest(cm)
        self.stopall = SimulStopLite(cm)
        self._startall = SimulStartLite(cm)

    def setup(self, node):
        #  Start all remaining nodes
        ret = self.stopall(None)
        if not ret:
            return self.failure("Couldn't stop all nodes")

        for node in self._env["nodes"]:
            if not self.downgrade(node, None):
                return self.failure("Couldn't downgrade %s" % node)

        ret = self._startall(None)
        if not ret:
            return self.failure("Couldn't start all nodes")
        return self.success()

    def teardown(self, node):
        # Stop everything
        ret = self.stopall(None)
        if not ret:
            return self.failure("Couldn't stop all nodes")

        for node in self._env["nodes"]:
            if not self.upgrade(node, None):
                return self.failure("Couldn't upgrade %s" % node)

        return self.success()

    def install(self, node, version, start=1, flags="--force"):

        target_dir = "/tmp/rpm-%s" % version
        src_dir = "%s/%s" % (self._env["rpm-dir"], version)

        self._logger.log("Installing %s on %s with %s" % (version, node, flags))
        if not self._stop(node):
            return self.failure("stop failure: "+node)

        self._rsh(node, "mkdir -p %s" % target_dir)
        self._rsh(node, "rm -f %s/*.rpm" % target_dir)
        (_, lines) = self._rsh(node, "ls -1 %s/*.rpm" % src_dir, verbose=1)
        for line in lines:
            line = line[:-1]
            rc = self._rsh.copy("%s" % (line), "%s:%s/" % (node, target_dir))
        self._rsh(node, "rpm -Uvh %s %s/*.rpm" % (flags, target_dir))

        if start and not self._start(node):
            return self.failure("start failure: "+node)

        return self.success()

    def upgrade(self, node, start=1):
        return self.install(node, self._env["current-version"], start)

    def downgrade(self, node, start=1):
        return self.install(node, self._env["previous-version"], start, "--force --nodeps")

    def __call__(self, node):
        '''Perform the 'Rolling Upgrade' test. '''
        self.incr("calls")

        for node in self._env["nodes"]:
            if self.upgrade(node):
                return self.failure("Couldn't upgrade %s" % node)

            self._cm.cluster_stable()

        return self.success()

    def is_applicable(self):
        if not CTSTest.is_applicable(self):
            return None

        if "rpm-dir" not in self._env:
            return None
        if "current-version" not in self._env:
            return None
        if "previous-version" not in self._env:
            return None

        return 1

#        Register RestartTest as a good test to run
AllTestClasses.append(RollingUpgradeTest)


class BSC_AddResource(CTSTest):
    '''Add a resource to the cluster'''
    def __init__(self, cm):
        CTSTest.__init__(self, cm)
        self.name = "AddResource"
        self.resource_offset = 0
        self.cib_cmd = """cibadmin -C -o %s -X '%s' """

    def __call__(self, node):
        self.incr("calls")
        self.resource_offset =         self.resource_offset  + 1

        r_id = "bsc-rsc-%s-%d" % (node, self.resource_offset)
        start_pat = "pacemaker-controld.*%s_start_0.*confirmed.*ok"

        patterns = []
        patterns.append(start_pat % r_id)

        watch = self.create_watch(patterns, self._env["DeadTime"])
        watch.set_watch()

        ip = self.NextIP()
        if not self.make_ip_resource(node, r_id, "ocf", "IPaddr", ip):
            return self.failure("Make resource %s failed" % r_id)

        failed = 0
        watch_result = watch.look_for_all()
        if watch.unmatched:
            for regex in watch.unmatched:
                self._logger.log ("Warn: Pattern not found: %s" % (regex))
                failed = 1

        if failed:
            return self.failure("Resource pattern(s) not found")

        if not self._cm.cluster_stable(self._env["DeadTime"]):
            return self.failure("Unstable cluster")

        return self.success()

    def NextIP(self):
        ip = self._env["IPBase"]
        if ":" in ip:
            fields = ip.rpartition(":")
            fields[2] = str(hex(int(fields[2], 16)+1))
            print(str(hex(int(f[2], 16)+1)))
        else:
            fields = ip.rpartition('.')
            fields[2] = str(int(fields[2])+1)

        ip = fields[0] + fields[1] + fields[3];
        self._env["IPBase"] = ip
        return ip.strip()

    def make_ip_resource(self, node, id, rclass, type, ip):
        self._logger.log("Creating %s:%s:%s (%s) on %s" % (rclass,type,id,ip,node))
        rsc_xml="""
<primitive id="%s" class="%s" type="%s"  provider="heartbeat">
    <instance_attributes id="%s"><attributes>
        <nvpair id="%s" name="ip" value="%s"/>
    </attributes></instance_attributes>
</primitive>""" % (id, rclass, type, id, id, ip)

        node_constraint = """
      <rsc_location id="run_%s" rsc="%s">
        <rule id="pref_run_%s" score="100">
          <expression id="%s_loc_expr" attribute="#uname" operation="eq" value="%s"/>
        </rule>
      </rsc_location>""" % (id, id, id, id, node)

        rc = 0
        (rc, _) = self._rsh(node, self.cib_cmd % ("constraints", node_constraint), verbose=1)
        if rc != 0:
            self._logger.log("Constraint creation failed: %d" % rc)
            return None

        (rc, _) = self._rsh(node, self.cib_cmd % ("resources", rsc_xml), verbose=1)
        if rc != 0:
            self._logger.log("Resource creation failed: %d" % rc)
            return None

        return 1

    def is_applicable(self):
        if self._env["DoBSC"]:
            return True
        return None

AllTestClasses.append(BSC_AddResource)


def TestList(cm, audits):
    result = []
    for testclass in AllTestClasses:
        bound_test = testclass(cm)
        if bound_test.is_applicable():
            bound_test.audits = audits
            result.append(bound_test)
    return result


class RemoteLXC(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "RemoteLXC"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)
        self.num_containers = 2
        self.is_container = True
        self.fail_string = ""

    def start_lxc_simple(self, node):

        # restore any artifacts laying around from a previous test.
        self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -s -R &>/dev/null")

        # generate the containers, put them in the config, add some resources to them
        pats = [ ]
        watch = self.create_watch(pats, 120)
        watch.set_watch()
        pats.append(self.templates["Pat:RscOpOK"] % ("start", "lxc1"))
        pats.append(self.templates["Pat:RscOpOK"] % ("start", "lxc2"))
        pats.append(self.templates["Pat:RscOpOK"] % ("start", "lxc-ms"))
        pats.append(self.templates["Pat:RscOpOK"] % ("promote", "lxc-ms"))

        self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -g -a -m -s -c %d &>/dev/null" % self.num_containers)

        with Timer(self._logger, self.name, "remoteSimpleInit"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail_string = "Unmatched patterns: %s" % (repr(watch.unmatched))
            self.failed = True

    def cleanup_lxc_simple(self, node):

        pats = [ ]
        # if the test failed, attempt to clean up the cib and libvirt environment
        # as best as possible 
        if self.failed:
            # restore libvirt and cib
            self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -s -R &>/dev/null")
            return

        watch = self.create_watch(pats, 120)
        watch.set_watch()

        pats.append(self.templates["Pat:RscOpOK"] % ("stop", "container1"))
        pats.append(self.templates["Pat:RscOpOK"] % ("stop", "container2"))

        self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -p &>/dev/null")

        with Timer(self._logger, self.name, "remoteSimpleCleanup"):
            watch.look_for_all()

        if watch.unmatched:
            self.fail_string = "Unmatched patterns: %s" % (repr(watch.unmatched))
            self.failed = True

        # cleanup libvirt
        self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -s -R &>/dev/null")

    def __call__(self, node):
        '''Perform the 'RemoteLXC' test. '''
        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed, start all nodes failed.")

        (rc, _) = self._rsh(node, "/usr/share/pacemaker/tests/cts/lxc_autogen.sh -v &>/dev/null")
        if rc == 1:
            self.log("Environment test for lxc support failed.")
            return self.skipped()

        self.start_lxc_simple(node)
        self.cleanup_lxc_simple(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for ping",
                 r"schedulerd.*: Recover\s+(ping|lxc-ms|container)\s+\(.*\)",
                 # The orphaned lxc-ms resource causes an expected transition error
                 # that is a result of the scheduler not having knowledge that the
                 # promotable resource used to be a clone. As a result, it looks like that
                 # resource is running in multiple locations when it shouldn't... But in
                 # this instance we know why this error is occurring and that it is expected.
                 r"Calculated [Tt]ransition .*pe-error",
                 r"Resource lxc-ms .* is active on 2 nodes attempting recovery",
                 r"Unknown operation: fail",
                 r"VirtualDomain.*ERROR: Unable to determine emulator" ]

AllTestClasses.append(RemoteLXC)


class RemoteBasic(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteBasic"

    def __call__(self, node):
        '''Perform the 'RemoteBaremetal' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.test_attributes(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

AllTestClasses.append(RemoteBasic)

class RemoteStonithd(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteStonithd"

    def __call__(self, node):
        '''Perform the 'RemoteStonithd' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.fail_connection(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    def is_applicable(self):
        if not RemoteDriver.is_applicable(self):
            return False

        if "DoFencing" in self._env:
            return self._env["DoFencing"]

        return True

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Lost connection to Pacemaker Remote node",
                 r"Software caused connection abort",
                 r"pacemaker-controld.*:\s+error.*: Operation remote-.*_monitor",
                 r"pacemaker-controld.*:\s+error.*: Result of monitor operation for remote-.*",
                 r"schedulerd.*:\s+Recover\s+remote-.*\s+\(.*\)",
                 r"error: Result of monitor operation for .* on remote-.*: Internal communication failure" ] + super().errors_to_ignore

AllTestClasses.append(RemoteStonithd)


class RemoteMigrate(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteMigrate"

    def __call__(self, node):
        '''Perform the 'RemoteMigrate' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.migrate_connection(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    def is_applicable(self):
        if not RemoteDriver.is_applicable(self):
            return 0
        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        if len(self._env["nodes"]) < 3:
            return 0
        return 1

AllTestClasses.append(RemoteMigrate)


class RemoteRscFailure(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteRscFailure"

    def __call__(self, node):
        '''Perform the 'RemoteRscFailure' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        # This is an important step. We are migrating the connection
        # before failing the resource. This verifies that the migration
        # has properly maintained control over the remote-node.
        self.migrate_connection(node)

        self.fail_rsc(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"schedulerd.*: Recover\s+remote-rsc\s+\(.*\)",
                 r"Dummy.*: No process state file found" ] + super().errors_to_ignore

    def is_applicable(self):
        if not RemoteDriver.is_applicable(self):
            return 0
        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        if len(self._env["nodes"]) < 3:
            return 0
        return 1

AllTestClasses.append(RemoteRscFailure)

# vim:ts=4:sw=4:et:
