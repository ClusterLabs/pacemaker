'''CTS: Cluster Testing System: LinuxHA v2 dependent modules...
'''

__copyright__='''
Author: Huang Zhen <zhenhltc@cn.ibm.com>
Copyright (C) 2004 International Business Machines

Additional Audits, Revised Start action, Default Configuration:
     Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>

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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import os,sys,CTS,CTSaudits,CTStests, warnings
from CTSvars import *
from CTS import *
from CTSaudits import ClusterAudit
from CTStests import *
from CIB import *
try:
    from xml.dom.minidom import *
except ImportError:
    sys.__stdout__.write("Python module xml.dom.minidom not found\n")
    sys.__stdout__.write("Please install python-xml or similar before continuing\n")
    sys.__stdout__.flush()
    sys.exit(1)

#######################################################################
#
#  LinuxHA v2 dependent modules
#
#######################################################################


class crm_lha(ClusterManager):
    '''
    The linux-ha version 2 cluster manager class.
    It implements the things we need to talk to and manipulate
    linux-ha version 2 clusters
    '''
    def __init__(self, Environment, randseed=None):
        ClusterManager.__init__(self, Environment, randseed=randseed)
        #HeartbeatCM.__init__(self, Environment, randseed=randseed)

        self.fastfail = 0
        self.clear_cache = 0
        self.cib_installed = 0
        self.config = None
        self.cluster_monitor = 0
        self.use_short_names = 1

        self.update({
            "Name"           : "crm-lha",
            "DeadTime"       : 300,
            "StartTime"      : 300,        # Max time to start up
            "StableTime"     : 30,
            "StartCmd"       : CTSvars.INITDIR+"/heartbeat start > /dev/null 2>&1",
            "StopCmd"        : CTSvars.INITDIR+"/heartbeat stop  > /dev/null 2>&1",
            "ElectionCmd"    : "crmadmin -E %s",
            "StatusCmd"      : "crmadmin -t 60000 -S %s 2>/dev/null",
            "EpocheCmd"      : "crm_node -H -e",
            "QuorumCmd"      : "crm_node -H -q",
            "ParitionCmd"    : "crm_node -H -p",
            "CibQuery"       : "cibadmin -Ql",
            "ExecuteRscOp"   : "lrmadmin -n %s -E %s %s 0 %d EVERYTIME 2>&1",
            "CIBfile"        : "%s:"+CTSvars.CRM_CONFIG_DIR+"/cib.xml",
            "TmpDir"         : "/tmp",

            "BreakCommCmd"   : "iptables -A INPUT -s %s -j DROP >/dev/null 2>&1",
            "FixCommCmd"     : "iptables -D INPUT -s %s -j DROP >/dev/null 2>&1",

# tc qdisc add dev lo root handle 1: cbq avpkt 1000 bandwidth 1000mbit
# tc class add dev lo parent 1: classid 1:1 cbq rate "$RATE"kbps allot 17000 prio 5 bounded isolated
# tc filter add dev lo parent 1: protocol ip prio 16 u32 match ip dst 127.0.0.1 match ip sport $PORT 0xFFFF flowid 1:1
# tc qdisc add dev lo parent 1: netem delay "$LATENCY"msec "$(($LATENCY/4))"msec 10% 2> /dev/null > /dev/null
            "ReduceCommCmd"  : "",
            "RestoreCommCmd" : "tc qdisc del dev lo root",

            "LogFileName"    : Environment["LogFileName"],

            "StandbyCmd"   : "crm_standby -U %s -v %s 2>/dev/null",
            "UUIDQueryCmd"   : "crmadmin -N",
            "StandbyQueryCmd"    : "crm_standby -GQ -U %s 2>/dev/null",

            # Patterns to look for in the log files for various occasions...
            "Pat:DC_IDLE"      : "crmd.*State transition.*-> S_IDLE",
            
            # This wont work if we have multiple partitions
            "Pat:Local_started" : "%s crmd:.*The local CRM is operational",
            "Pat:Slave_started" : "%s crmd:.*State transition.*-> S_NOT_DC",
            "Pat:Master_started"   : "%s crmd:.* State transition.*-> S_IDLE",
            "Pat:We_stopped"   : "heartbeat.*%s.*Heartbeat shutdown complete",
            "Pat:Logd_stopped" : "%s logd:.*Exiting write process",
            "Pat:They_stopped" : "%s crmd:.*LOST:.* %s ",
            "Pat:All_stopped"  : "heartbeat.*%s.*Heartbeat shutdown complete",
            "Pat:They_dead"    : "node %s.*: is dead",
            "Pat:TransitionComplete" : "Transition status: Complete: complete",

            "Pat:ChildKilled"  : "%s heartbeat.*%s.*killed by signal 9",
            "Pat:ChildRespawn" : "%s heartbeat.*Respawning client.*%s",
            "Pat:ChildExit"    : "ERROR: Client .* exited with return code",
            
            # Bad news Regexes.  Should never occur.
            "BadRegexes"   : (
                r"ERROR:",
                r"CRIT:",
                r"Shutting down\.",
                r"Forcing shutdown\.",
                r"Timer I_TERMINATE just popped",
                r"input=I_ERROR",
                r"input=I_FAIL",
                r"input=I_INTEGRATED cause=C_TIMER_POPPED",
                r"input=I_FINALIZED cause=C_TIMER_POPPED",
                r"input=I_ERROR",
                r", exiting\.",
                r"WARN.*Ignoring HA message.*vote.*not in our membership list",
                r"pengine.*Attempting recovery of resource",
                r"is taking more than 2x its timeout",
                r"Confirm not received from",
                r"Welcome reply not received from",
                r"Attempting to schedule .* after a stop",
                r"Resource .* was active at shutdown",
                r"duplicate entries for call_id",
                r"Search terminated:",
                r"No need to invoke the TE",
                r"global_timer_callback:",
                r"Faking parameter digest creation",
                r"Parameters to .* action changed:",
                r"Parameters to .* changed",
            ),
        })

        if self.Env["DoBSC"]:
            del self["Pat:They_stopped"]
            del self["Pat:Logd_stopped"]
            self.Env["use_logd"] = 0

        self._finalConditions()

        self.check_transitions = 0
        self.check_elections = 0
        self.CIBsync = {}
        self.CibFactory = ConfigFactory(self)
        self.cib = self.CibFactory.createConfig(self.Env["Schema"])
    
    def errorstoignore(self):
        # At some point implement a more elegant solution that 
        #   also produces a report at the end
        '''Return list of errors which are known and very noisey should be ignored'''
        if 1:
            return [ 
                "ERROR: crm_abort: crm_glib_handler: ",
                "ERROR: Message hist queue is filling up",
                "stonithd: .*CRIT: external_hostlist: 'vmware gethosts' returned an empty hostlist",
                "stonithd: .*ERROR: Could not list nodes for stonith RA external/vmware.",
                "pengine: Preventing .* from re-starting",
                ]
        return []

    def install_config(self, node):
        if not self.ns.WaitForNodeToComeUp(node):
            self.log("Node %s is not up." % node)
            return None

        if not self.CIBsync.has_key(node) and self.Env["ClobberCIB"] == 1:
            self.CIBsync[node] = 1
            self.rsh(node, "rm -f "+CTSvars.CRM_CONFIG_DIR+"/cib*")

            # Only install the CIB on the first node, all the other ones will pick it up from there
            if self.cib_installed == 1:
                return None

            self.cib_installed = 1
            if self.Env["CIBfilename"] == None:
                self.debug("Installing Generated CIB on node %s" %(node))
                warnings.filterwarnings("ignore")
                cib_file=os.tmpnam()
                warnings.resetwarnings()
                self.rsh("localhost", "rm -f "+cib_file)
                self.debug("Creating new CIB for " + node + " in: " + cib_file)
                self.rsh("localhost", "echo \'" + self.cib.contents() + "\' > " + cib_file)
                if 0!=self.rsh.echo_cp(None, cib_file, node, CTSvars.CRM_CONFIG_DIR+"/cib.xml"):
                #if 0!=self.rsh.cp(cib_file, "root@%s:"+CTSvars.CRM_CONFIG_DIR+"/cib.xml" % node):
                    raise ValueError("Can not create CIB on %s "%node)

                self.rsh("localhost", "rm -f "+cib_file)
            else:
                self.debug("Installing CIB (%s) on node %s" %(self.Env["CIBfilename"], node))
                if 0 != self.rsh.cp(self.Env["CIBfilename"], "root@" + (self["CIBfile"]%node)):
                    raise ValueError("Can not scp file to %s "%node)
        
            self.rsh(node, "chown "+CTSvars.CRM_DAEMON_USER+" "+CTSvars.CRM_CONFIG_DIR+"/cib.xml")

    def prepare(self):
        '''Finish the Initialization process. Prepare to test...'''

        self.partitions_expected = 1
        for node in self.Env["nodes"]:
            self.ShouldBeStatus[node] = ""
            self.unisolate_node(node)
            self.StataCM(node)

    def test_node_CM(self, node):
        '''Report the status of the cluster manager on a given node'''

        watchpats = [ ]
        watchpats.append("Current ping state: (S_IDLE|S_NOT_DC)")
        watchpats.append(self["Pat:Slave_started"]%node)
        idle_watch = CTS.LogWatcher(self["LogFileName"], watchpats)
        idle_watch.setwatch()

        out = self.rsh(node, self["StatusCmd"]%node, 1)
        self.debug("Node %s status: '%s'" %(node, out))            

        if not out or string.find(out, 'ok') < 0:
            if self.ShouldBeStatus[node] == "up":
                self.log(
                    "Node status for %s is %s but we think it should be %s"
                    %(node, "down", self.ShouldBeStatus[node]))
            self.ShouldBeStatus[node]="down"
            return 0

        if self.ShouldBeStatus[node] == "down":
            self.log(
                "Node status for %s is %s but we think it should be %s: %s"
                %(node, "up", self.ShouldBeStatus[node], out))

        self.ShouldBeStatus[node]="up"

        # check the output first - because syslog-ng looses messages
        if string.find(out, 'S_NOT_DC') != -1:
            # Up and stable
            return 2
        if string.find(out, 'S_IDLE') != -1:
            # Up and stable
            return 2

        # fall back to syslog-ng and wait
        if not idle_watch.look():
            # just up
            self.debug("Warn: Node %s is unstable: %s" %(node, out))
            return 1

        # Up and stable
        return 2

    # Is the node up or is the node down
    def StataCM(self, node):
        '''Report the status of the cluster manager on a given node'''

        if self.test_node_CM(node) > 0:
            return 1
        return None

    # Being up and being stable is not the same question...
    def node_stable(self, node):
        '''Report the status of the cluster manager on a given node'''

        if self.test_node_CM(node) == 2:
            return 1
        self.log("Warn: Node %s not stable" %(node)) 
        return None

    def partition_stable(self, nodes, timeout=None):
        watchpats = [ ]
        watchpats.append("Current ping state: S_IDLE")
        watchpats.append(self["Pat:DC_IDLE"])
        self.debug("Waiting for cluster stability...") 

        if timeout == None:
            timeout = self["DeadTime"]

        idle_watch = CTS.LogWatcher(self["LogFileName"], watchpats, timeout)
        idle_watch.setwatch()

        any_up = 0
        for node in self.Env["nodes"]:
            # have each node dump its current state
            if self.ShouldBeStatus[node] == "up":
                self.rsh(node, self["StatusCmd"] %node, 1)
                any_up = 1

        if any_up == 0:
            self.debug("Cluster is inactive") 
            return 1

        ret = idle_watch.look()
        while ret:
            self.debug(ret) 
            for node in nodes:
                if re.search(node, ret):
                    return 1
            ret = idle_watch.look()

        self.debug("Warn: Partition %s not IDLE after %ds" % (repr(nodes), timeout)) 
        return None

    def cluster_stable(self, timeout=None):
        partitions = self.find_partitions()

        for partition in partitions:
            if not self.partition_stable(partition, timeout):
                return None

        return 1

    def is_node_dc(self, node, status_line=None):
        rc = 0

        if not status_line: 
            status_line = self.rsh(node, self["StatusCmd"]%node, 1)

        if not status_line:
            rc = 0
        elif string.find(status_line, 'S_IDLE') != -1:
            rc = 1
        elif string.find(status_line, 'S_INTEGRATION') != -1: 
            rc = 1
        elif string.find(status_line, 'S_FINALIZE_JOIN') != -1: 
            rc = 1
        elif string.find(status_line, 'S_POLICY_ENGINE') != -1: 
            rc = 1
        elif string.find(status_line, 'S_TRANSITION_ENGINE') != -1: 
            rc = 1

        return rc

    def active_resources(self, node):
        # [SM].* {node} matches Started, Slave, Master
        # Stopped wont be matched as it wont include {node}
        (rc, output) = self.rsh(node, """crm_resource -c""", None)

        resources = []
        for line in output: 
            if re.search("^Resource", line):
                tmp = AuditResource(self, line)
                if tmp.type == "primitive" and tmp.host == node:
                    resources.append(tmp.id)
        return resources

    def ResourceOp(self, resource, op, node, interval=0, app="lrmadmin"):
        '''
        Execute an operation on a resource
        '''
        cmd = self["ExecuteRscOp"] % (app, resource, op, interval)
        (rc, lines) = self.rsh(node, cmd, None)

        #self.debug("RscOp '%s' on %s: %d" % (cmd, node, rc))
        #for line in lines:
        #    self.debug("RscOp: "+line)

        return rc

    def ResourceLocation(self, rid):
        ResourceNodes = []
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                dummy = 0
                rc = self.ResourceOp(rid, "monitor", node)
                # Strange error codes from remote_py
                # 65024 == not installed
                # 2048 == 8
                # 1792 == 7
                # 0    == 0
                if rc == 127:
                    self.log("Command failed.  Tool not available?")

                elif rc == 254 or rc == 65024:
                    dummy = 1
                    #self.debug("%s is not installed on %s: %d" % (rid, node, rc))

                elif rc == 0 or rc == 2048 or rc == 8:
                    ResourceNodes.append(node)

                elif rc == 7 or rc == 1792:
                    dummy = 1
                    #self.debug("%s is not running on %s: %d" % (rid, node, rc))

                else:
                    # not active on this node?
                    self.log("Unknown rc code for %s on %s: %d" % (rid, node, rc))

        return ResourceNodes

    def find_partitions(self):
        ccm_partitions = []

        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                partition = self.rsh(node, self["ParitionCmd"], 1)

                if not partition:
                    self.log("no partition details for %s" %node)
                elif len(partition) > 2:
                    partition = partition[:-1]
                    found=0
                    for a_partition in ccm_partitions:
                        if partition == a_partition:
                            found = 1
                    if found == 0:
                        self.debug("Adding partition from %s: %s" %(node, partition))
                        ccm_partitions.append(partition)
                    else:
                        self.debug("Partition '%s' from %s is consistent with existing entries" %(partition, node))

                else:
                    self.log("bad partition details for %s" %node)
            else:
                self.debug("Node %s is down... skipping" %node)

        return ccm_partitions

    def HasQuorum(self, node_list):
        # If we are auditing a partition, then one side will
        #   have quorum and the other not.
        # So the caller needs to tell us which we are checking
        # If no value for node_list is specified... assume all nodes  
        if not node_list:
            node_list = self.Env["nodes"]

        for node in node_list:
            if self.ShouldBeStatus[node] == "up":
                quorum = self.rsh(node, self["QuorumCmd"], 1)
                if string.find(quorum, "1") != -1:
                    return 1
                elif string.find(quorum, "0") != -1:
                    return 0
                else:
                    self.log("WARN: Unexpected quorum test result from "+ node +":"+ quorum)

        return 0
    def Components(self):    
        complist = []
        common_ignore = [
                    "Pending action:",
                    "ERROR: crm_log_message_adv:",
                    "ERROR: MSG: No message to dump",
                    "pending LRM operations at shutdown",
                    "Lost connection to the CIB service",
                    "Connection to the CIB terminated...",
                    "Sending message to CIB service FAILED",
                    "crmd: .*Action A_RECOVER .* not supported",
                    "ERROR: stonithd_op_result_ready: not signed on",
                    "pingd: .*ERROR: send_update: Could not send update",
                    "send_ipc_message: IPC Channel to .* is not connected",
                    "unconfirmed_actions: Waiting on .* unconfirmed actions",
                    "cib_native_msgready: Message pending on command channel",
                    "crmd:.*do_exit: Performing A_EXIT_1 - forcefully exiting the CRMd",
                    "verify_stopped: Resource .* was active at shutdown.  You may ignore this error if it is unmanaged.",
            ]

        stonith_ignore = [
            "ERROR: stonithd_signon: ",
            "update_failcount: Updating failcount for child_DoFencing",
            "ERROR: te_connect_stonith: Sign-in failed: triggered a retry",
            ]

        stonith_ignore.extend(common_ignore)

        ccm = Process("ccm", 0, [
                    "State transition S_IDLE",
                    "CCM connection appears to have failed",
                    "crmd: .*Action A_RECOVER .* not supported",
                    "crmd: .*Input I_TERMINATE from do_recover",
                    "Exiting to recover from CCM connection failure",
                    "crmd:.*do_exit: Could not recover from internal error",
                    "crmd: .*I_ERROR.*(ccm_dispatch|crmd_cib_connection_destroy)",
                    "crmd .*exited with return code 2.",
                    "attrd .*exited with return code 1.",
                    "cib .*exited with return code 2.",
                    "crmd:.*get_channel_token: No reply message - disconnected",
#                    "WARN: determine_online_status: Node .* is unclean",
#                    "Scheduling Node .* for STONITH",
#                    "Executing .* fencing operation",
#                    "tengine_stonith_callback: .*result=0",
                    "A new node joined the cluster",
#                    "Processing I_NODE_JOIN:.* cause=C_HA_MESSAGE",
#                    "State transition S_.* -> S_INTEGRATION.*input=I_NODE_JOIN",
                    "State transition S_STARTING -> S_PENDING",
                    ], [], common_ignore, self.fastfail, self)

        cib = Process("cib", 0, [
                    "State transition S_IDLE",
                    "Lost connection to the CIB service",
                    "Connection to the CIB terminated...",
                    "crmd: .*Input I_TERMINATE from do_recover",
                    "crmd: .*I_ERROR.*crmd_cib_connection_destroy",
                    "crmd:.*do_exit: Could not recover from internal error",
                    "crmd .*exited with return code 2.",
                    "attrd .*exited with return code 1.",
                    ], [], common_ignore, self.fastfail, self)

        lrmd = Process("lrmd", 0, [
                    "State transition S_IDLE",
                    "LRM Connection failed",
                    "crmd: .*I_ERROR.*lrm_connection_destroy",
                    "State transition S_STARTING -> S_PENDING",
                    "crmd: .*Input I_TERMINATE from do_recover",
                    "crmd:.*do_exit: Could not recover from internal error",
                    "crmd .*exited with return code 2.",
                    ], [], common_ignore, self.fastfail, self)

        crmd = Process("crmd", 0, [
#                    "WARN: determine_online_status: Node .* is unclean",
#                    "Scheduling Node .* for STONITH",
#                    "Executing .* fencing operation",
#                    "tengine_stonith_callback: .*result=0",
                    "State transition .* S_IDLE",
                    "State transition S_STARTING -> S_PENDING",
                    ], [
                    ], common_ignore, self.fastfail, self)

        pengine = Process("pengine", 1, [
                    "State transition S_IDLE",
                    "crmd .*exited with return code 2.",
                    "crmd: .*Input I_TERMINATE from do_recover",
                    "crmd: .*do_exit: Could not recover from internal error",
                    "crmd: .*CRIT: pe_connection_destroy: Connection to the Policy Engine failed",
                    "crmd: .*I_ERROR.*save_cib_contents",
                    "crmd .*exited with return code 2.",
                    ], [], common_ignore, self.fastfail, self)

        if self.Env["DoFencing"] == 1 :
            complist.append(Process("stonithd", 0, [], [
                        "crmd: .*CRIT: tengine_stonith_connection_destroy: Fencing daemon connection failed",
                        "Attempting connection to fencing daemon",
                        "te_connect_stonith: Connected",
                        ], stonith_ignore, 0, self))
#            complist.append(Process("heartbeat", 0, [], [], [], None, self))


        if self.fastfail == 0:
            ccm.pats.extend([
                "attrd .* exited with return code 1",
                "ERROR: Respawning client .*attrd",
                "cib .* exited with return code 2",
                "ERROR: Respawning client .*cib",
                "crmd .* exited with return code 2",
                "ERROR: Respawning client .*crmd" 
                ])
            cib.pats.extend([
                "attrd .* exited with return code 1",
                "ERROR: Respawning client .*attrd",
                "crmd .* exited with return code 2",
                "ERROR: Respawning client .*crmd" 
                ])
            lrmd.pats.extend([
                "crmd .* exited with return code 2",
                "ERROR: Respawning client .*crmd" 
                ])
            pengine.pats.extend([
                "ERROR: Respawning client .*crmd" 
                ])

        complist.append(ccm)
        complist.append(cib)
        complist.append(lrmd)
        complist.append(crmd)
        complist.append(pengine)

        return complist

    def NodeUUID(self, node):
        lines = self.rsh(node, self["UUIDQueryCmd"], 1)
        for line in lines:
            self.debug("UUIDLine:"+ line)
            m = re.search(r'%s.+\((.+)\)' % node, line)
            if m:
                return m.group(1)
        return ""

    def StandbyStatus(self, node):
        out=self.rsh(node, self["StandbyQueryCmd"]%node, 1)
        if not out:
            return "off"
        out = out[:-1]
        self.debug("Standby result: "+out)
        return out

    # status == "on" : Enter Standby mode
    # status == "off": Enter Active mode
    def SetStandbyMode(self, node, status):
        current_status = self.StandbyStatus(node)
        cmd = self["StandbyCmd"] % (node, status)
        ret = self.rsh(node, cmd)
        return True

#######################################################################
#
#   A little test code...
#
#   Which you are advised to completely ignore...
#
#######################################################################
if __name__ == '__main__': 
    pass
