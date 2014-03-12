from UserDict import UserDict
import sys, time, types, syslog, os, struct, string, signal, traceback, warnings, socket

patternvariants = {}
class BasePatterns:
    def __init__(self, name):
        self.name = name
        patternvariants[name] = self
        self.ignore = []
        self.BadNews = []
        self.commands = {
            "DeadTime"       : 300,
            "StartTime"      : 300,        # Max time to start up
            "StableTime"     : 30,
            "StatusCmd"      : "crmadmin -t 60000 -S %s 2>/dev/null",
            "CibQuery"       : "cibadmin -Ql",
            "CibAddXml"      : "cibadmin --modify -c --xml-text %s",
            "CibDelXpath"    : "cibadmin --delete --xpath %s",
            # 300,000 == 5 minutes
            "RscRunning"     : CTSvars.CRM_DAEMON_DIR + "/lrmd_test -R -r %s",
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

            "UUIDQueryCmd"    : "crmadmin -N",

            "MaintenanceModeOn"    : "cibadmin --modify -c --xml-text '<cluster_property_set id=\"cib-bootstrap-options\"><nvpair id=\"cts-maintenance-mode-setting\" name=\"maintenance-mode\" value=\"true\"/></cluster_property_set>'",
            "MaintenanceModeOff"    : "cibadmin --delete --xpath \"//nvpair[@name='maintenance-mode']\"",

            "StandbyCmd"      : "crm_attribute -VQ  -U %s -n standby -l forever -v %s 2>/dev/null",
            "StandbyQueryCmd" : "crm_attribute -QG -U %s -n standby -l forever -d off 2>/dev/null",
        }
        self.search = {
            "Pat:DC_IDLE"      : "crmd.*State transition.*-> S_IDLE",
            
            # This wont work if we have multiple partitions
            "Pat:Local_started" : "%s .*The local CRM is operational",
            "Pat:Slave_started" : "%s .*State transition.*-> S_NOT_DC",
            "Pat:Master_started"   : "%s .* State transition.*-> S_IDLE",
            "Pat:We_stopped"   : "heartbeat.*%s.*Heartbeat shutdown complete",
            "Pat:Logd_stopped" : "%s logd:.*Exiting write process",
            "Pat:They_stopped" : "%s .*LOST:.* %s ",
            "Pat:They_dead"    : "node %s.*: is dead",
            "Pat:TransitionComplete" : "Transition status: Complete: complete",

            "Pat:Fencing_start"    : "Initiating remote operation .* for %s",
            "Pat:Fencing_ok"   : "stonith.* remote_op_done: Operation .* of %s by .*: OK",

            "Pat:RscOpOK"        : "process_lrm_event: Operation %s_%s.*ok.*confirmed",
        }

    def get_patterns(self, key):
        if key == "BadNews":
            return self.BadNews
        elif key == "BadNewsIgnore":
            return self.ignore
        elif key == "Commands":
            return self.commands
        elif key == "Search":
            return self.search

    def __getitem__(self, key):
        if self.commands.has_key(key):
            return self.commands[key]
        elif self.search.has_key(key):
            return self.search[key]
        else:
            print "Unknown template '%s' for %s" % (key, self.name)
            return None

class crm_lha(BasePatterns):
    def __init__(self, name):
        BasePatterns.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "service heartbeat start > /dev/null 2>&1",
            "StopCmd"        : "service heartbeat stop  > /dev/null 2>&1",
            "EpocheCmd"      : "crm_node -H -e",
            "QuorumCmd"      : "crm_node -H -q",
            "ParitionCmd"    : "crm_node -H -p",
        })

        self.search.update({
            # Patterns to look for in the log files for various occasions...
            "Pat:ChildKilled"  : "%s heartbeat.*%s.*killed by signal 9",
            "Pat:ChildRespawn" : "%s heartbeat.*Respawning client.*%s",
            "Pat:ChildExit"    : "(ERROR|error): Client .* exited with return code",            
        })
        self.BadNews = [
                r" trace:",
                r"error:",
                r"crit:",
                r"ERROR:",
                r"CRIT:",
                r"Shutting down...NOW",
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
            ]

        self.ignore = [
                "(ERROR|error): crm_abort: crm_glib_handler: ",
                "(ERROR|error): Message hist queue is filling up",
                "stonithd.*CRIT: external_hostlist: 'vmware gethosts' returned an empty hostlist",
                "stonithd.*(ERROR|error): Could not list nodes for stonith RA external/vmware.",
                "pengine.*Preventing .* from re-starting",
                ]

class crm_cs_v0(BasePatterns):
    def __init__(self, name):
        BasePatterns.__init__(self, name)

        self.commands.update({
            "EpocheCmd"      : "crm_node -e --openais",
            "QuorumCmd"      : "crm_node -q --openais",
            "ParitionCmd"    : "crm_node -p --openais",
            "StartCmd"       : "service corosync start",
            "StopCmd"        : "service corosync stop",
        })

        self.search.update({
# The next pattern is too early
#            "Pat:We_stopped"   : "%s.*Service engine unloaded: Pacemaker Cluster Manager",
# The next pattern would be preferred, but it doesn't always come out
#            "Pat:We_stopped"   : "%s.*Corosync Cluster Engine exiting with status",
            "Pat:We_stopped"  : "%s.*Service engine unloaded: corosync cluster quorum service",
            "Pat:They_stopped" : "%s crmd.*Node %s\[.*state is now lost",
            "Pat:They_dead"    : "corosync:.*Node %s is now: lost",

            "Pat:ChildExit"    : "Child process .* exited",
            "Pat:ChildKilled"  : "%s corosync.*Child process %s terminated with signal 9",
            "Pat:ChildRespawn" : "%s corosync.*Respawning failed child process: %s",
        })

        self.ignore = [
            r"crm_mon:",
            r"crmadmin:",
            r"update_trace_data",
            r"async_notify: strange, client not found",
            r"Parse error: Ignoring unknown option .*nodename",
            r"error: log_operation: Operation 'reboot' .* with device 'FencingFail' returned:",
            r"Child process .* terminated with signal 9",
            r"getinfo response error: 1$",
        ]

        self.BadNews = [
            r" trace:",
            r"error:",
            r"crit:",
            r"ERROR:",
            r"CRIT:",
            r"Shutting down...NOW",
            r"Timer I_TERMINATE just popped",
            r"input=I_ERROR",
            r"input=I_FAIL",
            r"input=I_INTEGRATED cause=C_TIMER_POPPED",
            r"input=I_FINALIZED cause=C_TIMER_POPPED",
            r"input=I_ERROR",
            r", exiting\.",
            r"(WARN|warn).*Ignoring HA message.*vote.*not in our membership list",
            r"pengine.*Attempting recovery of resource",
            r"is taking more than 2x its timeout",
            r"Confirm not received from",
            r"Welcome reply not received from",
            r"Attempting to schedule .* after a stop",
            r"Resource .* was active at shutdown",
            r"duplicate entries for call_id",
            r"Search terminated:",
            r":global_timer_callback",
            r"Faking parameter digest creation",
            r"Parameters to .* action changed:",
            r"Parameters to .* changed",
            r"Child process .* terminated with signal",
            r"LogActions: Recover",
            r"rsyslogd.* imuxsock lost .* messages from pid .* due to rate-limiting",
            r"Peer is not part of our cluster",
            r"We appear to be in an election loop",
            r"Unknown node -> we will not deliver message",
            r"crm_write_blackbox",
            r"pacemakerd.*Could not connect to Cluster Configuration Database API",
            r"Receiving messages from a node we think is dead",
            r"share the same cluster nodeid",
            r"share the same name",

                #r"crm_ipc_send:.*Request .* failed",
            #r"crm_ipc_send:.*Sending to .* is disabled until pending reply is received",

                # Not inherently bad, but worth tracking
            #r"No need to invoke the TE",
            #r"ping.*: DEBUG: Updated connected = 0",
            #r"Digest mis-match:",
            r"te_graph_trigger: Transition failed: terminated",
            r"process_ping_reply",
            r"retrieveCib",
            r"cib_process_replace",
            #r"Executing .* fencing operation",
            #r"fence_pcmk.* Call to fence",
            #r"fence_pcmk",
            r"cman killed by node",
            r"Election storm",
            r"stalled the FSA with pending inputs",
        ]

class crm_mcp(crm_cs_v0):
    '''
    The crm version 4 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of native corosync (no plugins)
    '''
    def __init__(self, name):
        crm_cs_v0.__init__(self, name)

        self.name = "crm-plugin-v0"
        self.commands.update({
            "StartCmd"       : "service corosync start && service pacemaker start",
            "StopCmd"        : "service pacemaker stop; service pacemaker_remote stop; service corosync stop",

            "EpocheCmd"      : "crm_node -e",
            "QuorumCmd"      : "crm_node -q",
            "ParitionCmd"    : "crm_node -p",
        })

        self.search.update({
            # Close enough... "Corosync Cluster Engine exiting normally" isn't printed
            #   reliably and there's little interest in doing anything it
            "Pat:We_stopped"   : "%s.*Unloading all Corosync service engines",
            "Pat:They_stopped" : "%s crmd.*Node %s\[.*state is now lost",
            "Pat:They_dead"    : "crmd.*Node %s\[.*state is now lost",

            "Pat:ChildKilled"  : "%s pacemakerd.*Child process %s terminated with signal 9",
            "Pat:ChildRespawn" : "%s pacemakerd.*Respawning failed child process: %s",

            "Pat:InfraUp"      : "%s corosync.*Initializing transport",
            "Pat:PacemakerUp"  : "%s pacemakerd.*Starting Pacemaker",
        })

#        if self.Env["have_systemd"]:
#            self.update({
#                # When systemd is in use, we can look for this instead
#                "Pat:We_stopped"   : "%s.*Stopped Corosync Cluster Engine",
#            })

class crm_cman(crm_cs_v0):
    '''
    The crm version 3 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of openais
    '''
    def __init__(self, name):
        crm_cs_v0.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "service pacemaker start",
            "StopCmd"        : "service pacemaker stop; service pacemaker_remote stop",

            "EpocheCmd"      : "crm_node -e --cman",
            "QuorumCmd"      : "crm_node -q --cman",
            "ParitionCmd"    : "crm_node -p --cman",

            "Pat:We_stopped"   : "%s.*Unloading all Corosync service engines",
            "Pat:They_stopped" : "%s crmd.*Node %s\[.*state is now lost",
            "Pat:They_dead"    : "crmd.*Node %s\[.*state is now lost",

            "Pat:ChildKilled"  : "%s pacemakerd.*Child process %s terminated with signal 9",
            "Pat:ChildRespawn" : "%s pacemakerd.*Respawning failed child process: %s",
        })


class PatternSelector:

    def __init__(self, name):
        self.name = name
        self.base = BasePatterns("crm-base")

        if not name:
            crm_cs_v0("crm-plugin-v0")
            crm_cman("crm-cman")
            crm_mcp("crm-mcp")
        elif name == "crm-lha":
            crm_lha(name)
        elif name == "crm-plugin-v0":
            crm_cs_v0(name)
        elif name == "crm-cman":
            crm_cman(name)
        elif name == "crm-mcp":
            crm_mcp(name)

    def get_variant(self, variant):
        if patternvariants.has_key(variant):
            return patternvariants[variant]
        return self.base

    def get_patterns(self, variant, kind):
        return self.get_variant(variant).get_patterns(kind)

    def get_template(self, variant, key):
        v = self.get_variant(variant)
        return v[key]

    def __getitem__(self, key):
        return self.get_template(self.name, key)

# python cts/CTSpatt.py -k crm-mcp -t StartCmd
if __name__ == '__main__':

    pdir=os.path.dirname(sys.path[0])
    sys.path.insert(0, pdir) # So that things work from the source directory

    from cts.CTSvars   import *

    kind=None
    template=None

    skipthis=None
    args=sys.argv[1:]
    for i in range(0, len(args)):
       if skipthis:
           skipthis=None
           continue

       elif args[i] == "-k" or args[i] == "--kind":
           skipthis=1
           kind = args[i+1]

       elif args[i] == "-t" or args[i] == "--template":
           skipthis=1
           template = args[i+1]

       else:
           print "Illegal argument " + args[i]


    print PatternSelector(kind)[template]
