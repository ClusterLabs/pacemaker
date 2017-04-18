import sys, os

from cts.CTSvars import *

patternvariants = {}
class BasePatterns:
    def __init__(self, name):
        self.name = name
        patternvariants[name] = self
        self.ignore = [
            "avoid confusing Valgrind",
        ]
        self.BadNews = []
        self.components = {}
        self.commands = {
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

            "SetCheckInterval"    : "cibadmin --modify -c --xml-text '<cluster_property_set id=\"cib-bootstrap-options\"><nvpair id=\"cts-recheck-interval-setting\" name=\"cluster-recheck-interval\" value=\"%s\"/></cluster_property_set>'",
            "ClearCheckInterval"    : "cibadmin --delete --xpath \"//nvpair[@name='cluster-recheck-interval']\"",

            "MaintenanceModeOn"    : "cibadmin --modify -c --xml-text '<cluster_property_set id=\"cib-bootstrap-options\"><nvpair id=\"cts-maintenance-mode-setting\" name=\"maintenance-mode\" value=\"true\"/></cluster_property_set>'",
            "MaintenanceModeOff"    : "cibadmin --delete --xpath \"//nvpair[@name='maintenance-mode']\"",

            "StandbyCmd"      : "crm_attribute -VQ  -U %s -n standby -l forever -v %s 2>/dev/null",
            "StandbyQueryCmd" : "crm_attribute -QG -U %s -n standby -l forever -d off 2>/dev/null",
        }
        self.search = {
            "Pat:DC_IDLE"      : "crmd.*State transition.*-> S_IDLE",
            
            # This wont work if we have multiple partitions
            "Pat:Local_started" : "%s\W.*The local CRM is operational",
            "Pat:Slave_started" : "%s\W.*State transition.*-> S_NOT_DC",
            "Pat:Master_started": "%s\W.*State transition.*-> S_IDLE",
            "Pat:We_stopped"    : "heartbeat.*%s.*Heartbeat shutdown complete",
            "Pat:Logd_stopped"  : "%s\W.*logd:.*Exiting write process",
            "Pat:They_stopped"  : "%s\W.*LOST:.* %s ",
            "Pat:They_dead"     : "node %s.*: is dead",
            "Pat:TransitionComplete" : "Transition status: Complete: complete",

            "Pat:Fencing_start" : "(Initiating remote operation|Requesting peer fencing ).* (for|of) %s",
            "Pat:Fencing_ok"    : r"stonith.*:\s*Operation .* of %s by .* for .*@.*: OK",
            "Pat:Fencing_recover"    : r"pengine.*: Recover %s",

            "Pat:RscOpOK"       : r"crmd.*:\s+Result of %s operation for %s.*: (0 \()?ok",
            "Pat:RscRemoteOpOK" : r"crmd.*:\s+Result of %s operation for %s on %s: (0 \()?ok",
            "Pat:NodeFenced"    : r"crmd.*:\s* Peer %s was terminated \(.*\) by .* on behalf of .*: OK",
            "Pat:FenceOpOK"     : "Operation .* for host '%s' with device .* returned: 0",
        }

    def get_component(self, key):
        if key in self.components:
            return self.components[key]
        print("Unknown component '%s' for %s" % (key, self.name))
        return []

    def get_patterns(self, key):
        if key == "BadNews":
            return self.BadNews
        elif key == "BadNewsIgnore":
            return self.ignore
        elif key == "Commands":
            return self.commands
        elif key == "Search":
            return self.search
        elif key == "Components":
            return self.components

    def __getitem__(self, key):
        if key == "Name":
            return self.name
        elif key in self.commands:
            return self.commands[key]
        elif key in self.search:
            return self.search[key]
        else:
            print("Unknown template '%s' for %s" % (key, self.name))
            return None

class crm_lha(BasePatterns):
    def __init__(self, name):
        BasePatterns.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "service heartbeat start > /dev/null 2>&1",
            "StopCmd"        : "service heartbeat stop  > /dev/null 2>&1",
            "EpochCmd"      : "crm_node -H -e",
            "QuorumCmd"      : "crm_node -H -q",
            "PartitionCmd"    : "crm_node -H -p",
        })

        self.search.update({
            # Patterns to look for in the log files for various occasions...
            "Pat:ChildKilled"  : "%s\W.*heartbeat.*%s.*killed by signal 9",
            "Pat:ChildRespawn" : "%s\W.*heartbeat.*Respawning client.*%s",
            "Pat:ChildExit"    : "(ERROR|error): Client .* exited with return code",            
        })
        self.BadNews = [
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

        self.ignore = self.ignore + [
                r"(ERROR|error):.*\s+assert\s+at\s+crm_glib_handler:"
                "(ERROR|error): Message hist queue is filling up",
                "stonithd.*CRIT: external_hostlist:.*'vmware gethosts' returned an empty hostlist",
                "stonithd.*(ERROR|error): Could not list nodes for stonith RA external/vmware.",
                "pengine.*Preventing .* from re-starting",
                ]

class crm_cs_v0(BasePatterns):
    def __init__(self, name):
        BasePatterns.__init__(self, name)

        self.commands.update({
            "EpochCmd"      : "crm_node -e --openais",
            "QuorumCmd"      : "crm_node -q --openais",
            "PartitionCmd"    : "crm_node -p --openais",
            "StartCmd"       : "service corosync start",
            "StopCmd"        : "service corosync stop",
        })

        self.search.update({
# The next pattern is too early
#            "Pat:We_stopped"   : "%s.*Service engine unloaded: Pacemaker Cluster Manager",
# The next pattern would be preferred, but it doesn't always come out
#            "Pat:We_stopped"   : "%s.*Corosync Cluster Engine exiting with status",
            "Pat:We_stopped"   : "%s\W.*Service engine unloaded: corosync cluster quorum service",
            "Pat:They_stopped" : "%s\W.*crmd.*Node %s(\[|\s).*state is now lost",
            "Pat:They_dead"    : "corosync:.*Node %s is now: lost",

            "Pat:ChildExit"    : "Child process .* exited",
            "Pat:ChildKilled"  : "%s\W.*corosync.*Child process %s terminated with signal 9",
            "Pat:ChildRespawn" : "%s\W.*corosync.*Respawning failed child process: %s",

            "Pat:InfraUp"      : "%s\W.*corosync.*Initializing transport",
            "Pat:PacemakerUp"  : "%s\W.*corosync.*CRM: Initialized",
        })

        self.ignore = self.ignore + [
            r"crm_mon:",
            r"crmadmin:",
            r"update_trace_data",
            r"async_notify:.*strange, client not found",
            r"Parse error: Ignoring unknown option .*nodename",
            r"error.*: Operation 'reboot' .* with device 'FencingFail' returned:",
            r"Child process .* terminated with signal 9",
            r"getinfo response error: 1$",
            "sbd.* error: inquisitor_child: DEBUG MODE IS ACTIVE",
            r"sbd.* pcmk:\s*error:.*Connection to cib_ro failed",
            r"sbd.* pcmk:\s*error:.*Connection to cib_ro.* closed .I/O condition=17",
        ]

        self.BadNews = [
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
            r"The .* process .* terminated with signal",
            r"Child process .* terminated with signal",
            r"pengine:.*Recover .*\(.* -\> .*\)",
            r"rsyslogd.* imuxsock lost .* messages from pid .* due to rate-limiting",
            r"Peer is not part of our cluster",
            r"We appear to be in an election loop",
            r"Unknown node -> we will not deliver message",
            r"(Blackbox dump requested|Problem detected)",
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
            r"crmd:.*Transition failed: terminated",
            r"Local CIB .* differs from .*:",
            r"warn.*:\s*Continuing but .* will NOT be used",
            r"warn.*:\s*Cluster configuration file .* is corrupt",
            #r"Executing .* fencing operation",
            #r"fence_pcmk.* Call to fence",
            #r"fence_pcmk",
            r"cman killed by node",
            r"Election storm",
            r"stalled the FSA with pending inputs",
        ]


        self.components["common-ignore"] = [
                    "Pending action:",
                    "error: crm_log_message_adv:",
                    r"resource( was|s were) active at shutdown",
                    "pending LRM operations at shutdown",
                    "Lost connection to the CIB service",
                    "Connection to the CIB terminated...",
                    "Sending message to CIB service FAILED",
                    "apply_xml_diff:.*Diff application failed!",
                    r"crmd.*:\s*Action A_RECOVER .* not supported",
                    "unconfirmed_actions:.*Waiting on .* unconfirmed actions",
                    "cib_native_msgready:.*Message pending on command channel",
                    r"crmd.*:\s*Performing A_EXIT_1 - forcefully exiting the CRMd",
                    "verify_stopped:.*Resource .* was active at shutdown.  You may ignore this error if it is unmanaged.",
                    "error: attrd_connection_destroy:.*Lost connection to attrd",
                    r".*:\s*Executing .* fencing operation \(.*\) on ",
                    r".*:\s*Requesting fencing \([^)]+\) of node ",
                    r"(Blackbox dump requested|Problem detected)",
#                    "error: native_create_actions: Resource .*stonith::.* is active on 2 nodes attempting recovery",
#                    "error: process_pe_message: Transition .* ERRORs found during PE processing",
            ]
        
        self.components["corosync-ignore"] = [
            r"error:.*Connection to the CPG API failed: Library error",
            r"The .* process .* exited",
            r"pacemakerd.*error:.*Child process .* exited",
            r"cib.*error:.*Corosync connection lost",
            r"stonith-ng.*error:.*Corosync connection terminated",
            r"The cib process .* exited: Invalid argument",
            r"The attrd process .* exited: Transport endpoint is not connected",
            r"The crmd process .* exited: Link has been severed",
            r"error:.*Child process cib .* exited: Invalid argument",
            r"error:.*Child process attrd .* exited: Transport endpoint is not connected",
            r"error:.*Child process crmd .* exited: Link has been severed",
            r"lrmd.*error:.*Connection to stonith-ng failed",
            r"lrmd.*error:.*Connection to stonith-ng.* closed",
            r"lrmd.*error:.*LRMD lost STONITH connection",
            r"crmd.*State transition .* S_RECOVERY",
            r"crmd.*error:.*Input I_ERROR .*received in state",
            r"crmd.*error:.*Input I_TERMINATE .*received in state",
            r"crmd.*error:.*Connection to cman failed",
            r"crmd.*error:.*Could not recover from internal error",
            r"error:.*Connection to cib_shm failed",
            r"error:.*Connection to cib_shm.* closed",
            r"error:.*STONITH connection failed",
            r"error: Connection to stonith-ng failed",
            r"crit: Fencing daemon connection failed",
            r"error: Connection to stonith-ng.* closed",
            ]

        self.components["corosync"] = [
            r"pacemakerd.*error:.*Connection destroyed",
            r"attrd.*:\s*crit:.*Lost connection to Corosync service",
            r"stonith.*:\s*(Corosync connection terminated|Shutting down)",
            r"cib.*:\s*Corosync connection lost!\s+Exiting.",
            r"crmd.*:\s*(connection terminated|Disconnected from Corosync)",
            r"pengine.*Scheduling Node .* for STONITH",
            r"crmd.*:\s*Peer .* was terminated \(.*\) by .* for .*:\s*OK",
        ]

        self.components["cib-ignore"] = [
            "lrmd.*Connection to stonith-ng failed",
            "lrmd.*Connection to stonith-ng.* closed",
            "lrmd.*LRMD lost STONITH connection",
            "lrmd.*STONITH connection failed, finalizing .* pending operations",
            ]

        self.components["cib"] = [
                    "State transition .* S_RECOVERY",
                    "Respawning .* crmd",
                    "Respawning .* attrd",
                    "Connection to cib_.* failed",
                    "Connection to cib_.* closed",
                    r"crmd.*:.*Connection to the CIB terminated...",
                    r"attrd.*:.*(Lost connection to CIB service|Connection to the CIB terminated)",
                    "(Child process|The) crmd .* exited: Generic Pacemaker error",
                    "(Child process|The) attrd .* exited: (Connection reset by peer|Transport endpoint is not connected)",
                    r"crmd.*: Input I_TERMINATE .*from do_recover",
                    "crmd.*I_ERROR.*crmd_cib_connection_destroy",
                    "crmd.*Could not recover from internal error",
                    ]

        self.components["lrmd"] = [
                    "State transition .* S_RECOVERY",
                    "LRM Connection failed",
                    "Respawning .* crmd",
                    "Connection to lrmd failed",
                    "Connection to lrmd.* closed",
                    "crmd.*I_ERROR.*lrm_connection_destroy",
                    "(Child process|The) crmd .* exited: Generic Pacemaker error",
                    r"crmd.*: Input I_TERMINATE .*from do_recover",
                    "crmd.*Could not recover from internal error",
                    ]
        self.components["lrmd-ignore"] = []

        self.components["crmd"] = [
#                    "WARN: determine_online_status: Node .* is unclean",
#                    "Scheduling Node .* for STONITH",
#                    "Executing .* fencing operation",
# Only if the node wasn't the DC:  "State transition S_IDLE",
                    "State transition .* -> S_IDLE",
                    ]
        self.components["crmd-ignore"] = []

        self.components["attrd"] = []
        self.components["attrd-ignore"] = []

        self.components["pengine"] = [
                    "State transition .* S_RECOVERY",
                    "Respawning .* crmd",
                    "(The|Child process) crmd .* exited: Generic Pacemaker error",
                    "Connection to pengine failed",
                    "Connection to pengine.* closed",
                    "Connection to the Policy Engine failed",
                    "crmd.*I_ERROR.*save_cib_contents",
                    r"crmd.*: Input I_TERMINATE .*from do_recover",
                    "crmd.*Could not recover from internal error",
                    ]
        self.components["pengine-ignore"] = []

        self.components["stonith"] = [
            "Connection to stonith-ng failed",
            "LRMD lost STONITH connection",
            "Connection to stonith-ng.* closed",
            "Fencing daemon connection failed",
            r"crmd.*:\s*warn.*:\s*Callback already present",
        ]
        self.components["stonith-ignore"] = [
            r"pengine.*: Recover Fencing",
            r"Updating failcount for Fencing",
            r"error:.*Connection to stonith-ng failed",
            r"error:.*Connection to stonith-ng.*closed \(I/O condition=17\)",
            r"crit:.*Fencing daemon connection failed",
            r"error:.*Sign-in failed: triggered a retry",
            "STONITH connection failed, finalizing .* pending operations.",
            r"crmd.*:\s+Result of .* operation for Fencing.*Error",
        ]
        self.components["stonith-ignore"].extend(self.components["common-ignore"])

class crm_mcp(crm_cs_v0):
    '''
    The crm version 4 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of native corosync (no plugins)
    '''
    def __init__(self, name):
        crm_cs_v0.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "service corosync start && service pacemaker start",
            "StopCmd"        : "service pacemaker stop; [ ! -e /usr/sbin/pacemaker_remoted ] || service pacemaker_remote stop; service corosync stop",

            "EpochCmd"      : "crm_node -e",
            "QuorumCmd"      : "crm_node -q",
            "PartitionCmd"    : "crm_node -p",
        })

        self.search.update({
            # Close enough... "Corosync Cluster Engine exiting normally" isn't printed
            #   reliably and there's little interest in doing anything about it
            "Pat:We_stopped"   : "%s\W.*Unloading all Corosync service engines",
            "Pat:They_stopped" : "%s\W.*crmd.*Node %s(\[|\s).*state is now lost",
            "Pat:They_dead"    : "crmd.*Node %s(\[|\s).*state is now lost",

            "Pat:ChildExit"    : "The .* process exited",
            "Pat:ChildKilled"  : "%s\W.*pacemakerd.*The %s process .* terminated with signal 9",
            "Pat:ChildRespawn" : "%s\W.*pacemakerd.*Respawning failed child process: %s",

            "Pat:PacemakerUp"  : "%s\W.*pacemakerd.*Starting Pacemaker",
        })

#        if self.Env["have_systemd"]:
#            self.update({
#                # When systemd is in use, we can look for this instead
#                "Pat:We_stopped"   : "%s.*Stopped Corosync Cluster Engine",
#            })

class crm_mcp_docker(crm_mcp):
    '''
    The crm version 4 cluster manager class.
    It implements the things we need to talk to and manipulate
    crm clusters running on top of native corosync (no plugins)
    '''
    def __init__(self, name):
        crm_mcp.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "pcmk_start",
            "StopCmd"        : "pcmk_stop",
        })

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
            "StopCmd"        : "service pacemaker stop; [ ! -e /usr/sbin/pacemaker_remoted ] || service pacemaker_remote stop",

            "EpochCmd"      : "crm_node -e --cman",
            "QuorumCmd"      : "crm_node -q --cman",
            "PartitionCmd"    : "crm_node -p --cman",
        })

        self.search.update({
            "Pat:We_stopped"   : "%s.*Unloading all Corosync service engines",
            "Pat:They_stopped" : "%s\W.*crmd.*Node %s(\[|\s).*state is now lost",
            "Pat:They_dead"    : "crmd.*Node %s(\[|\s).*state is now lost",

            "Pat:ChildKilled"  : "%s\W.*pacemakerd.*The %s process .* terminated with signal 9",
            "Pat:ChildRespawn" : "%s\W.*pacemakerd.*Respawning failed child process: %s",

            "Pat:PacemakerUp"  : "%s\W.*pacemakerd.*Starting Pacemaker",
        })



class PatternSelector:

    def __init__(self, name=None):
        self.name = name
        self.base = BasePatterns("crm-base")

        if not name:
            crm_cs_v0("crm-plugin-v0")
            crm_cman("crm-cman")
            crm_mcp("crm-mcp")
            crm_lha("crm-lha")
        elif name == "crm-lha":
            crm_lha(name)
        elif name == "crm-plugin-v0":
            crm_cs_v0(name)
        elif name == "crm-cman":
            crm_cman(name)
        elif name == "crm-mcp":
            crm_mcp(name)
        elif name == "crm-mcp-docker":
            crm_mcp_docker(name)

    def get_variant(self, variant):
        if variant in patternvariants:
            return patternvariants[variant]
        print("defaulting to crm-base for %s" % variant)
        return self.base

    def get_patterns(self, variant, kind):
        return self.get_variant(variant).get_patterns(kind)

    def get_template(self, variant, key):
        v = self.get_variant(variant)
        return v[key]

    def get_component(self, variant, kind):
        return self.get_variant(variant).get_component(kind)

    def __getitem__(self, key):
        return self.get_template(self.name, key)

# python cts/CTSpatt.py -k crm-mcp -t StartCmd
if __name__ == '__main__':

    pdir=os.path.dirname(sys.path[0])
    sys.path.insert(0, pdir) # So that things work from the source directory

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
           print("Illegal argument " + args[i])


    print(PatternSelector(kind)[template])
