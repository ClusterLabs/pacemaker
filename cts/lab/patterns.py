""" Pattern-holding classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2008-2021 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys, os

from cts.CTSvars import *

patternvariants = {}
class BasePatterns(object):
    def __init__(self, name):
        self.name = name
        patternvariants[name] = self
        self.ignore = [
            "avoid confusing Valgrind",

            # Logging bug in some versions of libvirtd
            r"libvirtd.*: internal error: Failed to parse PCI config address",

            # pcs can log this when node is fenced, but fencing is OK in some
            # tests (and we will catch it in pacemaker logs when not OK)
            r"pcs.daemon:No response from: .* request: get_configs, error:",
        ]
        self.BadNews = []
        self.components = {}
        self.commands = {
            "StatusCmd"      : "crmadmin -t 60 -S %s 2>/dev/null",
            "CibQuery"       : "cibadmin -Ql",
            "CibAddXml"      : "cibadmin --modify -c --xml-text %s",
            "CibDelXpath"    : "cibadmin --delete --xpath %s",
            # 300,000 == 5 minutes
            "RscRunning"     : CTSvars.CRM_DAEMON_DIR + "/cts-exec-helper -R -r %s",
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

            "MaintenanceModeOn"    : "cibadmin --modify -c --xml-text '<cluster_property_set id=\"cib-bootstrap-options\"><nvpair id=\"cts-maintenance-mode-setting\" name=\"maintenance-mode\" value=\"true\"/></cluster_property_set>'",
            "MaintenanceModeOff"    : "cibadmin --delete --xpath \"//nvpair[@name='maintenance-mode']\"",

            "StandbyCmd"      : "crm_attribute -Vq  -U %s -n standby -l forever -v %s 2>/dev/null",
            "StandbyQueryCmd" : "crm_attribute -qG -U %s -n standby -l forever -d off 2>/dev/null",
        }
        self.search = {
            "Pat:DC_IDLE"      : "pacemaker-controld.*State transition.*-> S_IDLE",
            
            # This won't work if we have multiple partitions
            "Pat:Local_started" : "%s\W.*controller successfully started",
            "Pat:NonDC_started" : r"%s\W.*State transition.*-> S_NOT_DC",
            "Pat:DC_started"    : r"%s\W.*State transition.*-> S_IDLE",
            "Pat:We_stopped"    : "%s\W.*OVERRIDE THIS PATTERN",
            "Pat:They_stopped"  : "%s\W.*LOST:.* %s ",
            "Pat:They_dead"     : "node %s.*: is dead",
            "Pat:They_up"       : "%s %s\W.*OVERRIDE THIS PATTERN",
            "Pat:TransitionComplete" : "Transition status: Complete: complete",

            "Pat:Fencing_start"   : r"Requesting peer fencing .* targeting %s",
            "Pat:Fencing_ok"      : r"pacemaker-fenced.*:\s*Operation .* targeting %s by .* for .*@.*: OK",
            "Pat:Fencing_recover" : r"pacemaker-schedulerd.*: Recover %s",
            "Pat:Fencing_active"  : r"stonith resource .* is active on 2 nodes (attempting recovery)",
            "Pat:Fencing_probe"   : r"pacemaker-controld.* Result of probe operation for %s on .*: Error",

            "Pat:RscOpOK"       : r"pacemaker-controld.*:\s+Result of %s operation for %s.*: (0 \()?ok",
            "Pat:RscOpFail"     : r"pacemaker-schedulerd.*:.*Unexpected result .* recorded for %s of %s ",
            "Pat:CloneOpFail"   : r"pacemaker-schedulerd.*:.*Unexpected result .* recorded for %s of (%s|%s) ",
            "Pat:RscRemoteOpOK" : r"pacemaker-controld.*:\s+Result of %s operation for %s on %s: (0 \()?ok",
            "Pat:NodeFenced"    : r"pacemaker-controld.*:\s* Peer %s was terminated \(.*\) by .* on behalf of .*: OK",
            "Pat:FenceOpOK"     : "Operation .* targeting %s using .* returned 0",
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


class crm_corosync(BasePatterns):
    '''
    Patterns for Corosync version 2 cluster manager class
    '''

    def __init__(self, name):
        BasePatterns.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "service corosync start && service pacemaker start",
            "StopCmd"        : "service pacemaker stop; [ ! -e /usr/sbin/pacemaker-remoted ] || service pacemaker_remote stop; service corosync stop",

            "EpochCmd"      : "crm_node -e",
            "QuorumCmd"      : "crm_node -q",
            "PartitionCmd"    : "crm_node -p",
        })

        self.search.update({
            # Close enough ... "Corosync Cluster Engine exiting normally" isn't
            # printed reliably.
            "Pat:We_stopped"   : "%s\W.*Unloading all Corosync service engines",
            "Pat:They_stopped" : "%s\W.*pacemaker-controld.*Node %s(\[|\s).*state is now lost",
            "Pat:They_dead"    : "pacemaker-controld.*Node %s(\[|\s).*state is now lost",
            "Pat:They_up"      : "\W%s\W.*pacemaker-controld.*Node %s state is now member",

            "Pat:ChildExit"    : r"\[[0-9]+\] exited with status [0-9]+ \(",
            # "with signal 9" == pcmk_child_exit(), "$" == check_active_before_startup_processes()
            "Pat:ChildKilled"  : r"%s\W.*pacemakerd.*%s\[[0-9]+\] terminated( with signal 9|$)",
            "Pat:ChildRespawn" : "%s\W.*pacemakerd.*Respawning failed child process: %s",

            "Pat:InfraUp"      : "%s\W.*corosync.*Initializing transport",
            "Pat:PacemakerUp"  : "%s\W.*pacemakerd.*Starting Pacemaker",
        })

        self.ignore = self.ignore + [
            r"crm_mon:",
            r"crmadmin:",
            r"update_trace_data",
            r"async_notify:.*strange, client not found",
            r"Parse error: Ignoring unknown option .*nodename",
            r"error.*: Operation 'reboot' .* using FencingFail returned ",
            r"getinfo response error: 1$",
            r"sbd.* error: inquisitor_child: DEBUG MODE IS ACTIVE",
            r"sbd.* pcmk:\s*error:.*Connection to cib_ro.* (failed|closed)",
        ]

        self.BadNews = [
            r"[^(]error:",
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
            r"(pacemakerd|pacemaker-execd|pacemaker-controld):.*, exiting",
            r"schedulerd.*Attempting recovery of resource",
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
            r"pacemakerd.*\[[0-9]+\] terminated( with signal| as IPC server|$)",
            r"pacemaker-schedulerd.*Recover .*\(.* -\> .*\)",
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
            r"pacemaker-controld:.*Transition failed: terminated",
            r"Local CIB .* differs from .*:",
            r"warn.*:\s*Continuing but .* will NOT be used",
            r"warn.*:\s*Cluster configuration file .* is corrupt",
            #r"Executing .* fencing operation",
            r"Election storm",
            r"stalled the FSA with pending inputs",
        ]

        self.components["common-ignore"] = [
            r"Pending action:",
            r"resource( was|s were) active at shutdown",
            r"pending LRM operations at shutdown",
            r"Lost connection to the CIB manager",
            r"pacemaker-controld.*:\s*Action A_RECOVER .* not supported",
            r"pacemaker-controld.*:\s*Performing A_EXIT_1 - forcefully exiting ",
            r".*:\s*Requesting fencing \([^)]+\) of node ",
            r"(Blackbox dump requested|Problem detected)",
        ]
        
        self.components["corosync-ignore"] = [
            r"Could not connect to Corosync CFG: CS_ERR_LIBRARY",
            r"\[[0-9]+\] exited with status [0-9]+ \(",
            r"\[[0-9]+\] terminated with signal 15",
            r"pacemaker-based.*error:.*Corosync connection lost",
            r"pacemaker-fenced.*error:.*Corosync connection terminated",
            r"pacemaker-controld.*State transition .* S_RECOVERY",
            r"pacemaker-controld.*error:.*Input (I_ERROR|I_TERMINATE ) .*received in state",
            r"pacemaker-controld.*error:.*Could not recover from internal error",
            r"error:.*Connection to cib_(shm|rw).* (failed|closed)",
            r"error:.*cib_(shm|rw) IPC provider disconnected while waiting",
            r"error:.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"crit: Fencing daemon connection failed",
            # This is overbroad, but we don't have a way to say that only
            # certain transition errors are acceptable (if the fencer respawns,
            # fence devices may appear multiply active). We have to rely on
            # other causes of a transition error logging their own error
            # message, which is the usual practice.
            r"pacemaker-schedulerd.* Calculated transition .*/pe-error",
            ]

        self.components["corosync"] = [
            # We expect each daemon to lose its cluster connection.
            # However, if the CIB manager loses its connection first,
            # it's possible for another daemon to lose that connection and
            # exit before losing the cluster connection.
            r"pacemakerd.*:\s*(crit|error):.*Lost connection to cluster layer",
            r"pacemaker-attrd.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"pacemaker-based.*:\s*(crit|error):.*Lost connection to cluster layer",
            r"pacemaker-controld.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"pacemaker-fenced.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"schedulerd.*Scheduling Node .* for STONITH",
            r"pacemaker-controld.*:\s*Peer .* was terminated \(.*\) by .* on behalf of .*:\s*OK",
        ]

        self.components["pacemaker-based"] = [
            r"pacemakerd.* pacemaker-attrd\[[0-9]+\] exited with status 102",
            r"pacemakerd.* pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.* Respawning failed child process: pacemaker-attrd",
            r"pacemakerd.* Respawning failed child process: pacemaker-based",
            r"pacemakerd.* Respawning failed child process: pacemaker-controld",
            r"pacemakerd.* Respawning failed child process: pacemaker-fenced",
            r"pacemaker-.* Connection to cib_.* (failed|closed)",
            r"pacemaker-attrd.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*I_ERROR.*crmd_cib_connection_destroy",
            r"pacemaker-controld.* State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
        ]
        self.components["pacemaker-based-ignore"] = [
            r"pacemaker-execd.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            # This is overbroad, but we don't have a way to say that only
            # certain transition errors are acceptable (if the fencer respawns,
            # fence devices may appear multiply active). We have to rely on
            # other causes of a transition error logging their own error
            # message, which is the usual practice.
            r"pacemaker-schedulerd.* Calculated transition .*/pe-error",
        ]

        self.components["pacemaker-execd"] = [
            r"pacemaker-controld.*Connection to executor failed",
            r"pacemaker-controld.*I_ERROR.*lrm_connection_destroy",
            r"pacemaker-controld.*State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
            r"pacemakerd.*pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.*Respawning failed child process: pacemaker-execd",
            r"pacemakerd.*Respawning failed child process: pacemaker-controld",
        ]
        self.components["pacemaker-execd-ignore"] = [
            r"pacemaker-(attrd|controld).*Connection to lrmd.* (failed|closed)",
            r"pacemaker-(attrd|controld).*Could not execute alert",
        ]

        self.components["pacemaker-controld"] = [
#                    "WARN: determine_online_status: Node .* is unclean",
#                    "Scheduling Node .* for STONITH",
# Only if the node wasn't the DC:  "State transition S_IDLE",
                    "State transition .* -> S_IDLE",
                    ]
        self.components["pacemaker-controld-ignore"] = []

        self.components["pacemaker-attrd"] = []
        self.components["pacemaker-attrd-ignore"] = []

        self.components["pacemaker-schedulerd"] = [
                    "State transition .* S_RECOVERY",
                    r"Respawning failed child process: pacemaker-controld",
                    r"pacemaker-controld\[[0-9]+\] exited with status 1 \(",
                    r"Connection to the scheduler failed",
                    "pacemaker-controld.*I_ERROR.*save_cib_contents",
                    r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
                    "pacemaker-controld.*Could not recover from internal error",
                    ]
        self.components["pacemaker-schedulerd-ignore"] = [
            r"Connection to pengine.* (failed|closed)",
        ]

        self.components["pacemaker-fenced"] = [
            r"error:.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"Fencing daemon connection failed",
            r"pacemaker-controld.*Fencer successfully connected",
        ]
        self.components["pacemaker-fenced-ignore"] = [
            r"error:.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"crit:.*Fencing daemon connection failed",
            r"error:.*Fencer connection failed \(will retry\)",
            r"Connection to (fencer|stonith-ng) failed, finalizing .* pending operations",
            r"pacemaker-controld.*:\s+Result of .* operation for Fencing.*Error",
            # This is overbroad, but we don't have a way to say that only
            # certain transition errors are acceptable (if the fencer respawns,
            # fence devices may appear multiply active). We have to rely on
            # other causes of a transition error logging their own error
            # message, which is the usual practice.
            r"pacemaker-schedulerd.* Calculated transition .*/pe-error",
        ]
        self.components["pacemaker-fenced-ignore"].extend(self.components["common-ignore"])


class crm_corosync_docker(crm_corosync):
    '''
    Patterns for Corosync version 2 cluster manager class
    '''
    def __init__(self, name):
        crm_corosync.__init__(self, name)

        self.commands.update({
            "StartCmd"       : "pcmk_start",
            "StopCmd"        : "pcmk_stop",
        })


class PatternSelector(object):

    def __init__(self, name=None):
        self.name = name
        self.base = BasePatterns("crm-base")

        if not name:
            crm_corosync("crm-corosync")
        elif name == "crm-corosync":
            crm_corosync(name)
        elif name == "crm-corosync-docker":
            crm_corosync_docker(name)

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

# python cts/CTSpatt.py -k crm-corosync -t StartCmd
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
