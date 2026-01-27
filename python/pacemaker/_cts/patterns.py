"""Pattern-holding classes for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["PatternSelector"]
__copyright__ = "Copyright 2008-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+)"

from pacemaker.buildoptions import BuildOptions


class BasePatterns:
    """
    The base class for holding a stack-specific set of command and log file/stdout patterns.

    Stack-specific classes need to be built on top of this one.
    """

    def __init__(self):
        """Create a new BasePatterns instance which holds a very minimal set of basic patterns."""
        self._bad_news = []
        self._components = {}
        self._name = "crm-base"

        self._ignore = [
            "avoid confusing Valgrind",

            # Logging bug in some versions of libvirtd
            r"libvirtd.*: internal error: Failed to parse PCI config address",

            # pcs can log this when node is fenced, but fencing is OK in some
            # tests (and we will catch it in pacemaker logs when not OK)
            r"pcs.daemon:No response from: .* request: get_configs, error:",

            # This is overbroad, but there's no way to say that only certain
            # transition errors are acceptable. We have to rely on causes of a
            # transition error logging their own error message, which should
            # always be the case.
            r"pacemaker-schedulerd.* Calculated transition .*/pe-error",

            # This message comes up periodically but doesn't actually seem to
            # be related to any specific test failure, so just ignore it.
            r"pacemaker-based.* Local CIB .* differs from",
        ]

        self._commands = {
            "StatusCmd": "crmadmin -t 60 -S %s 2>/dev/null",
            "CibQuery": "cibadmin -Q",
            "CibAddXml": "cibadmin --modify -c --xml-text %s",
            "CibDelXpath": "cibadmin --delete --xpath %s",
            "RscRunning": BuildOptions.DAEMON_DIR + "/cts-exec-helper -R -r %s",
            "CIBfile": "%s:" + BuildOptions.CIB_DIR + "/cib.xml",
            "TmpDir": "/tmp",

            "BreakCommCmd": "iptables -A INPUT -s %s -j DROP >/dev/null 2>&1",
            "FixCommCmd": "iptables -D INPUT -s %s -j DROP >/dev/null 2>&1",

            "MaintenanceModeOn": "cibadmin --modify -c --xml-text '<cluster_property_set id=\"cib-bootstrap-options\"><nvpair id=\"cts-maintenance-mode-setting\" name=\"maintenance-mode\" value=\"true\"/></cluster_property_set>'",
            "MaintenanceModeOff": "cibadmin --delete --xpath \"//nvpair[@name='maintenance-mode']\"",

            "StandbyCmd": "crm_attribute -Vq  -U %s -n standby -l forever -v %s 2>/dev/null",
            "StandbyQueryCmd": "crm_attribute -qG -U %s -n standby -l forever -d off 2>/dev/null",
        }

        self._search = {
            "Pat:DC_IDLE": r"pacemaker-controld.*State transition.*-> S_IDLE",

            # This won't work if we have multiple partitions
            "Pat:Local_started": r"%s\W.*controller successfully started",
            "Pat:NonDC_started": r"%s\W.*State transition.*-> S_NOT_DC",
            "Pat:DC_started": r"%s\W.*State transition.*-> S_IDLE",
            "Pat:We_stopped": r"%s\W.*OVERRIDE THIS PATTERN",
            "Pat:They_stopped": r"%s\W.*LOST:.* %s ",
            "Pat:They_dead": r"node %s.*: is dead",
            "Pat:They_up": r"%s %s\W.*OVERRIDE THIS PATTERN",
            "Pat:TransitionComplete": "Transition status: Complete: complete",

            "Pat:Fencing_start": r"Requesting peer fencing .* targeting %s",
            "Pat:Fencing_ok": r"pacemaker-fenced.*:\s*Operation .* targeting %s by .* for .*@.*: OK",
            "Pat:Fencing_recover": r"pacemaker-schedulerd.*: Recover\s+%s",
            "Pat:Resource_active": r"resource .* might be active on \d+ nodes \(attempting recovery\)",
            "Pat:Fencing_probe": r"pacemaker-controld.* Result of probe operation for %s on .*: Error",

            "Pat:RscOpOK": r"pacemaker-controld.*:\s+Result of %s operation for %s.*: (0 \()?OK",
            "Pat:RscOpFail": r"pacemaker-schedulerd.*:.*Unexpected result .* recorded for %s of %s ",
            "Pat:CloneOpFail": r"pacemaker-schedulerd.*:.*Unexpected result .* recorded for %s of (%s|%s) ",
            "Pat:RscRemoteOpOK": r"pacemaker-controld.*:\s+Result of %s operation for %s on %s: (0 \()?OK",
            "Pat:NodeFenced": r"pacemaker-controld.*:\s* Peer %s was terminated \(.*\) by .* on behalf of .*: OK",
        }

    def get_component(self, key):
        """
        Return the patterns for a single component as a list, given by key.

         This is typically the name of some subprogram (pacemaker-based,
         pacemaker-fenced, etc.) or various special purpose keys.  If key is
         unknown, return an empty list.
        """
        if key in self._components:
            return self._components[key]

        print(f"Unknown component '{key}' for {self._name}")
        return []

    def get_patterns(self, key):
        """
        Return various patterns supported by this object, given by key.

        Depending on the key, this could either be a list or a hash.  If key is
        unknown, return None.
        """
        if key == "BadNews":
            return self._bad_news
        if key == "BadNewsIgnore":
            return self._ignore
        if key == "Commands":
            return self._commands
        if key == "Search":
            return self._search
        if key == "Components":
            return self._components

        print(f"Unknown pattern '{key}' for {self._name}")
        return None

    def __getitem__(self, key):
        if key in self._commands:
            return self._commands[key]
        if key in self._search:
            return self._search[key]

        print(f"Unknown template '{key}' for {self._name}")
        return None


class Corosync2Patterns(BasePatterns):
    """Patterns for Corosync version 2 cluster manager class."""

    # @FIXME Some of the templates here look like they start with
    # incorrect daemon names. Also, many of them aren't Corosync-
    # specific and should probably go in BasePatterns.

    def __init__(self):
        BasePatterns.__init__(self)
        self._name = "crm-corosync"

        self._commands.update({
            "StartCmd": "service corosync start && service pacemaker start",
            "StopCmd": "service pacemaker stop; [ ! -e /usr/sbin/pacemaker-remoted ] || service pacemaker_remote stop; service corosync stop",

            "EpochCmd": "crm_node -e",
            "QuorumCmd": "crm_node -q",
            "PartitionCmd": "crm_node -p",
        })

        self._search.update({
            # Close enough ... "Corosync Cluster Engine exiting normally" isn't
            # printed reliably.
            "Pat:We_stopped": r"%s\W.*Unloading all Corosync service engines",
            "Pat:They_stopped": r"%s\W.*pacemaker-controld.*Node %s(\[|\s).*state is now lost",
            "Pat:They_dead": r"pacemaker-controld.*Node %s(\[|\s).*state is now lost",
            "Pat:They_up": r"\W%s\W.*pacemaker-controld.*Node %s state is now member",

            "Pat:ChildExit": r"\[[0-9]+\] exited with status [0-9]+ \(",
            # "with signal 9" == pcmk_child_exit(), "$" == check_active_before_startup_processes()
            "Pat:ChildKilled": r"%s\W.*pacemakerd.*%s\[[0-9]+\] terminated( with signal 9|$)",
            "Pat:ChildRespawn": r"%s\W.*pacemakerd.*Respawning subdaemon %s after unexpected exit",

            "Pat:InfraUp": r"%s\W.*corosync.*Initializing transport",
            "Pat:PacemakerUp": r"%s\W.*pacemakerd.*Starting Pacemaker",
        })

        self._ignore += [
            r"crm_mon:",
            r"crmadmin:",
            r"update_trace_data",
            r"async_notify:.*strange, client not found",
            r"Parse error: Ignoring unknown option .*nodename",
            r"error.*: Operation 'reboot' .* using FencingFail returned ",
            r"getinfo response error: 1$",
            r"sbd.* error: inquisitor_child: DEBUG MODE IS ACTIVE",
            r"sbd.* pcmk:\s*error:.*Connection to cib_rw.* (failed|closed)",
        ]

        self._bad_news = [
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
            r"pacemakerd.*\[[0-9]+\] terminated( with signal|$)",
            r"pacemakerd.*\[[0-9]+\] .* will now be killed",
            r"pacemaker-schedulerd.*Recover\s+.*\(.* -\> .*\)",
            r"rsyslogd.* lost .* due to rate-limiting",
            r"Peer is not part of our cluster",
            r"We appear to be in an election loop",
            r"Unknown node -> we will not deliver message",
            r"(Blackbox dump requested|Problem detected)",
            r"pacemakerd.*Could not connect to Cluster Configuration Database API",
            r"Receiving messages from a node we think is dead",
            r"share the same cluster nodeid",
            r"share the same name",

            r"pacemaker-controld:.*Transition failed: terminated",
            r"Local CIB .* differs from .*:",
            r"warn.*:\s*Continuing but .* will NOT be used",
            r"warn.*:\s*Cluster configuration file .* is corrupt",
            r"Election storm",
            r"stalled the FSA with pending inputs",
        ]

        components_common_ignore = [
            r"Pending action:",
            r"resource( was|s were) active at shutdown",
            r"pending LRM operations at shutdown",
            r"Lost connection to the CIB manager",
            r"pacemaker-controld.*:\s*Action A_RECOVER .* not supported",
            r"pacemaker-controld.*:\s*Exiting now due to errors",
            r".*:\s*Requesting fencing \([^)]+\) targeting node ",
            r"(Blackbox dump requested|Problem detected)",
        ]

        self._components["corosync-ignore"] = components_common_ignore + [
            r"Could not connect to Corosync CFG: CS_ERR_LIBRARY",
            r"error:.*Connection to the CPG API failed: Library error",
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
            r"error: Lost fencer connection",
        ]

        self._components["corosync"] = [
            # We expect each daemon to lose its cluster connection.
            # However, if the CIB manager loses its connection first,
            # it's possible for another daemon to lose that connection and
            # exit before losing the cluster connection.
            r"pacemakerd.*:\s*warning:.*Lost connection to cluster layer",
            r"pacemaker-attrd.*:\s*(crit|error):.*Lost connection to (Corosync process group|the CIB manager)",
            r"pacemaker-based.*:\s*crit:.*Exiting immediately after losing connection to cluster layer",
            r"pacemaker-controld.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"pacemaker-fenced.*:\s*(crit|error):.*Lost connection to (cluster layer|the CIB manager)",
            r"schedulerd.*Scheduling node .* for fencing",
            r"pacemaker-controld.*:\s*Peer .* was terminated \(.*\) by .* on behalf of .*:\s*OK",
        ]

        self._components["pacemaker-based"] = [
            r"pacemakerd.* pacemaker-attrd\[[0-9]+\] exited with status 102",
            r"pacemakerd.* pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.* Respawning subdaemon pacemaker-attrd after unexpected exit",
            r"pacemakerd.* Respawning subdaemon pacemaker-based after unexpected exit",
            r"pacemakerd.* Respawning subdaemon pacemaker-controld after unexpected exit",
            r"pacemakerd.* Respawning subdaemon pacemaker-fenced after unexpected exit",
            r"pacemaker-.* Connection to cib_.* (failed|closed)",
            r"pacemaker-attrd.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*:.*Lost connection to the CIB manager",
            r"pacemaker-controld.*I_ERROR.*handle_cib_disconnect",
            r"pacemaker-controld.* State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
        ]

        self._components["pacemaker-based-ignore"] = components_common_ignore + [
            r"pacemaker-execd.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"pacemaker-controld.*:\s+Result of .* operation for Fencing.*Error \(Lost connection to fencer\)",
            r"pacemaker-controld.*:Could not connect to attrd: Connection refused",
        ]

        self._components["pacemaker-execd"] = [
            r"pacemaker-controld.*Lost connection to local executor",
            r"pacemaker-controld.*I_ERROR.*lrm_connection_destroy",
            r"pacemaker-controld.*State transition .* S_RECOVERY",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
            r"pacemakerd.*pacemaker-controld\[[0-9]+\] exited with status 1",
            r"pacemakerd.* Respawning subdaemon pacemaker-execd after unexpected exit",
            r"pacemakerd.* Respawning subdaemon pacemaker-controld after unexpected exit",
        ]

        self._components["pacemaker-execd-ignore"] = components_common_ignore + [
            r"pacemaker-(attrd|controld).*Connection to lrmd.* (failed|closed)",
            r"pacemaker-(attrd|controld).*Could not execute alert",
        ]

        self._components["pacemaker-controld"] = [
            r"State transition .* -> S_IDLE",
        ]

        self._components["pacemaker-controld-ignore"] = components_common_ignore
        self._components["pacemaker-attrd"] = []
        self._components["pacemaker-attrd-ignore"] = components_common_ignore + [
            r"pacemaker-controld.*Connection to attrd (IPC failed|closed)",
        ]

        self._components["pacemaker-schedulerd"] = [
            r"State transition .* S_RECOVERY",
            r"pacemakerd.* Respawning subdaemon pacemaker-controld after unexpected exit",
            r"pacemaker-controld\[[0-9]+\] exited with status 1 \(",
            r"pacemaker-controld.*Lost connection to the scheduler",
            r"pacemaker-controld.*I_ERROR.*save_cib_contents",
            r"pacemaker-controld.*: Input I_TERMINATE .*from do_recover",
            r"pacemaker-controld.*Could not recover from internal error",
        ]

        self._components["pacemaker-schedulerd-ignore"] = components_common_ignore + [
            r"Connection to pengine.* (failed|closed)",
        ]

        self._components["pacemaker-fenced"] = [
            r"error:.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"Lost fencer connection",
            r"pacemaker-controld.*Fencer successfully connected",
        ]

        self._components["pacemaker-fenced-ignore"] = components_common_ignore + [
            r"(error|warning):.*Connection to (fencer|stonith-ng).* (closed|failed|lost)",
            r"error:.*Lost fencer connection",
            r"error:.*Fencer connection failed \(will retry\)",
            r"pacemaker-controld.*:\s+Result of .* operation for Fencing.*Error \(Lost connection to fencer\)",
        ]


patternVariants = {
    "crm-base": BasePatterns,
    "crm-corosync": Corosync2Patterns
}


class PatternSelector:
    """Choose from among several Pattern objects and return the information from that object."""

    def __init__(self, name="crm-corosync"):
        """
        Create a new PatternSelector object.

        Instantiate whatever class is given by name.  Defaults to Corosync2Patterns
        for "crm-corosync" or None.  While other objects could be supported in the
        future, only this and the base object are supported at this time.
        """
        self._name = name

        # If no name was given, use the default.  Otherwise, look up the appropriate
        # class in patternVariants, instantiate it, and use that.
        if not name:
            self._base = Corosync2Patterns()
        else:
            self._base = patternVariants[name]()

    def __getitem__(self, key):
        """
        Return a single pattern from the previously instantiated pattern object.

        If no pattern exists for the given key, return None.
        """
        return self._base[key]

    def get_patterns(self, kind):
        """Call get_patterns on the previously instantiated pattern object."""
        return self._base.get_patterns(kind)

    def get_component(self, kind):
        """Call get_component on the previously instantiated pattern object."""
        return self._base.get_component(kind)
