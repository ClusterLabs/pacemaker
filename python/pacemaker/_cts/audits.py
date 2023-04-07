""" Auditing classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import time, re, uuid

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.watcher import LogKind, LogWatcher

AllAuditClasses = [ ]


class ClusterAudit(object):
    def __init__(self, cm):
        self.CM = cm

    def __call__(self):
        raise ValueError("Abstract Class member (__call__)")

    def is_applicable(self):
        '''Return TRUE if we are applicable in the current test configuration'''
        raise ValueError("Abstract Class member (is_applicable)")
        return 1

    def log(self, args):
        self.CM.log("audit: %s" % args)

    def debug(self, args):
        self.CM.debug("audit: %s" % args)

    def name(self):
        raise ValueError("Abstract Class member (name)")


class LogAudit(ClusterAudit):
    def name(self):
        return "LogAudit"

    def __init__(self, cm):
        self.CM = cm

    def RestartClusterLogging(self, nodes=None):
        if not nodes:
            nodes = self.CM.Env["nodes"]

        self.CM.debug("Restarting logging on: %s" % repr(nodes))

        for node in nodes:
            if self.CM.Env["have_systemd"]:
                (rc, _) = self.CM.rsh(node, "systemctl stop systemd-journald.socket")
                if rc != 0:
                    self.CM.log ("ERROR: Cannot stop 'systemd-journald' on %s" % node)

                (rc, _) = self.CM.rsh(node, "systemctl start systemd-journald.service")
                if rc != 0:
                    self.CM.log ("ERROR: Cannot start 'systemd-journald' on %s" % node)

            (rc, _) = self.CM.rsh(node, "service %s restart" % self.CM.Env["syslogd"])
            if rc != 0:
                self.CM.log ("ERROR: Cannot restart '%s' on %s" % (self.CM.Env["syslogd"], node))

    def _create_watcher(self, patterns, kind):
        watch = LogWatcher(self.CM.Env["LogFileName"], patterns,
                           self.CM.Env["nodes"], kind, "LogAudit", 5,
                           silent=True)
        watch.set_watch()
        return watch

    def TestLogging(self):
        patterns = []
        prefix   = "Test message from"
        suffix   = str(uuid.uuid4())
        watch    = {}

        for node in self.CM.Env["nodes"]:
            # Look for the node name in two places to make sure
            # that syslog is logging with the correct hostname
            m = re.search("^([^.]+).*", node)
            if m:
                simple = m.group(1)
            else:
                simple = node

            patterns.append("%s.*%s %s %s" % (simple, prefix, node, suffix))

        watch_pref = self.CM.Env["LogWatcher"]
        if watch_pref == LogKind.ANY:
            kinds = [ LogKind.FILE ]
            if self.CM.Env["have_systemd"]:
                kinds +=  [ LogKind.JOURNAL ]
            kinds += [ LogKind.REMOTE_FILE ]
            for k in kinds:
                watch[k] = self._create_watcher(patterns, k)
            self.CM.log("Logging test message with identifier %s" % (suffix))
        else:
            watch[watch_pref] = self._create_watcher(patterns, watch_pref)

        for node in self.CM.Env["nodes"]:
            cmd = "logger -p %s.info %s %s %s" % (self.CM.Env["SyslogFacility"], prefix, node, suffix)

            (rc, _) = self.CM.rsh(node, cmd, synchronous=False, verbose=0)
            if rc != 0:
                self.CM.log ("ERROR: Cannot execute remote command [%s] on %s" % (cmd, node))

        for k in list(watch.keys()):
            w = watch[k]
            if watch_pref == LogKind.ANY:
                self.CM.log("Checking for test message in %s logs" % (k))
            w.look_for_all(silent=True)
            if w.unmatched:
                for regex in w.unmatched:
                    self.CM.log("Test message [%s] not found in %s logs" % (regex, w.kind))
            else:
                if watch_pref == LogKind.ANY:
                    self.CM.log("Found test message in %s logs" % (k))
                    self.CM.Env["LogWatcher"] = k
                return 1

        return 0

    def __call__(self):
        max = 3
        attempt = 0

        self.CM.ns.wait_for_all_nodes(self.CM.Env["nodes"])
        while attempt <= max and self.TestLogging() == 0:
            attempt = attempt + 1
            self.RestartClusterLogging()
            time.sleep(60*attempt)

        if attempt > max:
            self.CM.log("ERROR: Cluster logging unrecoverable.")
            return 0

        return 1

    def is_applicable(self):
        if self.CM.Env["DoBSC"]:
            return 0
        if self.CM.Env["LogAuditDisabled"]:
            return 0

        return 1


class DiskAudit(ClusterAudit):
    def name(self):
        return "DiskspaceAudit"

    def __init__(self, cm):
        self.CM = cm

    def __call__(self):
        result = 1
        # @TODO Use directory of PCMK_logfile if set on host
        dfcmd = "df -BM " + BuildOptions.LOG_DIR + " | tail -1 | awk '{print $(NF-1)\" \"$(NF-2)}' | tr -d 'M%'"

        self.CM.ns.wait_for_all_nodes(self.CM.Env["nodes"])
        for node in self.CM.Env["nodes"]:
            (_, dfout) = self.CM.rsh(node, dfcmd, verbose=1)
            if not dfout:
                self.CM.log ("ERROR: Cannot execute remote df command [%s] on %s" % (dfcmd, node))
            else:
                dfout = dfout[0].strip()

                try:
                    (used, remain) = dfout.split()
                    used_percent = int(used)
                    remaining_mb = int(remain)
                except (ValueError, TypeError):
                    self.CM.log("Warning: df output '%s' from %s was invalid [%s, %s]"
                                % (dfout, node, used, remain))
                else:
                    if remaining_mb < 10 or used_percent > 95:
                        self.CM.log("CRIT: Out of log disk space on %s (%d%% / %dMB)"
                                    % (node, used_percent, remaining_mb))
                        result = None
                        if self.CM.Env["continue"]:
                            answer = "Y"
                        else:
                            try:
                                answer = input('Continue? [nY]')
                            except EOFError as e:
                                answer = "n"

                        if answer and answer == "n":
                            raise ValueError("Disk full on %s" % (node))

                    elif remaining_mb < 100 or used_percent > 90:
                        self.CM.log("WARN: Low on log disk space (%dMB) on %s" % (remaining_mb, node))
        return result

    def is_applicable(self):
        if self.CM.Env["DoBSC"]:
            return 0
        return 1


class FileAudit(ClusterAudit):
    def name(self):
        return "FileAudit"

    def __init__(self, cm):
        self.CM = cm
        self.known = []

    def __call__(self):
        result = 1

        self.CM.ns.wait_for_all_nodes(self.CM.Env["nodes"])
        for node in self.CM.Env["nodes"]:

            (_, lsout) = self.CM.rsh(node, "ls -al /var/lib/pacemaker/cores/* | grep core.[0-9]", verbose=1)
            for line in lsout:
                line = line.strip()

                if line not in self.known:
                    result = 0
                    self.known.append(line)
                    self.CM.log("Warning: Pacemaker core file on %s: %s" % (node, line))

            (_, lsout) = self.CM.rsh(node, "ls -al /var/lib/corosync | grep core.[0-9]", verbose=1)
            for line in lsout:
                line = line.strip()

                if line not in self.known:
                    result = 0
                    self.known.append(line)
                    self.CM.log("Warning: Corosync core file on %s: %s" % (node, line))

            if node in self.CM.ShouldBeStatus and self.CM.ShouldBeStatus[node] == "down":
                clean = 0
                (_, lsout) = self.CM.rsh(node, "ls -al /dev/shm | grep qb-", verbose=1)

                for line in lsout:
                    result = 0
                    clean = 1
                    self.CM.log("Warning: Stale IPC file on %s: %s" % (node, line))

                if clean:
                    (_, lsout) = self.CM.rsh(node, "ps axf | grep -e pacemaker -e corosync", verbose=1)

                    for line in lsout:
                        self.CM.debug("ps[%s]: %s" % (node, line))

                    self.CM.rsh(node, "rm -rf /dev/shm/qb-*")

            else:
                self.CM.debug("Skipping %s" % node)

        return result

    def is_applicable(self):
        return 1


class AuditResource(object):
    def __init__(self, cm, line):
        fields = line.split()
        self.CM = cm
        self.line = line
        self.type = fields[1]
        self.id = fields[2]
        self.clone_id = fields[3]
        self.parent = fields[4]
        self.rprovider = fields[5]
        self.rclass = fields[6]
        self.rtype = fields[7]
        self.host = fields[8]
        self.needs_quorum = fields[9]
        self.flags = int(fields[10])
        self.flags_s = fields[11]

        if self.parent == "NA":
            self.parent = None

    def unique(self):
        if self.flags & int("0x00000020", 16):
            return 1

        return 0

    def orphan(self):
        if self.flags & int("0x00000001", 16):
            return 1

        return 0

    def managed(self):
        if self.flags & int("0x00000002", 16):
            return 1

        return 0


class AuditConstraint(object):
    def __init__(self, cm, line):
        fields = line.split()
        self.CM = cm
        self.line = line
        self.type = fields[1]
        self.id = fields[2]
        self.rsc = fields[3]
        self.target = fields[4]
        self.score = fields[5]
        self.rsc_role = fields[6]
        self.target_role = fields[7]

        if self.rsc_role == "NA":
            self.rsc_role = None

        if self.target_role == "NA":
            self.target_role = None


class PrimitiveAudit(ClusterAudit):
    def name(self):
        return "PrimitiveAudit"

    def __init__(self, cm):
        self.CM = cm

    def doResourceAudit(self, resource, quorum):
        rc = 1
        active = self.CM.ResourceLocation(resource.id)

        if len(active) == 1:
            if quorum:
                self.debug("Resource %s active on %s" % (resource.id, repr(active)))

            elif resource.needs_quorum == 1:
                self.CM.log("Resource %s active without quorum: %s"
                            % (resource.id, repr(active)))
                rc = 0

        elif not resource.managed():
            self.CM.log("Resource %s not managed. Active on %s"
                        % (resource.id, repr(active)))

        elif not resource.unique():
            # TODO: Figure out a clever way to actually audit these resource types
            if len(active) > 1:
                self.debug("Non-unique resource %s is active on: %s"
                              % (resource.id, repr(active)))
            else:
                self.debug("Non-unique resource %s is not active" % resource.id)

        elif len(active) > 1:
            self.CM.log("Resource %s is active multiple times: %s"
                        % (resource.id, repr(active)))
            rc = 0

        elif resource.orphan():
            self.debug("Resource %s is an inactive orphan" % resource.id)

        elif len(self.inactive_nodes) == 0:
            self.CM.log("WARN: Resource %s not served anywhere" % resource.id)
            rc = 0

        elif self.CM.Env["warn-inactive"]:
            if quorum or not resource.needs_quorum:
                self.CM.log("WARN: Resource %s not served anywhere (Inactive nodes: %s)"
                            % (resource.id, repr(self.inactive_nodes)))
            else:
                self.debug("Resource %s not served anywhere (Inactive nodes: %s)"
                              % (resource.id, repr(self.inactive_nodes)))

        elif quorum or not resource.needs_quorum:
            self.debug("Resource %s not served anywhere (Inactive nodes: %s)"
                          % (resource.id, repr(self.inactive_nodes)))

        return rc

    def setup(self):
        self.target = None
        self.resources = []
        self.constraints = []
        self.active_nodes = []
        self.inactive_nodes = []

        for node in self.CM.Env["nodes"]:
            if self.CM.ShouldBeStatus[node] == "up":
                self.active_nodes.append(node)
            else:
                self.inactive_nodes.append(node)

        for node in self.CM.Env["nodes"]:
            if self.target == None and self.CM.ShouldBeStatus[node] == "up":
                self.target = node

        if not self.target:
            # TODO: In Pacemaker 1.0 clusters we'll be able to run crm_resource
            # with CIB_file=/path/to/cib.xml even when the cluster isn't running
            self.debug("No nodes active - skipping %s" % self.name())
            return 0

        (_, lines) = self.CM.rsh(self.target, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                self.resources.append(AuditResource(self.CM, line))
            elif re.search("^Constraint", line):
                self.constraints.append(AuditConstraint(self.CM, line))
            else:
                self.CM.log("Unknown entry: %s" % line);

        return 1

    def __call__(self):
        rc = 1

        if not self.setup():
            return 1

        quorum = self.CM.HasQuorum(None)
        for resource in self.resources:
            if resource.type == "primitive":
                if self.doResourceAudit(resource, quorum) == 0:
                    rc = 0
        return rc

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self.CM["Name"] == "crm-corosync":
        #    return 1
        return 0


class GroupAudit(PrimitiveAudit):
    def name(self):
        return "GroupAudit"

    def __call__(self):
        rc = 1
        if not self.setup():
            return 1

        for group in self.resources:
            if group.type == "group":
                first_match = 1
                group_location = None

                for child in self.resources:
                    if child.parent == group.id:
                        nodes = self.CM.ResourceLocation(child.id)

                        if first_match and len(nodes) > 0:
                            group_location = nodes[0]

                        first_match = 0

                        if len(nodes) > 1:
                            rc = 0
                            self.CM.log("Child %s of %s is active more than once: %s"
                                        % (child.id, group.id, repr(nodes)))

                        elif len(nodes) == 0:
                            # Groups are allowed to be partially active
                            # However we do need to make sure later children aren't running
                            group_location = None
                            self.debug("Child %s of %s is stopped" % (child.id, group.id))

                        elif nodes[0] != group_location:
                            rc = 0
                            self.CM.log("Child %s of %s is active on the wrong node (%s) expected %s"
                                        % (child.id, group.id, nodes[0], group_location))
                        else:
                            self.debug("Child %s of %s is active on %s" % (child.id, group.id, nodes[0]))

        return rc


class CloneAudit(PrimitiveAudit):
    def name(self):
        return "CloneAudit"

    def __call__(self):
        rc = 1
        if not self.setup():
            return 1

        for clone in self.resources:
            if clone.type == "clone":
                for child in self.resources:
                    if child.parent == clone.id and child.type == "primitive":
                        self.debug("Checking child %s of %s..." % (child.id, clone.id))
                        # Check max and node_max
                        # Obtain with:
                        #    crm_resource -g clone_max --meta -r child.id
                        #    crm_resource -g clone_node_max --meta -r child.id

        return rc


class ColocationAudit(PrimitiveAudit):
    def name(self):
        return "ColocationAudit"

    def crm_location(self, resource):
        (rc, lines) = self.CM.rsh(self.target, "crm_resource -W -r %s -Q"%resource, verbose=1)
        hosts = []

        if rc == 0:
            for line in lines:
                fields = line.split()
                hosts.append(fields[0])

        return hosts

    def __call__(self):
        rc = 1
        if not self.setup():
            return 1

        for coloc in self.constraints:
            if coloc.type == "rsc_colocation":
                source = self.crm_location(coloc.rsc)
                target = self.crm_location(coloc.target)

                if len(source) == 0:
                    self.debug("Colocation audit (%s): %s not running" % (coloc.id, coloc.rsc))
                else:
                    for node in source:
                        if not node in target:
                            rc = 0
                            self.CM.log("Colocation audit (%s): %s running on %s (not in %s)"
                                        % (coloc.id, coloc.rsc, node, repr(target)))
                        else:
                            self.debug("Colocation audit (%s): %s running on %s (in %s)"
                                          % (coloc.id, coloc.rsc, node, repr(target)))

        return rc


class ControllerStateAudit(ClusterAudit):
    def __init__(self, cm):
        self.CM = cm
        self.Stats = {"calls":0
        ,        "success":0
        ,        "failure":0
        ,        "skipped":0
        ,        "auditfail":0}

    def has_key(self, key):
        return key in self.Stats

    def __setitem__(self, key, value):
        self.Stats[key] = value

    def __getitem__(self, key):
        return self.Stats[key]

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not name in self.Stats:
            self.Stats[name] = 0
        self.Stats[name] = self.Stats[name]+1

    def __call__(self):
        passed = 1
        up_are_down = 0
        down_are_up = 0
        unstable_list = []

        for node in self.CM.Env["nodes"]:
            should_be = self.CM.ShouldBeStatus[node]
            rc = self.CM.test_node_CM(node)

            if rc > 0:
                if should_be == "down":
                    down_are_up = down_are_up + 1

                if rc == 1:
                    unstable_list.append(node)

            elif should_be == "up":
                up_are_down = up_are_down + 1

        if len(unstable_list) > 0:
            passed = 0
            self.CM.log("Cluster is not stable: %d (of %d): %s"
                     % (len(unstable_list), self.CM.upcount(), repr(unstable_list)))

        if up_are_down > 0:
            passed = 0
            self.CM.log("%d (of %d) nodes expected to be up were down."
                     % (up_are_down, len(self.CM.Env["nodes"])))

        if down_are_up > 0:
            passed = 0
            self.CM.log("%d (of %d) nodes expected to be down were up."
                     % (down_are_up, len(self.CM.Env["nodes"])))

        return passed

    def name(self):
        return "ControllerStateAudit"

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self.CM["Name"] == "crm-corosync":
        #    return 1
        return 0


class CIBAudit(ClusterAudit):
    def __init__(self, cm):
        self.CM = cm
        self.Stats = {"calls":0
        ,        "success":0
        ,        "failure":0
        ,        "skipped":0
        ,        "auditfail":0}

    def has_key(self, key):
        return key in self.Stats

    def __setitem__(self, key, value):
        self.Stats[key] = value

    def __getitem__(self, key):
        return self.Stats[key]

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not name in self.Stats:
            self.Stats[name] = 0
        self.Stats[name] = self.Stats[name]+1

    def __call__(self):
        passed = 1
        ccm_partitions = self.CM.find_partitions()

        if len(ccm_partitions) == 0:
            self.debug("\tNo partitions to audit")
            return 1

        for partition in ccm_partitions:
            self.debug("\tAuditing CIB consistency for: %s" % partition)
            partition_passed = 0

            if self.audit_cib_contents(partition) == 0:
                passed = 0

        return passed

    def audit_cib_contents(self, hostlist):
        passed = 1
        node0 = None
        node0_xml = None

        partition_hosts = hostlist.split()
        for node in partition_hosts:
            node_xml = self.store_remote_cib(node, node0)

            if node_xml == None:
                self.CM.log("Could not perform audit: No configuration from %s" % node)
                passed = 0

            elif node0 == None:
                node0 = node
                node0_xml = node_xml

            elif node0_xml == None:
                self.CM.log("Could not perform audit: No configuration from %s" % node0)
                passed = 0

            else:
                (rc, result) = self.CM.rsh(
                    node0, "crm_diff -VV -cf --new %s --original %s" % (node_xml, node0_xml), verbose=1)

                if rc != 0:
                    self.CM.log("Diff between %s and %s failed: %d" % (node0_xml, node_xml, rc))
                    passed = 0

                for line in result:
                    if not re.search("<diff/>", line):
                        passed = 0
                        self.debug("CibDiff[%s-%s]: %s" % (node0, node, line))
                    else:
                        self.debug("CibDiff[%s-%s] Ignoring: %s" % (node0, node, line))

#            self.CM.rsh(node0, "rm -f %s" % node_xml)
#        self.CM.rsh(node0, "rm -f %s" % node0_xml)
        return passed

    def store_remote_cib(self, node, target):
        combined = ""
        filename = "/tmp/ctsaudit.%s.xml" % node

        if not target:
            target = node

        (rc, lines) = self.CM.rsh(node, self.CM["CibQuery"], verbose=1)
        if rc != 0:
            self.CM.log("Could not retrieve configuration")
            return None

        self.CM.rsh("localhost", "rm -f %s" % filename)
        for line in lines:
            self.CM.rsh("localhost", "echo \'%s\' >> %s" % (line[:-1], filename), verbose=0)

        if self.CM.rsh.copy(filename, "root@%s:%s" % (target, filename), silent=True) != 0:
            self.CM.log("Could not store configuration")
            return None

        return filename

    def name(self):
        return "CibAudit"

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self.CM["Name"] == "crm-corosync":
        #    return 1
        return 0


class PartitionAudit(ClusterAudit):
    def __init__(self, cm):
        self.CM = cm
        self.Stats = {"calls":0
        ,        "success":0
        ,        "failure":0
        ,        "skipped":0
        ,        "auditfail":0}
        self.NodeEpoch = {}
        self.NodeState = {}
        self.NodeQuorum = {}

    def has_key(self, key):
        return key in self.Stats

    def __setitem__(self, key, value):
        self.Stats[key] = value

    def __getitem__(self, key):
        return self.Stats[key]

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not name in self.Stats:
            self.Stats[name] = 0

        self.Stats[name] = self.Stats[name]+1

    def __call__(self):
        passed = 1
        ccm_partitions = self.CM.find_partitions()

        if ccm_partitions == None or len(ccm_partitions) == 0:
            return 1

        self.CM.cluster_stable(double_check=True)

        if len(ccm_partitions) != self.CM.partitions_expected:
            self.CM.log("ERROR: %d cluster partitions detected:" % len(ccm_partitions))
            passed = 0

            for partition in ccm_partitions:
                self.CM.log("\t %s" % partition)

        for partition in ccm_partitions:
            partition_passed = 0

            if self.audit_partition(partition) == 0:
                passed = 0

        return passed

    def trim_string(self, avalue):
        if not avalue:
            return None

        if len(avalue) > 1:
            return avalue[:-1]

    def trim2int(self, avalue):
        if not avalue:
            return None

        if len(avalue) > 1:
            return int(avalue[:-1])

    def audit_partition(self, partition):
        passed = 1
        dc_found = []
        dc_allowed_list = []
        lowest_epoch = None
        node_list = partition.split()

        self.debug("Auditing partition: %s" % (partition))
        for node in node_list:
            if self.CM.ShouldBeStatus[node] != "up":
                self.CM.log("Warn: Node %s appeared out of nowhere" % (node))
                self.CM.ShouldBeStatus[node] = "up"
                # not in itself a reason to fail the audit (not what we're
                #  checking for in this audit)

            (_, out) = self.CM.rsh(node, self.CM["StatusCmd"] % node, verbose=1)
            self.NodeState[node] = out[0].strip()

            (_, out) = self.CM.rsh(node, self.CM["EpochCmd"], verbose=1)
            self.NodeEpoch[node] = out[0].strip()

            (_, out) = self.CM.rsh(node, self.CM["QuorumCmd"], verbose=1)
            self.NodeQuorum[node] = out[0].strip()

            self.debug("Node %s: %s - %s - %s." % (node, self.NodeState[node], self.NodeEpoch[node], self.NodeQuorum[node]))
            self.NodeState[node]  = self.trim_string(self.NodeState[node])
            self.NodeEpoch[node] = self.trim2int(self.NodeEpoch[node])
            self.NodeQuorum[node] = self.trim_string(self.NodeQuorum[node])

            if not self.NodeEpoch[node]:
                self.CM.log("Warn: Node %s dissappeared: cant determin epoch" % (node))
                self.CM.ShouldBeStatus[node] = "down"
                # not in itself a reason to fail the audit (not what we're
                #  checking for in this audit)
            elif lowest_epoch == None or self.NodeEpoch[node] < lowest_epoch:
                lowest_epoch = self.NodeEpoch[node]

        if not lowest_epoch:
            self.CM.log("Lowest epoch not determined in %s" % (partition))
            passed = 0

        for node in node_list:
            if self.CM.ShouldBeStatus[node] == "up":
                if self.CM.is_node_dc(node, self.NodeState[node]):
                    dc_found.append(node)
                    if self.NodeEpoch[node] == lowest_epoch:
                        self.debug("%s: OK" % node)
                    elif not self.NodeEpoch[node]:
                        self.debug("Check on %s ignored: no node epoch" % node)
                    elif not lowest_epoch:
                        self.debug("Check on %s ignored: no lowest epoch" % node)
                    else:
                        self.CM.log("DC %s is not the oldest node (%d vs. %d)"
                            % (node, self.NodeEpoch[node], lowest_epoch))
                        passed = 0

        if len(dc_found) == 0:
            self.CM.log("DC not found on any of the %d allowed nodes: %s (of %s)"
                        % (len(dc_allowed_list), str(dc_allowed_list), str(node_list)))

        elif len(dc_found) > 1:
            self.CM.log("%d DCs (%s) found in cluster partition: %s"
                        % (len(dc_found), str(dc_found), str(node_list)))
            passed = 0

        if passed == 0:
            for node in node_list:
                if self.CM.ShouldBeStatus[node] == "up":
                    self.CM.log("epoch %s : %s"
                                % (self.NodeEpoch[node], self.NodeState[node]))

        return passed

    def name(self):
        return "PartitionAudit"

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self.CM["Name"] == "crm-corosync":
        #    return 1
        return 0

AllAuditClasses.append(DiskAudit)
AllAuditClasses.append(FileAudit)
AllAuditClasses.append(LogAudit)
AllAuditClasses.append(ControllerStateAudit)
AllAuditClasses.append(PartitionAudit)
AllAuditClasses.append(PrimitiveAudit)
AllAuditClasses.append(GroupAudit)
AllAuditClasses.append(CloneAudit)
AllAuditClasses.append(ColocationAudit)
AllAuditClasses.append(CIBAudit)


def AuditList(cm):
    result = []

    for auditclass in AllAuditClasses:
        a = auditclass(cm)
        if a.is_applicable():
            result.append(a)

    return result
