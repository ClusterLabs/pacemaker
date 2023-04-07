""" Auditing classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import time
import uuid

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.watcher import LogKind, LogWatcher


class ClusterAudit:
    def __init__(self, cm):
        self._cm = cm
        self.name = None

    def __call__(self):
        raise NotImplementedError

    def is_applicable(self):
        """ Return True if this class is applicable in the current test configuration """

        raise NotImplementedError

    def log(self, args):
        self._cm.log("audit: %s" % args)

    def debug(self, args):
        self._cm.debug("audit: %s" % args)


class LogAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "LogAudit"

    def _restart_cluster_logging(self, nodes=None):
        if not nodes:
            nodes = self._cm.Env["nodes"]

        self._cm.debug("Restarting logging on: %s" % repr(nodes))

        for node in nodes:
            if self._cm.Env["have_systemd"]:
                (rc, _) = self._cm.rsh(node, "systemctl stop systemd-journald.socket")
                if rc != 0:
                    self._cm.log ("ERROR: Cannot stop 'systemd-journald' on %s" % node)

                (rc, _) = self._cm.rsh(node, "systemctl start systemd-journald.service")
                if rc != 0:
                    self._cm.log ("ERROR: Cannot start 'systemd-journald' on %s" % node)

            (rc, _) = self._cm.rsh(node, "service %s restart" % self._cm.Env["syslogd"])
            if rc != 0:
                self._cm.log ("ERROR: Cannot restart '%s' on %s" % (self._cm.Env["syslogd"], node))

    def _create_watcher(self, patterns, kind):
        watch = LogWatcher(self._cm.Env["LogFileName"], patterns,
                           self._cm.Env["nodes"], kind, "LogAudit", 5,
                           silent=True)
        watch.set_watch()
        return watch

    def TestLogging(self):
        patterns = []
        prefix   = "Test message from"
        suffix   = str(uuid.uuid4())
        watch    = {}

        for node in self._cm.Env["nodes"]:
            # Look for the node name in two places to make sure
            # that syslog is logging with the correct hostname
            m = re.search("^([^.]+).*", node)
            if m:
                simple = m.group(1)
            else:
                simple = node

            patterns.append("%s.*%s %s %s" % (simple, prefix, node, suffix))

        watch_pref = self._cm.Env["LogWatcher"]
        if watch_pref == LogKind.ANY:
            kinds = [ LogKind.FILE ]
            if self._cm.Env["have_systemd"]:
                kinds +=  [ LogKind.JOURNAL ]
            kinds += [ LogKind.REMOTE_FILE ]
            for k in kinds:
                watch[k] = self._create_watcher(patterns, k)
            self._cm.log("Logging test message with identifier %s" % suffix)
        else:
            watch[watch_pref] = self._create_watcher(patterns, watch_pref)

        for node in self._cm.Env["nodes"]:
            cmd = "logger -p %s.info %s %s %s" % (self._cm.Env["SyslogFacility"], prefix, node, suffix)

            (rc, _) = self._cm.rsh(node, cmd, synchronous=False, verbose=0)
            if rc != 0:
                self._cm.log ("ERROR: Cannot execute remote command [%s] on %s" % (cmd, node))

        for k in list(watch.keys()):
            w = watch[k]
            if watch_pref == LogKind.ANY:
                self._cm.log("Checking for test message in %s logs" % k)
            w.look_for_all(silent=True)
            if w.unmatched:
                for regex in w.unmatched:
                    self._cm.log("Test message [%s] not found in %s logs" % (regex, w.kind))
            else:
                if watch_pref == LogKind.ANY:
                    self._cm.log("Found test message in %s logs" % k)
                    self._cm.Env["LogWatcher"] = k
                return 1

        return 0

    def __call__(self):
        max_attempts = 3
        attempt = 0

        self._cm.ns.wait_for_all_nodes(self._cm.Env["nodes"])
        while attempt <= max_attempts and self.TestLogging() == 0:
            attempt += 1
            self._restart_cluster_logging()
            time.sleep(60*attempt)

        if attempt > max_attempts:
            self._cm.log("ERROR: Cluster logging unrecoverable.")
            return False

        return True

    def is_applicable(self):
        if self._cm.Env["DoBSC"] or self._cm.Env["LogAuditDisabled"]:
            return False

        return True


class DiskAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "DiskspaceAudit"

    def __call__(self):
        result = True

        # @TODO Use directory of PCMK_logfile if set on host
        dfcmd = "df -BM " + BuildOptions.LOG_DIR + " | tail -1 | awk '{print $(NF-1)\" \"$(NF-2)}' | tr -d 'M%'"

        self._cm.ns.wait_for_all_nodes(self._cm.Env["nodes"])
        for node in self._cm.Env["nodes"]:
            (_, dfout) = self._cm.rsh(node, dfcmd, verbose=1)
            if not dfout:
                self._cm.log ("ERROR: Cannot execute remote df command [%s] on %s" % (dfcmd, node))
                continue

            dfout = dfout[0].strip()

            try:
                (used, remain) = dfout.split()
                used_percent = int(used)
                remaining_mb = int(remain)
            except (ValueError, TypeError):
                self._cm.log("Warning: df output '%s' from %s was invalid [%s, %s]"
                            % (dfout, node, used, remain))
            else:
                if remaining_mb < 10 or used_percent > 95:
                    self._cm.log("CRIT: Out of log disk space on %s (%d%% / %dMB)"
                                % (node, used_percent, remaining_mb))
                    result = False

                    if self._cm.Env["continue"]:
                        answer = "Y"
                    else:
                        try:
                            answer = input('Continue? [nY]')
                        except EOFError:
                            answer = "n"

                    if answer and answer == "n":
                        raise ValueError("Disk full on %s" % node)

                elif remaining_mb < 100 or used_percent > 90:
                    self._cm.log("WARN: Low on log disk space (%dMB) on %s" % (remaining_mb, node))

        return result

    def is_applicable(self):
        return not self._cm.Env["DoBSC"]


class FileAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.known = []
        self.name = "FileAudit"

    def __call__(self):
        result = True

        self._cm.ns.wait_for_all_nodes(self._cm.Env["nodes"])
        for node in self._cm.Env["nodes"]:

            (_, lsout) = self._cm.rsh(node, "ls -al /var/lib/pacemaker/cores/* | grep core.[0-9]", verbose=1)
            for line in lsout:
                line = line.strip()

                if line not in self.known:
                    result = False
                    self.known.append(line)
                    self._cm.log("Warning: Pacemaker core file on %s: %s" % (node, line))

            (_, lsout) = self._cm.rsh(node, "ls -al /var/lib/corosync | grep core.[0-9]", verbose=1)
            for line in lsout:
                line = line.strip()

                if line not in self.known:
                    result = False
                    self.known.append(line)
                    self._cm.log("Warning: Corosync core file on %s: %s" % (node, line))

            if node in self._cm.ShouldBeStatus and self._cm.ShouldBeStatus[node] == "down":
                clean = 0
                (_, lsout) = self._cm.rsh(node, "ls -al /dev/shm | grep qb-", verbose=1)

                for line in lsout:
                    result = False
                    clean = 1
                    self._cm.log("Warning: Stale IPC file on %s: %s" % (node, line))

                if clean:
                    (_, lsout) = self._cm.rsh(node, "ps axf | grep -e pacemaker -e corosync", verbose=1)

                    for line in lsout:
                        self._cm.debug("ps[%s]: %s" % (node, line))

                    self._cm.rsh(node, "rm -rf /dev/shm/qb-*")

            else:
                self._cm.debug("Skipping %s" % node)

        return result

    def is_applicable(self):
        return True


class AuditResource:
    def __init__(self, cm, line):
        fields = line.split()
        self._cm = cm
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

    @property
    def unique(self):
        return self.flags & 0x20

    @property
    def orphan(self):
        return self.flags & 0x01

    @property
    def managed(self):
        return self.flags & 0x02


class AuditConstraint:
    def __init__(self, cm, line):
        fields = line.split()
        self._cm = cm
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
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "PrimitiveAudit"

    def _audit_resource(self, resource, quorum):
        rc = True
        active = self._cm.ResourceLocation(resource.id)

        if len(active) == 1:
            if quorum:
                self.debug("Resource %s active on %s" % (resource.id, repr(active)))

            elif resource.needs_quorum == 1:
                self._cm.log("Resource %s active without quorum: %s"
                            % (resource.id, repr(active)))
                rc = False

        elif not resource.managed:
            self._cm.log("Resource %s not managed. Active on %s"
                        % (resource.id, repr(active)))

        elif not resource.unique:
            # TODO: Figure out a clever way to actually audit these resource types
            if len(active) > 1:
                self.debug("Non-unique resource %s is active on: %s"
                              % (resource.id, repr(active)))
            else:
                self.debug("Non-unique resource %s is not active" % resource.id)

        elif len(active) > 1:
            self._cm.log("Resource %s is active multiple times: %s"
                        % (resource.id, repr(active)))
            rc = False

        elif resource.orphan:
            self.debug("Resource %s is an inactive orphan" % resource.id)

        elif len(self.inactive_nodes) == 0:
            self._cm.log("WARN: Resource %s not served anywhere" % resource.id)
            rc = False

        elif self._cm.Env["warn-inactive"]:
            if quorum or not resource.needs_quorum:
                self._cm.log("WARN: Resource %s not served anywhere (Inactive nodes: %s)"
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

        for node in self._cm.Env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self.active_nodes.append(node)
            else:
                self.inactive_nodes.append(node)

        for node in self._cm.Env["nodes"]:
            if self.target == None and self._cm.ShouldBeStatus[node] == "up":
                self.target = node

        if not self.target:
            # TODO: In Pacemaker 1.0 clusters we'll be able to run crm_resource
            # with CIB_file=/path/to/cib.xml even when the cluster isn't running
            self.debug("No nodes active - skipping %s" % self.name)
            return 0

        (_, lines) = self._cm.rsh(self.target, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                self.resources.append(AuditResource(self._cm, line))
            elif re.search("^Constraint", line):
                self.constraints.append(AuditConstraint(self._cm, line))
            else:
                self._cm.log("Unknown entry: %s" % line)

        return 1

    def __call__(self):
        result = True

        if not self.setup():
            return result

        quorum = self._cm.HasQuorum(None)
        for resource in self.resources:
            if resource.type == "primitive" and not self._audit_resource(resource, quorum):
                result = False

        return result

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class GroupAudit(PrimitiveAudit):
    def __init__(self, cm):
        PrimitiveAudit.__init__(self, cm)
        self.name = "GroupAudit"

    def __call__(self):
        result = True

        if not self.setup():
            return result

        for group in self.resources:
            if group.type != "group":
                continue

            first_match = 1
            group_location = None

            for child in self.resources:
                if child.parent != group.id:
                    continue

                nodes = self._cm.ResourceLocation(child.id)

                if first_match and len(nodes) > 0:
                    group_location = nodes[0]

                first_match = 0

                if len(nodes) > 1:
                    result = False
                    self._cm.log("Child %s of %s is active more than once: %s"
                                % (child.id, group.id, repr(nodes)))

                elif len(nodes) == 0:
                    # Groups are allowed to be partially active
                    # However we do need to make sure later children aren't running
                    group_location = None
                    self.debug("Child %s of %s is stopped" % (child.id, group.id))

                elif nodes[0] != group_location:
                    result = False
                    self._cm.log("Child %s of %s is active on the wrong node (%s) expected %s"
                                % (child.id, group.id, nodes[0], group_location))
                else:
                    self.debug("Child %s of %s is active on %s" % (child.id, group.id, nodes[0]))

        return result


class CloneAudit(PrimitiveAudit):
    def __init__(self, cm):
        PrimitiveAudit.__init__(self, cm)
        self.name = "CloneAudit"

    def __call__(self):
        result = True

        if not self.setup():
            return result

        for clone in self.resources:
            if clone.type != "clone":
                continue

            for child in self.resources:
                if child.parent == clone.id and child.type == "primitive":
                    self.debug("Checking child %s of %s..." % (child.id, clone.id))
                    # Check max and node_max
                    # Obtain with:
                    #    crm_resource -g clone_max --meta -r child.id
                    #    crm_resource -g clone_node_max --meta -r child.id

        return result


class ColocationAudit(PrimitiveAudit):
    def __init__(self, cm):
        PrimitiveAudit.__init__(self, cm)
        self.name = "ColocationAudit"

    def crm_location(self, resource):
        (rc, lines) = self._cm.rsh(self.target, "crm_resource -W -r %s -Q" % resource, verbose=1)
        hosts = []

        if rc == 0:
            for line in lines:
                fields = line.split()
                hosts.append(fields[0])

        return hosts

    def __call__(self):
        result = True

        if not self.setup():
            return result

        for coloc in self.constraints:
            if coloc.type != "rsc_colocation":
                continue

            source = self.crm_location(coloc.rsc)
            target = self.crm_location(coloc.target)

            if len(source) == 0:
                self.debug("Colocation audit (%s): %s not running" % (coloc.id, coloc.rsc))
            else:
                for node in source:
                    if not node in target:
                        result = False
                        self._cm.log("Colocation audit (%s): %s running on %s (not in %s)"
                                    % (coloc.id, coloc.rsc, node, repr(target)))
                    else:
                        self.debug("Colocation audit (%s): %s running on %s (in %s)"
                                      % (coloc.id, coloc.rsc, node, repr(target)))

        return result


class ControllerStateAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "ControllerStateAudit"
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

        self.Stats[name] += 1

    def __call__(self):
        result = True
        up_are_down = 0
        down_are_up = 0
        unstable_list = []

        for node in self._cm.Env["nodes"]:
            should_be = self._cm.ShouldBeStatus[node]
            rc = self._cm.test_node_CM(node)

            if rc > 0:
                if should_be == "down":
                    down_are_up += 1

                if rc == 1:
                    unstable_list.append(node)

            elif should_be == "up":
                up_are_down += 1

        if len(unstable_list) > 0:
            result = False
            self._cm.log("Cluster is not stable: %d (of %d): %s"
                     % (len(unstable_list), self._cm.upcount(), repr(unstable_list)))

        if up_are_down > 0:
            result = False
            self._cm.log("%d (of %d) nodes expected to be up were down."
                     % (up_are_down, len(self._cm.Env["nodes"])))

        if down_are_up > 0:
            result = False
            self._cm.log("%d (of %d) nodes expected to be down were up."
                     % (down_are_up, len(self._cm.Env["nodes"])))

        return result

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class CIBAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "CibAudit"
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

        self.Stats[name] += 1

    def __call__(self):
        result = True
        ccm_partitions = self._cm.find_partitions()

        if len(ccm_partitions) == 0:
            self.debug("\tNo partitions to audit")
            return result

        for partition in ccm_partitions:
            self.debug("\tAuditing CIB consistency for: %s" % partition)

            if self.audit_cib_contents(partition) == 0:
                result = False

        return result

    def audit_cib_contents(self, hostlist):
        passed = 1
        node0 = None
        node0_xml = None

        partition_hosts = hostlist.split()
        for node in partition_hosts:
            node_xml = self.store_remote_cib(node, node0)

            if node_xml == None:
                self._cm.log("Could not perform audit: No configuration from %s" % node)
                passed = 0

            elif node0 == None:
                node0 = node
                node0_xml = node_xml

            elif node0_xml == None:
                self._cm.log("Could not perform audit: No configuration from %s" % node0)
                passed = 0

            else:
                (rc, result) = self._cm.rsh(
                    node0, "crm_diff -VV -cf --new %s --original %s" % (node_xml, node0_xml), verbose=1)

                if rc != 0:
                    self._cm.log("Diff between %s and %s failed: %d" % (node0_xml, node_xml, rc))
                    passed = 0

                for line in result:
                    if not re.search("<diff/>", line):
                        passed = 0
                        self.debug("CibDiff[%s-%s]: %s" % (node0, node, line))
                    else:
                        self.debug("CibDiff[%s-%s] Ignoring: %s" % (node0, node, line))

#            self._cm.rsh(node0, "rm -f %s" % node_xml)
#        self._cm.rsh(node0, "rm -f %s" % node0_xml)
        return passed

    def store_remote_cib(self, node, target):
        filename = "/tmp/ctsaudit.%s.xml" % node

        if not target:
            target = node

        (rc, lines) = self._cm.rsh(node, self._cm["CibQuery"], verbose=1)
        if rc != 0:
            self._cm.log("Could not retrieve configuration")
            return None

        self._cm.rsh("localhost", "rm -f %s" % filename)
        for line in lines:
            self._cm.rsh("localhost", "echo \'%s\' >> %s" % (line[:-1], filename), verbose=0)

        if self._cm.rsh.copy(filename, "root@%s:%s" % (target, filename), silent=True) != 0:
            self._cm.log("Could not store configuration")
            return None

        return filename

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class PartitionAudit(ClusterAudit):
    def __init__(self, cm):
        ClusterAudit.__init__(self, cm)
        self.name = "PartitionAudit"
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

        self.Stats[name] += 1

    def __call__(self):
        result = True
        ccm_partitions = self._cm.find_partitions()

        if ccm_partitions == None or len(ccm_partitions) == 0:
            return result

        self._cm.cluster_stable(double_check=True)

        if len(ccm_partitions) != self._cm.partitions_expected:
            self._cm.log("ERROR: %d cluster partitions detected:" % len(ccm_partitions))
            result = False

            for partition in ccm_partitions:
                self._cm.log("\t %s" % partition)

        for partition in ccm_partitions:
            if self.audit_partition(partition) == 0:
                result = False

        return result

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

        self.debug("Auditing partition: %s" % partition)
        for node in node_list:
            if self._cm.ShouldBeStatus[node] != "up":
                self._cm.log("Warn: Node %s appeared out of nowhere" % node)
                self._cm.ShouldBeStatus[node] = "up"
                # not in itself a reason to fail the audit (not what we're
                #  checking for in this audit)

            (_, out) = self._cm.rsh(node, self._cm["StatusCmd"] % node, verbose=1)
            self.NodeState[node] = out[0].strip()

            (_, out) = self._cm.rsh(node, self._cm["EpochCmd"], verbose=1)
            self.NodeEpoch[node] = out[0].strip()

            (_, out) = self._cm.rsh(node, self._cm["QuorumCmd"], verbose=1)
            self.NodeQuorum[node] = out[0].strip()

            self.debug("Node %s: %s - %s - %s." % (node, self.NodeState[node], self.NodeEpoch[node], self.NodeQuorum[node]))
            self.NodeState[node]  = self.trim_string(self.NodeState[node])
            self.NodeEpoch[node] = self.trim2int(self.NodeEpoch[node])
            self.NodeQuorum[node] = self.trim_string(self.NodeQuorum[node])

            if not self.NodeEpoch[node]:
                self._cm.log("Warn: Node %s dissappeared: cant determin epoch" % node)
                self._cm.ShouldBeStatus[node] = "down"
                # not in itself a reason to fail the audit (not what we're
                #  checking for in this audit)
            elif lowest_epoch == None or self.NodeEpoch[node] < lowest_epoch:
                lowest_epoch = self.NodeEpoch[node]

        if not lowest_epoch:
            self._cm.log("Lowest epoch not determined in %s" % partition)
            passed = 0

        for node in node_list:
            if self._cm.ShouldBeStatus[node] != "up":
                continue

            if self._cm.is_node_dc(node, self.NodeState[node]):
                dc_found.append(node)
                if self.NodeEpoch[node] == lowest_epoch:
                    self.debug("%s: OK" % node)
                elif not self.NodeEpoch[node]:
                    self.debug("Check on %s ignored: no node epoch" % node)
                elif not lowest_epoch:
                    self.debug("Check on %s ignored: no lowest epoch" % node)
                else:
                    self._cm.log("DC %s is not the oldest node (%d vs. %d)"
                        % (node, self.NodeEpoch[node], lowest_epoch))
                    passed = 0

        if len(dc_found) == 0:
            self._cm.log("DC not found on any of the %d allowed nodes: %s (of %s)"
                        % (len(dc_allowed_list), str(dc_allowed_list), str(node_list)))

        elif len(dc_found) > 1:
            self._cm.log("%d DCs (%s) found in cluster partition: %s"
                        % (len(dc_found), str(dc_found), str(node_list)))
            passed = 0

        if passed == 0:
            for node in node_list:
                if self._cm.ShouldBeStatus[node] == "up":
                    self._cm.log("epoch %s : %s"
                                % (self.NodeEpoch[node], self.NodeState[node]))

        return passed

    def is_applicable(self):
        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


def audit_list(cm):
    result = []

    for auditclass in [DiskAudit, FileAudit, LogAudit, ControllerStateAudit,
                       PartitionAudit, PrimitiveAudit, GroupAudit, CloneAudit,
                       ColocationAudit, CIBAudit]:
        a = auditclass(cm)
        if a.is_applicable():
            result.append(a)

    return result
