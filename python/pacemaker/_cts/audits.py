""" Auditing classes for Pacemaker's Cluster Test Suite (CTS) """

__all__ = ["AuditConstraint", "AuditResource", "ClusterAudit", "audit_list"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import time
import uuid

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.input import should_continue
from pacemaker._cts.watcher import LogKind, LogWatcher


class ClusterAudit:
    """ The base class for various kinds of auditors.  Specific audit implementations
        should be built on top of this one.  Audits can do all kinds of checks on the
        system.  The basic interface for callers is the `__call__` method, which
        returns True if the audit passes and False if it fails.
    """

    def __init__(self, cm):
        """ Create a new ClusterAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        # pylint: disable=invalid-name
        self._cm = cm
        self.name = None

    def __call__(self):
        raise NotImplementedError

    def is_applicable(self):
        """ Return True if this audit is applicable in the current test configuration.
            This method must be implemented by all subclasses.
        """

        raise NotImplementedError

    def log(self, args):
        """ Log a message """

        self._cm.log("audit: %s" % args)

    def debug(self, args):
        """ Log a debug message """

        self._cm.debug("audit: %s" % args)


class LogAudit(ClusterAudit):
    """ Audit each cluster node to verify that some logging system is usable.
        This is done by logging a unique test message and then verifying that
        we can read back that test message using logging tools.
    """

    def __init__(self, cm):
        """ Create a new LogAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "LogAudit"

    def _restart_cluster_logging(self, nodes=None):
        """ Restart logging on the given nodes, or all if none are given """

        if not nodes:
            nodes = self._cm.Env["nodes"]

        self._cm.debug("Restarting logging on: %r" % nodes)

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
        """ Create a new LogWatcher instance for the given patterns """

        watch = LogWatcher(self._cm.Env["LogFileName"], patterns,
                           self._cm.Env["nodes"], kind, "LogAudit", 5,
                           silent=True)
        watch.set_watch()
        return watch

    def _test_logging(self):
        """ Perform the log audit """

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

        return False

    def __call__(self):
        max_attempts = 3
        attempt = 0

        self._cm.ns.wait_for_all_nodes(self._cm.Env["nodes"])
        while attempt <= max_attempts and not self._test_logging():
            attempt += 1
            self._restart_cluster_logging()
            time.sleep(60*attempt)

        if attempt > max_attempts:
            self._cm.log("ERROR: Cluster logging unrecoverable.")
            return False

        return True

    def is_applicable(self):
        """ Return True if this audit is applicable in the current test configuration. """

        if self._cm.Env["DoBSC"] or self._cm.Env["LogAuditDisabled"]:
            return False

        return True


class DiskAudit(ClusterAudit):
    """ Audit disk usage on cluster nodes to verify that there is enough free
        space left on whichever mounted file system holds the logs.

        Warn on:  less than 100 MB or 10% of free space
        Error on: less than 10 MB or 5% of free space
    """

    def __init__(self, cm):
        """ Create a new DiskAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "DiskspaceAudit"

    def __call__(self):
        result = True

        # @TODO Use directory of PCMK_logfile if set on host
        dfcmd = "df -BM %s | tail -1 | awk '{print $(NF-1)\" \"$(NF-2)}' | tr -d 'M%%'" % BuildOptions.LOG_DIR

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

                    if not should_continue(self._cm.Env):
                        raise ValueError("Disk full on %s" % node)

                elif remaining_mb < 100 or used_percent > 90:
                    self._cm.log("WARN: Low on log disk space (%dMB) on %s" % (remaining_mb, node))

        return result

    def is_applicable(self):
        """ Return True if this audit is applicable in the current test configuration. """

        return not self._cm.Env["DoBSC"]


class FileAudit(ClusterAudit):
    """ Audit the filesystem looking for various failure conditions:

        * The presence of core dumps from corosync or Pacemaker daemons
        * Stale IPC files
    """

    def __init__(self, cm):
        """ Create a new FileAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

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

            if self._cm.ShouldBeStatus.get(node) == "down":
                clean = False
                (_, lsout) = self._cm.rsh(node, "ls -al /dev/shm | grep qb-", verbose=1)

                for line in lsout:
                    result = False
                    clean = True
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
        """ Return True if this audit is applicable in the current test configuration. """

        return True


class AuditResource:
    """ A base class for storing information about a cluster resource """

    def __init__(self, cm, line):
        """ Create a new AuditResource instance

            Arguments:

            cm   -- A ClusterManager instance
            line -- One line of output from `crm_resource` describing a single
                    resource
        """

        # pylint: disable=invalid-name
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
        """ Is this resource unique? """

        return self.flags & 0x20

    @property
    def orphan(self):
        """ Is this resource an orphan? """

        return self.flags & 0x01

    @property
    def managed(self):
        """ Is this resource managed by the cluster? """

        return self.flags & 0x02


class AuditConstraint:
    """ A base class for storing information about a cluster constraint """

    def __init__(self, cm, line):
        """ Create a new AuditConstraint instance

            Arguments:

            cm   -- A ClusterManager instance
            line -- One line of output from `crm_resource` describing a single
                    constraint
        """

        # pylint: disable=invalid-name
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
    """ Audit primitive resources to verify a variety of conditions, including that
        they are active and managed only when expected; they are active on the
        expected clusted node; and that they are not orphaned.
    """

    def __init__(self, cm):
        """ Create a new PrimitiveAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "PrimitiveAudit"

        self._active_nodes = []
        self._constraints = []
        self._inactive_nodes = []
        self._resources = []
        self._target = None

    def _audit_resource(self, resource, quorum):
        """ Perform the audit of a single resource """

        rc = True
        active = self._cm.ResourceLocation(resource.id)

        if len(active) == 1:
            if quorum:
                self.debug("Resource %s active on %r" % (resource.id, active))

            elif resource.needs_quorum == 1:
                self._cm.log("Resource %s active without quorum: %r" % (resource.id, active))
                rc = False

        elif not resource.managed:
            self._cm.log("Resource %s not managed. Active on %r" % (resource.id, active))

        elif not resource.unique:
            # TODO: Figure out a clever way to actually audit these resource types
            if len(active) > 1:
                self.debug("Non-unique resource %s is active on: %r" % (resource.id, active))
            else:
                self.debug("Non-unique resource %s is not active" % resource.id)

        elif len(active) > 1:
            self._cm.log("Resource %s is active multiple times: %r" % (resource.id, active))
            rc = False

        elif resource.orphan:
            self.debug("Resource %s is an inactive orphan" % resource.id)

        elif not self._inactive_nodes:
            self._cm.log("WARN: Resource %s not served anywhere" % resource.id)
            rc = False

        elif self._cm.Env["warn-inactive"]:
            if quorum or not resource.needs_quorum:
                self._cm.log("WARN: Resource %s not served anywhere (Inactive nodes: %r)"
                            % (resource.id, self._inactive_nodes))
            else:
                self.debug("Resource %s not served anywhere (Inactive nodes: %r)"
                              % (resource.id, self._inactive_nodes))

        elif quorum or not resource.needs_quorum:
            self.debug("Resource %s not served anywhere (Inactive nodes: %r)"
                          % (resource.id, self._inactive_nodes))

        return rc

    def _setup(self):
        """ Verify cluster nodes are active, and collect resource and colocation
            information used for performing the audit.
        """

        for node in self._cm.Env["nodes"]:
            if self._cm.ShouldBeStatus[node] == "up":
                self._active_nodes.append(node)
            else:
                self._inactive_nodes.append(node)

        for node in self._cm.Env["nodes"]:
            if self._target is None and self._cm.ShouldBeStatus[node] == "up":
                self._target = node

        if not self._target:
            # TODO: In Pacemaker 1.0 clusters we'll be able to run crm_resource
            # with CIB_file=/path/to/cib.xml even when the cluster isn't running
            self.debug("No nodes active - skipping %s" % self.name)
            return False

        (_, lines) = self._cm.rsh(self._target, "crm_resource -c", verbose=1)

        for line in lines:
            if re.search("^Resource", line):
                self._resources.append(AuditResource(self._cm, line))
            elif re.search("^Constraint", line):
                self._constraints.append(AuditConstraint(self._cm, line))
            else:
                self._cm.log("Unknown entry: %s" % line)

        return True

    def __call__(self):
        result = True

        if not self._setup():
            return result

        quorum = self._cm.HasQuorum(None)
        for resource in self._resources:
            if resource.type == "primitive" and not self._audit_resource(resource, quorum):
                result = False

        return result

    def is_applicable(self):
        """ Return True if this audit is applicable in the current test configuration. """

        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class GroupAudit(PrimitiveAudit):
    """ Audit group resources to verify that each of its child primitive
        resources is active on the expected cluster node.
    """

    def __init__(self, cm):
        """ Create a new GroupAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        PrimitiveAudit.__init__(self, cm)
        self.name = "GroupAudit"

    def __call__(self):
        result = True

        if not self._setup():
            return result

        for group in self._resources:
            if group.type != "group":
                continue

            first_match = True
            group_location = None

            for child in self._resources:
                if child.parent != group.id:
                    continue

                nodes = self._cm.ResourceLocation(child.id)

                if first_match and len(nodes) > 0:
                    group_location = nodes[0]

                first_match = False

                if len(nodes) > 1:
                    result = False
                    self._cm.log("Child %s of %s is active more than once: %r"
                                % (child.id, group.id, nodes))

                elif not nodes:
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
    """ Audit clone resources.  NOTE: Currently, this class does not perform
        any actual audit functions.
    """

    def __init__(self, cm):
        """ Create a new CloneAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        PrimitiveAudit.__init__(self, cm)
        self.name = "CloneAudit"

    def __call__(self):
        result = True

        if not self._setup():
            return result

        for clone in self._resources:
            if clone.type != "clone":
                continue

            for child in self._resources:
                if child.parent == clone.id and child.type == "primitive":
                    self.debug("Checking child %s of %s..." % (child.id, clone.id))
                    # Check max and node_max
                    # Obtain with:
                    #    crm_resource -g clone_max --meta -r child.id
                    #    crm_resource -g clone_node_max --meta -r child.id

        return result


class ColocationAudit(PrimitiveAudit):
    """ Audit cluster resources to verify that those that should be colocated
        with each other actually are.
    """

    def __init__(self, cm):
        """ Create a new ColocationAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        PrimitiveAudit.__init__(self, cm)
        self.name = "ColocationAudit"

    def _crm_location(self, resource):
        """ Return a list of cluster nodes where a given resource is running """

        (rc, lines) = self._cm.rsh(self._target, "crm_resource -W -r %s -Q" % resource, verbose=1)
        hosts = []

        if rc == 0:
            for line in lines:
                fields = line.split()
                hosts.append(fields[0])

        return hosts

    def __call__(self):
        result = True

        if not self._setup():
            return result

        for coloc in self._constraints:
            if coloc.type != "rsc_colocation":
                continue

            source = self._crm_location(coloc.rsc)
            target = self._crm_location(coloc.target)

            if not source:
                self.debug("Colocation audit (%s): %s not running" % (coloc.id, coloc.rsc))
            else:
                for node in source:
                    if not node in target:
                        result = False
                        self._cm.log("Colocation audit (%s): %s running on %s (not in %r)"
                                    % (coloc.id, coloc.rsc, node, target))
                    else:
                        self.debug("Colocation audit (%s): %s running on %s (in %r)"
                                      % (coloc.id, coloc.rsc, node, target))

        return result


class ControllerStateAudit(ClusterAudit):
    """ Audit cluster nodes to verify that those we expect to be active are
        active, and those that are expected to be inactive are inactive.
    """

    def __init__(self, cm):
        """ Create a new ControllerStateAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "ControllerStateAudit"

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
            self._cm.log("Cluster is not stable: %d (of %d): %r"
                     % (len(unstable_list), self._cm.upcount(), unstable_list))

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
        """ Return True if this audit is applicable in the current test configuration. """

        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class CIBAudit(ClusterAudit):
    """ Audit the CIB by verifying that it is identical across cluster nodes """

    def __init__(self, cm):
        """ Create a new CIBAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "CibAudit"

    def __call__(self):
        result = True
        ccm_partitions = self._cm.find_partitions()

        if not ccm_partitions:
            self.debug("\tNo partitions to audit")
            return result

        for partition in ccm_partitions:
            self.debug("\tAuditing CIB consistency for: %s" % partition)

            if self._audit_cib_contents(partition) == 0:
                result = False

        return result

    def _audit_cib_contents(self, hostlist):
        """ Perform the CIB audit on the given hosts """

        passed = True
        node0 = None
        node0_xml = None

        partition_hosts = hostlist.split()
        for node in partition_hosts:
            node_xml = self._store_remote_cib(node, node0)

            if node_xml is None:
                self._cm.log("Could not perform audit: No configuration from %s" % node)
                passed = False

            elif node0 is None:
                node0 = node
                node0_xml = node_xml

            elif node0_xml is None:
                self._cm.log("Could not perform audit: No configuration from %s" % node0)
                passed = False

            else:
                (rc, result) = self._cm.rsh(
                    node0, "crm_diff -VV -cf --new %s --original %s" % (node_xml, node0_xml), verbose=1)

                if rc != 0:
                    self._cm.log("Diff between %s and %s failed: %d" % (node0_xml, node_xml, rc))
                    passed = False

                for line in result:
                    if not re.search("<diff/>", line):
                        passed = False
                        self.debug("CibDiff[%s-%s]: %s" % (node0, node, line))
                    else:
                        self.debug("CibDiff[%s-%s] Ignoring: %s" % (node0, node, line))

        return passed

    def _store_remote_cib(self, node, target):
        """ Store a copy of the given node's CIB on the given target node.  If
            no target is given, store the CIB on the given node.
        """

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
        """ Return True if this audit is applicable in the current test configuration. """

        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


class PartitionAudit(ClusterAudit):
    """ Audit each partition in a cluster to verify a variety of conditions:

        * The number of partitions and the nodes in each is as expected
        * Each node is active when it should be active and inactive when it
          should be inactive
        * The status and epoch of each node is as expected
        * A partition has quorum
        * A partition has a DC when expected
    """

    def __init__(self, cm):
        """ Create a new PartitionAudit instance

            Arguments:

            cm -- A ClusterManager instance
        """

        ClusterAudit.__init__(self, cm)
        self.name = "PartitionAudit"

        self._node_epoch = {}
        self._node_state = {}
        self._node_quorum = {}

    def __call__(self):
        result = True
        ccm_partitions = self._cm.find_partitions()

        if not ccm_partitions:
            return result

        self._cm.cluster_stable(double_check=True)

        if len(ccm_partitions) != self._cm.partitions_expected:
            self._cm.log("ERROR: %d cluster partitions detected:" % len(ccm_partitions))
            result = False

            for partition in ccm_partitions:
                self._cm.log("\t %s" % partition)

        for partition in ccm_partitions:
            if self._audit_partition(partition) == 0:
                result = False

        return result

    def _trim_string(self, avalue):
        """ Remove the last character from a multi-character string """

        if not avalue:
            return None

        if len(avalue) > 1:
            return avalue[:-1]

        return avalue

    def _trim2int(self, avalue):
        """ Remove the last character from a multi-character string and convert
            the result to an int.
        """

        trimmed = self._trim_string(avalue)
        if trimmed:
            return int(trimmed)

        return None

    def _audit_partition(self, partition):
        """ Perform the audit of a single partition """

        passed = True
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
            self._node_state[node] = out[0].strip()

            (_, out) = self._cm.rsh(node, self._cm["EpochCmd"], verbose=1)
            self._node_epoch[node] = out[0].strip()

            (_, out) = self._cm.rsh(node, self._cm["QuorumCmd"], verbose=1)
            self._node_quorum[node] = out[0].strip()

            self.debug("Node %s: %s - %s - %s." % (node, self._node_state[node], self._node_epoch[node], self._node_quorum[node]))
            self._node_state[node]  = self._trim_string(self._node_state[node])
            self._node_epoch[node] = self._trim2int(self._node_epoch[node])
            self._node_quorum[node] = self._trim_string(self._node_quorum[node])

            if not self._node_epoch[node]:
                self._cm.log("Warn: Node %s dissappeared: cant determin epoch" % node)
                self._cm.ShouldBeStatus[node] = "down"
                # not in itself a reason to fail the audit (not what we're
                #  checking for in this audit)
            elif lowest_epoch is None or self._node_epoch[node] < lowest_epoch:
                lowest_epoch = self._node_epoch[node]

        if not lowest_epoch:
            self._cm.log("Lowest epoch not determined in %s" % partition)
            passed = False

        for node in node_list:
            if self._cm.ShouldBeStatus[node] != "up":
                continue

            if self._cm.is_node_dc(node, self._node_state[node]):
                dc_found.append(node)
                if self._node_epoch[node] == lowest_epoch:
                    self.debug("%s: OK" % node)
                elif not self._node_epoch[node]:
                    self.debug("Check on %s ignored: no node epoch" % node)
                elif not lowest_epoch:
                    self.debug("Check on %s ignored: no lowest epoch" % node)
                else:
                    self._cm.log("DC %s is not the oldest node (%d vs. %d)"
                        % (node, self._node_epoch[node], lowest_epoch))
                    passed = False

        if not dc_found:
            self._cm.log("DC not found on any of the %d allowed nodes: %s (of %s)"
                        % (len(dc_allowed_list), str(dc_allowed_list), str(node_list)))

        elif len(dc_found) > 1:
            self._cm.log("%d DCs (%s) found in cluster partition: %s"
                        % (len(dc_found), str(dc_found), str(node_list)))
            passed = False

        if not passed:
            for node in node_list:
                if self._cm.ShouldBeStatus[node] == "up":
                    self._cm.log("epoch %s : %s"
                                % (self._node_epoch[node], self._node_state[node]))

        return passed

    def is_applicable(self):
        """ Return True if this audit is applicable in the current test configuration. """

        # @TODO Due to long-ago refactoring, this name test would never match,
        # so this audit (and those derived from it) would never run.
        # Uncommenting the next lines fixes the name test, but that then
        # exposes pre-existing bugs that need to be fixed.
        #if self._cm["Name"] == "crm-corosync":
        #    return True
        return False


# pylint: disable=invalid-name
def audit_list(cm):
    """ Return a list of instances of applicable audits that can be performed
        for the given ClusterManager.
    """

    result = []

    for auditclass in [DiskAudit, FileAudit, LogAudit, ControllerStateAudit,
                       PartitionAudit, PrimitiveAudit, GroupAudit, CloneAudit,
                       ColocationAudit, CIBAudit]:
        a = auditclass(cm)
        if a.is_applicable():
            result.append(a)

    return result
