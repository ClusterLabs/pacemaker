""" Test environment classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["EnvFactory"]
__copyright__ = "Copyright 2014-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import argparse
import os
import random
import socket
import sys
import time

from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteFactory

class Environment:
    def __init__(self, args):
        self.data = {}
        self._nodes = []

        # Set some defaults before processing command line arguments.  These are
        # either not set by any command line parameter, or they need a default
        # that can't be set in add_argument.
        self["DeadTime"] = 300
        self["StartTime"] = 300
        self["StableTime"] = 30
        self["tests"] = []
        self["IPagent"] = "IPaddr2"
        self["DoFencing"] = True
        self["ClobberCIB"] = False
        self["CIBfilename"] = None
        self["CIBResource"] = False
        self["LogWatcher"] = "any"
        self["node-limit"] = 0
        self["scenario"] = "random"

        self.random_gen = random.Random()
        self.logger = LogFactory()

        self._seed_random()
        self.rsh = RemoteFactory().getInstance()

        self.target = "localhost"

        self.parse_args(args)
        if not self["ListTests"]:
            self.validate()
            self.discover()

    def _seed_random(self, seed=None):
        if not seed:
            seed = int(time.time())

        self["RandSeed"] = seed
        self.random_gen.seed(str(seed))

    def dump(self):
        keys = []
        for key in list(self.data.keys()):
            keys.append(key)

        keys.sort()
        for key in keys:
            self.logger.debug("Environment["+key+"]:\t"+str(self[key]))

    def keys(self):
        return list(self.data.keys())

    def has_key(self, key):
        if key == "nodes":
            return True

        return key in self.data

    def __getitem__(self, key):
        if str(key) == "0":
            raise ValueError("Bad call to 'foo in X', should reference 'foo in X.keys()' instead")

        if key == "nodes":
            return self._nodes

        if key == "Name":
            return self.get_stack_short()

        if key in self.data:
            return self.data[key]

        return None

    def __setitem__(self, key, value):
        if key == "Stack":
            self.set_stack(value)

        elif key == "node-limit":
            self.data[key] = value
            self.filter_nodes()

        elif key == "nodes":
            self._nodes = []
            for node in value:
                # I don't think I need the IP address, etc. but this validates
                # the node name against /etc/hosts and/or DNS, so it's a
                # GoodThing(tm).
                try:
                    n = node.strip()
                    socket.gethostbyname_ex(n)
                    self._nodes.append(n)
                except:
                    self.logger.log(node+" not found in DNS... aborting")
                    raise

            self.filter_nodes()

        else:
            self.data[key] = value

    def random_node(self):
        """ Choose a random node from the cluster """
        return self.random_gen.choice(self["nodes"])

    def set_stack(self, name):
        # Normalize stack names
        if name in ["corosync", "cs", "mcp"]:
            self.data["Stack"] = "corosync 2+"

        else:
            raise ValueError("Unknown stack: "+name)

    def get_stack_short(self):
        # Create the Cluster Manager object
        if "Stack" not in self.data:
            return "unknown"

        if self.data["Stack"] == "corosync 2+":
            return "crm-corosync"

        LogFactory().log("Unknown stack: "+self["stack"])
        raise ValueError("Unknown stack: "+self["stack"])

    def detect_syslog(self):
        # Detect syslog variant
        if "syslogd" not in self.data:
            if self["have_systemd"]:
                # Systemd
                (_, lines) = self.rsh(self.target, "systemctl list-units | grep syslog.*\.service.*active.*running | sed 's:.service.*::'", verbose=1)
                self["syslogd"] = lines[0].strip()
            else:
                # SYS-V
                (_, lines) = self.rsh(self.target, "chkconfig --list | grep syslog.*on | awk '{print $1}' | head -n 1", verbose=1)
                self["syslogd"] = lines[0].strip()

            if "syslogd" not in self.data or not self["syslogd"]:
                # default
                self["syslogd"] = "rsyslog"

    def disable_service(self, node, service):
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self.rsh(node, "systemctl disable %s" % service)
            return rc

        # SYS-V
        (rc, _) = self.rsh(node, "chkconfig %s off" % service)
        return rc

    def enable_service(self, node, service):
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self.rsh(node, "systemctl enable %s" % service)
            return rc

        # SYS-V
        (rc, _) = self.rsh(node, "chkconfig %s on" % service)
        return rc

    def service_is_enabled(self, node, service):
        if self["have_systemd"]:
            # Systemd

            # With "systemctl is-enabled", we should check if the service is
            # explicitly "enabled" instead of the return code. For example it returns
            # 0 if the service is "static" or "indirect", but they don't really count
            # as "enabled".
            (rc, _) = self.rsh(node, "systemctl is-enabled %s | grep enabled" % service)
            return rc == 0

        # SYS-V
        (rc, _) = self.rsh(node, "chkconfig --list | grep -e %s.*on" % service)
        return rc == 0

    def detect_at_boot(self):
        # Detect if the cluster starts at boot
        if "at-boot" not in self.data:
            self["at-boot"] = self.service_is_enabled(self.target, "corosync") \
                              or self.service_is_enabled(self.target, "pacemaker")

    def detect_ip_offset(self):
        # Try to determine an offset for IPaddr resources
        if self["CIBResource"] and "IPBase" not in self.data:
            (_, lines) = self.rsh(self.target, "ip addr | grep inet | grep -v -e link -e inet6 -e '/32' -e ' lo' | awk '{print $2}'", verbose=0)
            network = lines[0].strip()

            (_, lines) = self.rsh(self.target, "nmap -sn -n %s | grep 'scan report' | awk '{print $NF}' | sed 's:(::' | sed 's:)::' | sort -V | tail -n 1" % network, verbose=0)
            self["IPBase"] = lines[0].strip()

            if not self["IPBase"]:
                self["IPBase"] = " fe80::1234:56:7890:1000"
                self.logger.log("Could not determine an offset for IPaddr resources.  Perhaps nmap is not installed on the nodes.")
                self.logger.log("Defaulting to '%s', use --test-ip-base to override" % self["IPBase"])

            elif int(self["IPBase"].split('.')[3]) >= 240:
                self.logger.log("Could not determine an offset for IPaddr resources. Upper bound is too high: %s %s"
                                % (self["IPBase"], self["IPBase"].split('.')[3]))
                self["IPBase"] = " fe80::1234:56:7890:1000"
                self.logger.log("Defaulting to '%s', use --test-ip-base to override" % self["IPBase"])

    def filter_nodes(self):
        if self["node-limit"] > 0:
            if len(self["nodes"]) > self["node-limit"]:
                self.logger.log("Limiting the number of nodes configured=%d (max=%d)"
                                %(len(self["nodes"]), self["node-limit"]))

                while len(self["nodes"]) > self["node-limit"]:
                    self["nodes"].pop(len(self["nodes"])-1)

    def validate(self):
        if not self["nodes"]:
            print("No nodes specified!")
            sys.exit(1)

    def discover(self):
        self.target = random.Random().choice(self["nodes"])

        exerciser = socket.gethostname()

        # Use the IP where possible to avoid name lookup failures
        for ip in socket.gethostbyname_ex(exerciser)[2]:
            if ip != "127.0.0.1":
                exerciser = ip
                break

        self["cts-exerciser"] = exerciser

        if "have_systemd" not in self.data:
            (rc, _) = self.rsh(self.target, "systemctl list-units", verbose=0)
            self["have_systemd"] = rc == 0

        self.detect_syslog()
        self.detect_at_boot()
        self.detect_ip_offset()

    def parse_args(self, argv):
        if not argv:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser(epilog="%s -g virt1 -r --stonith ssh --schema pacemaker-2.0 500" % sys.argv[0])

        grp1 = parser.add_argument_group("Common options")
        grp1.add_argument("-g", "--dsh-group", "--group",
                          metavar="GROUP", dest="group",
                          help="Use the nodes listed in the named DSH group (~/.dsh/groups/$name)")
        grp1.add_argument("-l", "--limit-nodes",
                          type=int, default=0,
                          metavar="MAX",
                          help="Only use the first MAX cluster nodes supplied with --nodes")
        grp1.add_argument("--benchmark",
                          action="store_true",
                          help="Add timing information")
        grp1.add_argument("--list", "--list-tests",
                          action="store_true", dest="list_tests",
                          help="List the valid tests")
        grp1.add_argument("--nodes",
                          metavar="NODES",
                          help="List of cluster nodes separated by whitespace")
        grp1.add_argument("--stack",
                          default="corosync",
                          metavar="STACK",
                          help="Which cluster stack is installed")

        grp2 = parser.add_argument_group("Options that CTS will usually auto-detect correctly")
        grp2.add_argument("-L", "--logfile",
                          metavar="PATH",
                          help="Where to look for logs from cluster nodes")
        grp2.add_argument("--at-boot", "--cluster-starts-at-boot",
                          choices=["1", "0", "yes", "no"],
                          help="Does the cluster software start at boot time?")
        grp2.add_argument("--facility", "--syslog-facility",
                          default="daemon",
                          metavar="NAME",
                          help="Which syslog facility to log to")
        grp2.add_argument("--ip", "--test-ip-base",
                          metavar="IP",
                          help="Offset for generated IP address resources")

        grp3 = parser.add_argument_group("Options for release testing")
        grp3.add_argument("-r", "--populate-resources",
                          action="store_true",
                          help="Generate a sample configuration")
        grp3.add_argument("--choose",
                          metavar="NAME",
                          help="Run only the named test")
        grp3.add_argument("--fencing", "--stonith",
                          choices=["1", "0", "yes", "no", "lha", "openstack", "rhcs", "rhevm", "scsi", "ssh", "virt", "xvm"],
                          default="1",
                          help="What fencing agent to use")
        grp3.add_argument("--once",
                          action="store_true",
                          help="Run all valid tests once")

        grp4 = parser.add_argument_group("Additional (less common) options")
        grp4.add_argument("-c", "--clobber-cib",
                          action="store_true",
                          help="Erase any existing configuration")
        grp4.add_argument("-y", "--yes",
                          action="store_true", dest="always_continue",
                          help="Continue to run whenever prompted")
        grp4.add_argument("--boot",
                          action="store_true",
                          help="")
        grp4.add_argument("--bsc",
                          action="store_true",
                          help="")
        grp4.add_argument("--cib-filename",
                          metavar="PATH",
                          help="Install the given CIB file to the cluster")
        grp4.add_argument("--container-tests",
                          action="store_true",
                          help="Include pacemaker_remote tests that run in lxc container resources")
        grp4.add_argument("--experimental-tests",
                          action="store_true",
                          help="Include experimental tests")
        grp4.add_argument("--loop-minutes",
                          type=int, default=60,
                          help="")
        grp4.add_argument("--no-loop-tests",
                          action="store_true",
                          help="Don't run looping/time-based tests")
        grp4.add_argument("--no-unsafe-tests",
                          action="store_true",
                          help="Don't run tests that are unsafe for use with ocfs2/drbd")
        grp4.add_argument("--notification-agent",
                          metavar="PATH",
                          default="/var/lib/pacemaker/notify.sh",
                          help="Script to configure for Pacemaker alerts")
        grp4.add_argument("--notification-recipient",
                          metavar="R",
                          default="/var/lib/pacemaker/notify.log",
                          help="Recipient to pass to alert script")
        grp4.add_argument("--oprofile",
                          metavar="NODES",
                          help="List of cluster nodes to run oprofile on")
        grp4.add_argument("--outputfile",
                          metavar="PATH",
                          help="Location to write logs to")
        grp4.add_argument("--qarsh",
                          action="store_true",
                          help="Use QARSH to access nodes instead of SSH")
        grp4.add_argument("--recv-loss",
                          type=float, default=0.0,
                          metavar="RATE",
                          help="")
        grp4.add_argument("--schema",
                          metavar="SCHEMA",
                          default="pacemaker-3.0",
                          help="Create a CIB conforming to the given schema")
        grp4.add_argument("--seed",
                          metavar="SEED",
                          help="Use the given string as the random number seed")
        grp4.add_argument("--set",
                          action="append",
                          metavar="ARG",
                          default=[],
                          help="Set key=value pairs (can be specified multiple times)")
        grp4.add_argument("--stonith-args",
                          metavar="ARGS",
                          default="hostlist=all,livedangerously=yes",
                          help="")
        grp4.add_argument("--stonith-type",
                          metavar="TYPE",
                          default="external/ssh",
                          help="")
        grp4.add_argument("--trunc",
                          action="store_true", dest="truncate",
                          help="Truncate log file before starting")
        grp4.add_argument("--valgrind-procs",
                          metavar="PROCS",
                          default="pacemaker-attrd pacemaker-based pacemaker-controld pacemaker-execd pacemaker-fenced pacemaker-schedulerd",
                          help="Run valgrind against the given space-separated list of processes")
        grp4.add_argument("--valgrind-tests",
                          action="store_true",
                          help="Include tests using valgrind")
        grp4.add_argument("--warn-inactive",
                          action="store_true",
                          help="Warn if a resource is assigned to an inactive node")
        grp4.add_argument("--xmit-loss",
                          type=float, default=0.0,
                          metavar="RATE",
                          help="")

        parser.add_argument("iterations",
                            type=int,
                            help="Number of tests to run")

        args = parser.parse_args(args=argv)

        # Set values on this object based on what happened with command line
        # processing.  This has to be done in several blocks.

        # These values can always be set.  They get a default from the add_argument
        # calls, only do one thing, and they do not have any side effects.
        self["ClobberCIB"] = args.clobber_cib
        self["ListTests"] = args.list_tests
        self["Schema"] = args.schema
        self["Stack"] = args.stack
        self["SyslogFacility"] = args.facility
        self["TruncateLog"] = args.truncate
        self["at-boot"] = args.at_boot in ["1", "yes"]
        self["benchmark"] = args.benchmark
        self["continue"] = args.always_continue
        self["container-tests"] = args.container_tests
        self["experimental-tests"] = args.experimental_tests
        self["iterations"] = args.iterations
        self["loop-minutes"] = args.loop_minutes
        self["loop-tests"] = not args.no_loop_tests
        self["notification-agent"] = args.notification_agent
        self["notification-recipient"] = args.notification_recipient
        self["node-limit"] = args.limit_nodes
        self["stonith-params"] = args.stonith_args
        self["stonith-type"] = args.stonith_type
        self["unsafe-tests"] = not args.no_unsafe_tests
        self["valgrind-procs"] = args.valgrind_procs
        self["valgrind-tests"] = args.valgrind_tests
        self["warn-inactive"] = args.warn_inactive

        # Nodes and groups are mutually exclusive, so their defaults cannot be
        # set in their add_argument calls.  Additionally, groups does more than
        # just set a value.  Here, set nodes first and then if a group is
        # specified, override the previous nodes value.
        if args.nodes:
            self["nodes"] = args.nodes.split(" ")
        else:
            self["nodes"] = []

        if args.group:
            self["OutputFile"] = "%s/cluster-%s.log" % (os.environ['HOME'], args.dsh_group)
            LogFactory().add_file(self["OutputFile"], "CTS")

            dsh_file = "%s/.dsh/group/%s" % (os.environ['HOME'], args.dsh_group)

            if os.path.isfile(dsh_file):
                self["nodes"] = []

                with open(dsh_file, "r") as f:
                    for line in f:
                        l = line.strip().rstrip()

                        if not l.startswith('#'):
                            self["nodes"].append(l)
            else:
                print("Unknown DSH group: %s" % args.dsh_group)

        # Everything else either can't have a default set in an add_argument
        # call (likely because we don't want to always have a value set for it)
        # or it does something fancier than just set a single value.  However,
        # order does not matter for these as long as the user doesn't provide
        # conflicting arguments on the command line.  So just do Everything
        # alphabetically.
        if args.boot:
            self["scenario"] = "boot"

        if args.bsc:
            self["DoBSC"] = True
            self["scenario"] = "basic-sanity"

        if args.cib_filename:
            self["CIBfilename"] = args.cib_filename
        else:
            self["CIBfilename"] = None

        if args.choose:
            self["scenario"] = "sequence"
            self["tests"].append(args.choose)

        if args.fencing:
            if args.fencing in ["0", "no"]:
                self["DoFencing"] = False
            else:
                self["DoFencing"] = True

                if args.fencing in ["rhcs", "virt", "xvm"]:
                    self["stonith-type"] = "fence_xvm"

                elif args.fencing == "scsi":
                    self["stonith-type"] = "fence_scsi"

                elif args.fencing in ["lha", "ssh"]:
                    self["stonith-params"] = "hostlist=all,livedangerously=yes"
                    self["stonith-type"] = "external/ssh"

                elif args.fencing == "openstack":
                    self["stonith-type"] = "fence_openstack"

                    print("Obtaining OpenStack credentials from the current environment")
                    self["stonith-params"] = "region=%s,tenant=%s,auth=%s,user=%s,password=%s" % (
                        os.environ['OS_REGION_NAME'],
                        os.environ['OS_TENANT_NAME'],
                        os.environ['OS_AUTH_URL'],
                        os.environ['OS_USERNAME'],
                        os.environ['OS_PASSWORD']
                    )

                elif args.fencing == "rhevm":
                    self["stonith-type"] = "fence_rhevm"

                    print("Obtaining RHEV-M credentials from the current environment")
                    self["stonith-params"] = "login=%s,passwd=%s,ipaddr=%s,ipport=%s,ssl=1,shell_timeout=10" % (
                        os.environ['RHEVM_USERNAME'],
                        os.environ['RHEVM_PASSWORD'],
                        os.environ['RHEVM_SERVER'],
                        os.environ['RHEVM_PORT'],
                    )

        if args.ip:
            self["CIBResource"] = True
            self["ClobberCIB"] = True
            self["IPBase"] = args.ip

        if args.logfile:
            self["LogAuditDisabled"] = True
            self["LogFileName"] = args.logfile
            self["LogWatcher"] = "remote"
        else:
            # We can't set this as the default on the parser.add_argument call
            # for this option because then args.logfile will be set, which means
            # the above branch will be taken and those other values will also be
            # set.
            self["LogFileName"] = "/var/log/messages"

        if args.once:
            self["scenario"] = "all-once"

        if args.oprofile:
            self["oprofile"] = args.oprofile.split(" ")
        else:
            self["oprofile"] = []

        if args.outputfile:
            self["OutputFile"] = args.outputfile
            LogFactory().add_file(self["OutputFile"])

        if args.populate_resources:
            self["CIBResource"] = True
            self["ClobberCIB"] = True

        if args.qarsh:
            self.rsh.enable_qarsh()

        for kv in args.set:
            (name, value) = kv.split("=")
            self[name] = value
            print("Setting %s = %s" % (name, value))

class EnvFactory:
    instance = None

    def getInstance(self, args=None):
        if not EnvFactory.instance:
            EnvFactory.instance = Environment(args)

        return EnvFactory.instance
