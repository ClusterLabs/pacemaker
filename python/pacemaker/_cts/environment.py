"""Test environment classes for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["EnvFactory", "set_cts_path"]
__copyright__ = "Copyright 2014-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import argparse
from contextlib import suppress
from glob import glob
import os
import random
import shlex
import socket
import sys

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts import logging
from pacemaker._cts.remote import RemoteExec
from pacemaker._cts.watcher import LogKind


class Environment:
    """
    A class for managing the CTS environment.

    This consists largely of processing and storing command line parameters.
    """

    def __init__(self, args):
        """
        Create a new Environment instance.

        This class can be treated kind of like a dictionary due to the presence
        of typical dict functions like __contains__, __getitem__, and __setitem__.
        However, it is not a dictionary so do not rely on standard dictionary
        behavior.

        Arguments:
        args -- A list of command line parameters, minus the program name.
                If None, sys.argv will be used.
        """
        self.data = {}

        # Set some defaults before processing command line arguments.  These are
        # either not set by any command line parameter, or they need a default
        # that can't be set in add_argument.
        self["dead_time"] = 300
        self["log_kind"] = None
        self["scenario"] = "random"
        self["stable_time"] = 30
        self["start_time"] = 300
        self["syslog_facility"] = "daemon"
        self["tests"] = []

        # Hard-coded since there is only one supported cluster manager/stack
        self["Name"] = "crm-corosync"
        self["Stack"] = "corosync 2+"

        self.random_gen = random.Random()

        self._rsh = RemoteExec()

        self._parse_args(args)

        if not self["ListTests"]:
            self._validate()
            self._discover()

    def dump(self):
        """Print the current environment."""
        for key in sorted(self.data.keys()):
            logging.debug(f"{f'Environment[{key}]':35}: {str(self[key])}")

    def __contains__(self, key):
        """Return True if the given key exists in the environment."""
        return key in self.data

    def __getitem__(self, key):
        """Return the given environment key, or None if it does not exist."""
        return self.data.get(key)

    def __setitem__(self, key, value):
        """Set the given environment key to the given value, overriding any previous value."""
        if key == "nodes":
            self.data["nodes"] = []
            for node in value:
                node = node.strip()

                # I don't think I need the IP address, etc. but this validates
                # the node name against /etc/hosts and/or DNS, so it's a
                # GoodThing(tm).
                try:
                    # @TODO This only handles IPv4, use getaddrinfo() instead
                    # (here and in _discover())
                    socket.gethostbyname_ex(node)
                    self.data["nodes"].append(node)
                except socket.herror:
                    logging.log(f"{node} not found in DNS... aborting")
                    raise

        else:
            self.data[key] = value

    def random_node(self):
        """Choose a random node from the cluster."""
        return self.random_gen.choice(self["nodes"])

    def _detect_systemd(self, node):
        """Detect whether systemd is in use on the target node."""
        if "have_systemd" not in self.data:
            (rc, _) = self._rsh(node, "systemctl list-units", verbose=0)
            self["have_systemd"] = rc == 0

    def _detect_syslog(self, node):
        """Detect the syslog variant in use on the target node (if any)."""
        if "syslogd" in self.data:
            return

        if self["have_systemd"]:
            # Systemd
            (_, lines) = self._rsh(node, r"systemctl list-units | grep syslog.*\.service.*active.*running | sed 's:.service.*::'", verbose=1)
        else:
            # SYS-V
            (_, lines) = self._rsh(node, "chkconfig --list | grep syslog.*on | awk '{print $1}' | head -n 1", verbose=1)

        with suppress(IndexError):
            self["syslogd"] = lines[0].strip()

    def disable_service(self, node, service):
        """Disable the given service on the given node."""
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self._rsh(node, f"systemctl disable {service}")
            return rc

        # SYS-V
        (rc, _) = self._rsh(node, f"chkconfig {service} off")
        return rc

    def enable_service(self, node, service):
        """Enable the given service on the given node."""
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self._rsh(node, f"systemctl enable {service}")
            return rc

        # SYS-V
        (rc, _) = self._rsh(node, f"chkconfig {service} on")
        return rc

    def service_is_enabled(self, node, service):
        """Return True if the given service is enabled on the given node."""
        if self["have_systemd"]:
            # Systemd

            # With "systemctl is-enabled", we should check if the service is
            # explicitly "enabled" instead of the return code. For example it returns
            # 0 if the service is "static" or "indirect", but they don't really count
            # as "enabled".
            (rc, _) = self._rsh(node, f"systemctl is-enabled {service} | grep enabled")
            return rc == 0

        # SYS-V
        (rc, _) = self._rsh(node, f"chkconfig --list | grep -e {service}.*on")
        return rc == 0

    def _detect_at_boot(self, node):
        """Detect if the cluster starts at boot."""
        self["at-boot"] = any(self.service_is_enabled(node, service)
                              for service in ("pacemaker", "corosync"))

    def _detect_ip_offset(self, node):
        """Detect the offset for IPaddr resources."""
        if self["create_resources"] and "IPBase" not in self.data:
            (_, lines) = self._rsh(node, "ip addr | grep inet | grep -v -e link -e inet6 -e '/32' -e ' lo' | awk '{print $2}'", verbose=0)
            network = lines[0].strip()

            (_, lines) = self._rsh(node, "nmap -sn -n %s | grep 'scan report' | awk '{print $NF}' | sed 's:(::' | sed 's:)::' | sort -V | tail -n 1" % network, verbose=0)

            try:
                self["IPBase"] = lines[0].strip()
            except (IndexError, TypeError):
                self["IPBase"] = None

            if not self["IPBase"]:
                self["IPBase"] = " fe80::1234:56:7890:1000"
                logging.log("Could not determine an offset for IPaddr resources.  Perhaps nmap is not installed on the nodes.")
                logging.log(f"""Defaulting to '{self["IPBase"]}', use --test-ip-base to override""")
                return

            last_part = self["IPBase"].split('.')[3]
            if int(last_part) >= 240:
                logging.log(f"Could not determine an offset for IPaddr resources. Upper bound is too high: {self['IPBase']} {last_part}")
                self["IPBase"] = " fe80::1234:56:7890:1000"
                logging.log(f"""Defaulting to '{self["IPBase"]}', use --test-ip-base to override""")

    def _validate(self):
        """Check that we were given all required command line parameters."""
        if not self["nodes"]:
            raise ValueError("No nodes specified!")

    def _discover(self):
        """Probe cluster nodes to figure out how to log and manage services."""
        exerciser = socket.gethostname()

        # Use the IP where possible to avoid name lookup failures
        for ip in socket.gethostbyname_ex(exerciser)[2]:
            if ip != "127.0.0.1":
                exerciser = ip
                break

        self["cts-exerciser"] = exerciser

        node = self["nodes"][0]
        self._detect_systemd(node)
        self._detect_syslog(node)
        self._detect_at_boot(node)
        self._detect_ip_offset(node)

    def _parse_args(self, argv):
        """
        Parse and validate command line parameters.

        Set the appropriate values in the environment dictionary.  If argv is
        None, use sys.argv instead.
        """
        if not argv:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser()

        grp1 = parser.add_argument_group("Common options")
        grp1.add_argument("--benchmark",
                          action="store_true",
                          help="Add timing information")
        grp1.add_argument("--list", "--list-tests",
                          action="store_true", dest="list_tests",
                          help="List the valid tests")
        grp1.add_argument("--nodes",
                          default="",
                          help="List of cluster nodes separated by whitespace")

        grp2 = parser.add_argument_group("Options that CTS will usually auto-detect correctly")
        grp2.add_argument("-L", "--logfile",
                          metavar="PATH",
                          help="Where to look for logs from cluster nodes (or 'journal' for systemd journal)")
        grp2.add_argument("--ip", "--test-ip-base",
                          help="Offset for generated IP address resources")
        grp2.add_argument("--nic",
                          help="Network interface used for generated IP address resources")

        grp3 = parser.add_argument_group("Options for release testing")
        grp3.add_argument("-r", "--populate-resources",
                          action="store_true",
                          help="Generate a sample configuration")
        grp3.add_argument("--choose",
                          metavar="NAME",
                          help="Run only the named tests, separated by whitespace")
        grp3.add_argument("--disable-fencing",
                          action="store_false",
                          dest="fencing_enabled",
                          help="Whether to disable fencing")
        grp3.add_argument("--fencing-agent",
                          metavar="AGENT",
                          default="external/ssh",
                          help="Agent to use for a fencing resource")
        grp3.add_argument("--fencing-params",
                          metavar="PARAMS",
                          default="",
                          help="Parameters for the fencing resource (as NAME=VALUE), separated by whitespace")
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
        grp4.add_argument("--cib-filename",
                          metavar="PATH",
                          help="Install the given CIB file to the cluster")
        grp4.add_argument("--no-unsafe-tests",
                          action="store_false",
                          dest="unsafe_tests",
                          help="Don't run tests that are unsafe for use with ocfs2/drbd")
        grp4.add_argument("--notification-agent",
                          metavar="PATH",
                          default="/var/lib/pacemaker/notify.sh",
                          help="Script to configure for Pacemaker alerts")
        grp4.add_argument("--notification-recipient",
                          metavar="R",
                          default="/var/lib/pacemaker/notify.log",
                          help="Recipient to pass to alert script")
        grp4.add_argument("--outputfile",
                          metavar="PATH",
                          help="Location to write logs to")
        grp4.add_argument("--schema",
                          default=f"pacemaker-{BuildOptions.CIB_SCHEMA_VERSION}",
                          help="Create a CIB conforming to the given schema")
        grp4.add_argument("--seed",
                          help="Use the given string as the random number seed")
        grp4.add_argument("--trunc",
                          action="store_true", dest="truncate",
                          help="Truncate log file before starting")

        parser.add_argument("iterations",
                            nargs='?',
                            type=int, default=1,
                            help="Number of tests to run")

        args = parser.parse_args(args=argv)

        # Set values on this object based on what happened with command line
        # processing.  This has to be done in several blocks.

        # These values can always be set. Most get a default from the add_argument
        # calls, they only do one thing, and they do not have any side effects.
        self["CIBfilename"] = args.cib_filename if args.cib_filename else None
        self["create_resources"] = bool(args.ip or args.populate_resources)
        self["fencing_agent"] = args.fencing_agent
        self["fencing_enabled"] = args.fencing_enabled
        self["fencing_params"] = shlex.split(args.fencing_params)
        self["ListTests"] = args.list_tests
        self["overwrite_cib"] = any([args.clobber_cib, args.ip, args.populate_resources])
        self["Schema"] = args.schema
        self["TruncateLog"] = args.truncate
        self["benchmark"] = args.benchmark
        self["continue"] = args.always_continue
        self["iterations"] = args.iterations
        self["nodes"] = shlex.split(args.nodes)
        self["notification-agent"] = args.notification_agent
        self["notification-recipient"] = args.notification_recipient
        self["unsafe-tests"] = args.unsafe_tests
        self["nic"] = args.nic

        # Everything else either can't have a default set in an add_argument
        # call (likely because we don't want to always have a value set for it)
        # or it does something fancier than just set a single value.  However,
        # order does not matter for these as long as the user doesn't provide
        # conflicting arguments on the command line.  So just do Everything
        # alphabetically.
        if args.boot:
            self["scenario"] = "boot"

        if args.choose:
            self["scenario"] = "sequence"
            self["tests"].extend(shlex.split(args.choose))
            self["iterations"] = len(self["tests"])

        if args.ip:
            self["IPBase"] = args.ip

        if args.logfile == "journal":
            self["LogAuditDisabled"] = True
            self["log_kind"] = LogKind.JOURNAL
        elif args.logfile:
            self["LogAuditDisabled"] = True
            self["LogFileName"] = args.logfile
            self["log_kind"] = LogKind.REMOTE_FILE
        else:
            # We can't set this as the default on the parser.add_argument call
            # for this option because then args.logfile will be set, which means
            # the above branch will be taken and those other values will also be
            # set.
            self["LogFileName"] = "/var/log/messages"

        if args.once:
            self["scenario"] = "all-once"

        if args.outputfile:
            self["OutputFile"] = args.outputfile
            logging.add_file(self["OutputFile"])

        self.random_gen.seed(args.seed)


class EnvFactory:
    """A class for constructing a singleton instance of an Environment object."""

    instance = None

    # pylint: disable=invalid-name
    def getInstance(self, args=None):
        """
        Return the previously created instance of Environment.

        If no instance exists, create a new instance and return that.
        """
        if not EnvFactory.instance:
            EnvFactory.instance = Environment(args)

        return EnvFactory.instance


def set_cts_path(extra=None):
    """Set the PATH environment variable appropriately for the tests."""
    new_path = os.environ['PATH']

    # Add any search paths given on the command line
    if extra is not None:
        for p in extra:
            new_path = f"{p}:{new_path}"

    cwd = os.getcwd()

    if os.path.exists(f"{cwd}/cts/cts-attrd.in"):
        # pylint: disable=protected-access
        print(f"Running tests from the source tree: {BuildOptions._BUILD_DIR}")

        for d in glob(f"{BuildOptions._BUILD_DIR}/daemons/*/"):
            new_path = f"{d}:{new_path}"

        new_path = f"{BuildOptions._BUILD_DIR}/tools:{new_path}"
        new_path = f"{BuildOptions._BUILD_DIR}/cts/support:{new_path}"

        print(f"Using local schemas from: {cwd}/xml")
        os.environ["PCMK_schema_directory"] = f"{cwd}/xml"

    else:
        print(f"Running tests from the install tree: {BuildOptions.DAEMON_DIR} (not {cwd})")
        new_path = f"{BuildOptions.DAEMON_DIR}:{new_path}"
        os.environ["PCMK_schema_directory"] = BuildOptions.SCHEMA_DIR

    print(f'Using PATH="{new_path}"')
    os.environ['PATH'] = new_path
