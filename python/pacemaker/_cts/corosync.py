"""A module providing functions for manipulating corosync."""

__all__ = ["Corosync", "localname"]
__copyright__ = "Copyright 2009-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+)"

import os
import shutil
import subprocess
import tempfile
import time

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.process import killall, stdout_from_command


AUTOGEN_COROSYNC_TEMPLATE = """
totem {
    version: 2
    cluster_name: %s
    crypto_cipher: none
    crypto_hash: none
    transport: udp
}

nodelist {
    node {
        nodeid: 1
        name: %s
        ring0_addr: 127.0.0.1
    }
}

logging {
    debug: off
    to_syslog: no
    to_stderr: no
    to_logfile: yes
    logfile: %s
}
"""


def corosync_cfg_exists():
    """Return whether the corosync config file exists."""
    return os.path.exists(BuildOptions.COROSYNC_CONFIG_FILE)


def corosync_log_file(cfgfile):
    """Return the path to the corosync log file, or None."""
    with open(cfgfile, "r", encoding="utf-8") as f:
        for line in f.readlines():
            # "to_logfile:" could also be in the config file, so check for a
            # slash to make sure it's a path we're looking at.
            if "logfile: /" in line:
                return line.split()[-1]

    return None


def generate_corosync_cfg(logdir, cluster_name, node_name):
    """
    Generate a corosync config file.

    If there's a corosync config file already installed on the system, move
    it to a temporary location and return that temporary name.  Otherwise,
    return None.
    """
    retval = None

    if corosync_cfg_exists():
        # pylint: disable=consider-using-with
        config_dir = os.path.dirname(BuildOptions.COROSYNC_CONFIG_FILE)
        f = tempfile.NamedTemporaryFile(dir=config_dir, prefix="corosync.conf-")
        f.close()
        shutil.move(BuildOptions.COROSYNC_CONFIG_FILE, f.name)

        retval = f.name

    logfile = os.path.join(logdir, "corosync.log")

    with open(BuildOptions.COROSYNC_CONFIG_FILE, "w", encoding="utf-8") as corosync_cfg:
        corosync_cfg.write(AUTOGEN_COROSYNC_TEMPLATE % (cluster_name, node_name, logfile))

    return retval


def localname():
    """Return the uname of the local host."""
    our_uname = stdout_from_command(["uname", "-n"])
    if our_uname:
        our_uname = our_uname[0]
    else:
        our_uname = "localhost"

    return our_uname


class Corosync:
    """A class for managing corosync processes and config files."""

    def __init__(self, verbose, logdir, cluster_name):
        """
        Create a new Corosync instance.

        Arguments:
        verbose      -- Whether to print the corosync log file
        logdir       -- The base directory under which to store log files
        cluster_name -- The name of the cluster
        """
        self.verbose = verbose
        self.logdir = logdir
        self.cluster_name = cluster_name

        # The Corosync class doesn't use self._env["nodes"], but the
        # "--nodes" argument is required to be present and nonempty
        self._env = EnvFactory().getInstance(args=["--nodes", "localhost"])
        self._existing_cfg_file = None

    def _ready(self, logfile, timeout=10):
        """Return whether corosync is ready."""
        i = 0

        while i < timeout:
            with open(logfile, "r", encoding="utf-8") as corosync_log:
                for line in corosync_log.readlines():
                    if line.endswith("ready to provide service.\n"):
                        # Even once the line is in the log file, we may still need to wait just
                        # a little bit longer before corosync is really ready to go.
                        time.sleep(1)
                        return

            time.sleep(1)
            i += 1

        raise TimeoutError

    def _start(self):
        """Start corosync using whatever method is supported on the system."""
        # pylint doesn't understand that self._env is subscriptable.
        # pylint: disable=unsubscriptable-object
        if self._env["have_systemd"]:
            cmd = ["systemctl", "start", "corosync.service"]
        else:
            cmd = ["corosync"]

        if self.verbose:
            print("Starting corosync")

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            p.wait()

    def _stop(self):
        """Stop corosync using whatever method is supported on the system."""
        # pylint doesn't understand that self._env is subscriptable.
        # pylint: disable=unsubscriptable-object
        if self._env["have_systemd"]:
            cmd = ["systemctl", "stop", "corosync.service"]

            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
                p.wait()
        else:
            killall(["corosync"])

    def start(self, kill_first=False, timeout=10):
        """
        Start the corosync process.

        Arguments:
        kill_first -- Whether to kill any pre-existing corosync processes before
                      starting a new one
        timeout    -- If corosync does not start within this many seconds, raise
                      TimeoutError
        """
        if kill_first:
            self._stop()

        self._existing_cfg_file = generate_corosync_cfg(self.logdir,
                                                        self.cluster_name, localname())
        logfile = corosync_log_file(BuildOptions.COROSYNC_CONFIG_FILE)

        self._start()

        # Wait for corosync to be ready before returning
        self._ready(logfile, timeout=timeout)

    def stop(self):
        """Stop the corosync process."""
        self._stop()

        if self.verbose:
            print("Corosync output")

            logfile = corosync_log_file(BuildOptions.COROSYNC_CONFIG_FILE)
            with open(logfile, "r", encoding="utf-8") as corosync_log:
                for line in corosync_log.readlines():
                    print(line.strip())

        os.remove(BuildOptions.COROSYNC_CONFIG_FILE)

        # If there was a previous corosync config file, move it back into place
        if self._existing_cfg_file:
            shutil.move(self._existing_cfg_file, BuildOptions.COROSYNC_CONFIG_FILE)
