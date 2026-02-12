"""Remote command runner for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["RemoteExec"]
__copyright__ = "Copyright 2014-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import os

import subprocess
from threading import Thread

from pacemaker._cts import logging


class AsyncCmd(Thread):
    """A class for doing the hard work of running a command on another machine."""

    def __init__(self, node, command, proc=None, delegate=None):
        """
        Create a new AsyncCmd instance.

        Arguments:
        node     -- The remote machine to run on
        command  -- The ssh command string to use for remote execution
        proc     -- If not None, a process object previously created with Popen.
                    Instead of spawning a new process, we will then wait on
                    this process to finish and handle its output.
        delegate -- When the command completes, call the async_complete method
                    on this object
        """
        self._command = command
        self._delegate = delegate
        self._node = node
        self._proc = proc

        Thread.__init__(self)

    def run(self):
        """Run the previously instantiated AsyncCmd object."""
        out = None
        err = None

        if not self._proc:
            # pylint: disable=consider-using-with
            self._proc = subprocess.Popen(self._command, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, close_fds=True,
                                          shell=True, universal_newlines=True)

        logging.debug(f"cmd: async: target={self._node}, pid={self._proc.pid}: {self._command}")
        self._proc.wait()

        if self._delegate:
            logging.debug(f"cmd: pid {self._proc.pid} returned {self._proc.returncode} to {self._delegate!r}")
        else:
            logging.debug(f"cmd: pid {self._proc.pid} returned {self._proc.returncode}")

        if self._proc.stderr:
            err = self._proc.stderr.readlines()
            self._proc.stderr.close()

            for line in err:
                logging.debug(f"cmd: stderr[{self._proc.pid}]: {line}")

        if self._proc.stdout:
            out = self._proc.stdout.readlines()
            self._proc.stdout.close()

        if self._delegate:
            self._delegate.async_complete(self._proc.pid, self._proc.returncode, out, err)


class RemoteExec:
    """
    An abstract class for remote execution.

    It runs a command on another machine using ssh and scp.
    """

    def __init__(self):
        """Create a new RemoteExec instance."""

        # @TODO This should be an argument list that gets used with subprocess,
        # but making that change will require changing everywhere that __call__
        # or call_async pass a command string.
        #
        # -n: no stdin, -x: no X11,
        # -o ServerAliveInterval=5: disconnect after 3*5s if the server
        # stops responding
        self._command = "ssh -l root -n -x -o ServerAliveInterval=5 " \
                        "-o ConnectTimeout=10 -o TCPKeepAlive=yes " \
                        "-o ServerAliveCountMax=3"
        self._our_node = os.uname()[1].lower()

    def _fixcmd(self, cmd):
        """Perform shell escapes on certain characters in the input cmd string."""
        return re.sub("\'", "'\\''", cmd)

    def _cmd(self, args):
        """Given a list of arguments, return the string that will be run on the remote system."""
        sysname = args[0]
        command = args[1]

        if sysname is None or sysname.lower() in [self._our_node, "localhost"]:
            ret = command
        else:
            ret = f"{self._command} {sysname} '{self._fixcmd(command)}'"

        return ret

    def call_async(self, node, command, delegate=None):
        """
        Run the given command on the given remote system and do not wait for it to complete.

        Arguments:
        node     -- The remote machine to run on
        command  -- The command to run, as a string
        delegate -- When the command completes, call the async_complete method
                    on this object

        Returns the running process object.
        """
        aproc = AsyncCmd(node, self._cmd([node, command]), delegate=delegate)
        aproc.start()
        return aproc

    def __call__(self, node, command, verbose=2):
        """
        Run the given command on the given remote system.

        If you call this class like a function, this is what gets called.  It's
        approximately the same as a system() call on the remote machine.

        Arguments:
        node        -- The remote machine to run on
        command     -- The command to run, as a string
        verbose     -- If 0, do not log anything.  If 1, log the command and its
                       return code but not its output.  If 2, additionally log
                       command output.

        Returns a tuple of (return code, command output).
        """
        rc = 0
        result = None
        # pylint: disable=consider-using-with
        proc = subprocess.Popen(self._cmd([node, command]), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True, shell=True,
                                universal_newlines=True)

        if proc.stdout:
            result = proc.stdout.readlines()
            proc.stdout.close()
        else:
            logging.log("No stdout stream")

        rc = proc.wait()

        if verbose > 0:
            logging.debug(f"cmd: target={node}, rc={rc}: {command}")

        if proc.stderr:
            errors = proc.stderr.readlines()
            proc.stderr.close()

            for err in errors:
                logging.debug(f"cmd: stderr: {err}")

        if verbose == 2:
            for line in result:
                logging.debug(f"cmd: stdout: {line}")

        return (rc, result)

    def copy(self, source, target):
        """
        Perform a copy of the source file to the remote target.

        Returns the return code of the copy process.
        """
        # -B: batch mode, -q: no stats (quiet)
        p = subprocess.run(["scp", "-B", "-q", f"'{source}'", f"'{target}'"],
                           check=False)
        logging.debug(f"cmd: rc={p.returncode}: {p.args}")
        return p.returncode

    def exists_on_all(self, filename, hosts):
        """Return True if specified file exists on all specified hosts."""
        for host in hosts:
            (rc, _) = self(host, f"test -r {filename}")
            if rc != 0:
                return False

        return True

    def exists_on_none(self, filename, hosts):
        """Return True if specified file does not exist on any specified host."""
        for host in hosts:
            (rc, _) = self(host, f"test -r {filename}")
            if rc == 0:
                return False

        return True
