"""Remote command runner for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["RemoteExec", "RemoteFactory"]
__copyright__ = "Copyright 2014-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import os

from subprocess import Popen, PIPE
from threading import Thread

from pacemaker._cts.logging import LogFactory


def convert2string(lines):
    """
    Convert byte strings to UTF-8 strings.

    Lists of byte strings are converted to a list of UTF-8 strings.  All other
    text formats are passed through.
    """
    if isinstance(lines, bytes):
        return lines.decode("utf-8")

    if isinstance(lines, list):
        lst = []
        for line in lines:
            if isinstance(line, bytes):
                line = line.decode("utf-8")

            lst.append(line)

        return lst

    return lines


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
        self._logger = LogFactory()
        self._node = node
        self._proc = proc

        Thread.__init__(self)

    def run(self):
        """Run the previously instantiated AsyncCmd object."""
        out = None
        err = None

        if not self._proc:
            # pylint: disable=consider-using-with
            self._proc = Popen(self._command, stdout=PIPE, stderr=PIPE, close_fds=True, shell=True)

        self._logger.debug(f"cmd: async: target={self._node}, pid={self._proc.pid}: {self._command}")
        self._proc.wait()

        if self._delegate:
            self._logger.debug(f"cmd: pid {self._proc.pid} returned {self._proc.returncode} to {self._delegate!r}")
        else:
            self._logger.debug(f"cmd: pid {self._proc.pid} returned {self._proc.returncode}")

        if self._proc.stderr:
            err = self._proc.stderr.readlines()
            self._proc.stderr.close()

            for line in err:
                self._logger.debug(f"cmd: stderr[{self._proc.pid}]: {line}")

            err = convert2string(err)

        if self._proc.stdout:
            out = self._proc.stdout.readlines()
            self._proc.stdout.close()
            out = convert2string(out)

        if self._delegate:
            self._delegate.async_complete(self._proc.pid, self._proc.returncode, out, err)


class RemoteExec:
    """
    An abstract class for remote execution.

    It runs a command on another machine using ssh and scp.
    """

    def __init__(self, command, cp_command, silent=False):
        """
        Create a new RemoteExec instance.

        Arguments:
        command    -- The ssh command string to use for remote execution
        cp_command -- The scp command string to use for copying files
        silent     -- Should we log command status?
        """
        self._command = command
        self._cp_command = cp_command
        self._logger = LogFactory()
        self._silent = silent
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

    def _log(self, args):
        """Log a message."""
        if not self._silent:
            self._logger.log(args)

    def _debug(self, args):
        """Log a message at the debug level."""
        if not self._silent:
            self._logger.debug(args)

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

    def __call__(self, node, command, synchronous=True, verbose=2):
        """
        Run the given command on the given remote system.

        If you call this class like a function, this is what gets called.  It's
        approximately the same as a system() call on the remote machine.

        Arguments:
        node        -- The remote machine to run on
        command     -- The command to run, as a string
        synchronous -- Should we wait for the command to complete?
        verbose     -- If 0, do not lo:g anything.  If 1, log the command and its
                       return code but not its output.  If 2, additionally log
                       command output.

        Returns a tuple of (return code, command output).
        """
        rc = 0
        result = None
        # pylint: disable=consider-using-with
        proc = Popen(self._cmd([node, command]),
                     stdout=PIPE, stderr=PIPE, close_fds=True, shell=True)

        if not synchronous and proc.pid > 0 and not self._silent:
            aproc = AsyncCmd(node, command, proc=proc)
            aproc.start()
            return (rc, result)

        if proc.stdout:
            result = proc.stdout.readlines()
            proc.stdout.close()
        else:
            self._log("No stdout stream")

        rc = proc.wait()

        if verbose > 0:
            self._debug(f"cmd: target={node}, rc={rc}: {command}")

        result = convert2string(result)

        if proc.stderr:
            errors = proc.stderr.readlines()
            proc.stderr.close()

            for err in errors:
                self._debug(f"cmd: stderr: {err}")

        if verbose == 2:
            for line in result:
                self._debug(f"cmd: stdout: {line}")

        return (rc, result)

    def copy(self, source, target, silent=False):
        """
        Perform a copy of the source file to the remote target.

        This function uses the cp_command provided when the RemoteExec object
        was created.

        Returns the return code of the cp_command.
        """
        # @TODO Use subprocess module with argument array instead
        # (self._cp_command should be an array too)
        cmd = f"{self._cp_command} '{source}' '{target}'"
        rc = os.system(cmd)

        if not silent:
            self._debug(f"cmd: rc={rc}: {cmd}")

        return rc

    def exists_on_all(self, filename, hosts):
        """Return True if specified file exists on all specified hosts."""
        for host in hosts:
            rc = self(host, f"test -r {filename}")
            if rc != 0:
                return False

        return True


class RemoteFactory:
    """A class for constructing a singleton instance of a RemoteExec object."""

    # Class variables

    # -n: no stdin, -x: no X11,
    # -o ServerAliveInterval=5: disconnect after 3*5s if the server
    # stops responding
    command = ("ssh -l root -n -x -o ServerAliveInterval=5 "
               "-o ConnectTimeout=10 -o TCPKeepAlive=yes "
               "-o ServerAliveCountMax=3 ")

    # -B: batch mode, -q: no stats (quiet)
    cp_command = "scp -B -q"

    instance = None

    # pylint: disable=invalid-name
    def getInstance(self):
        """
        Return the previously created instance of RemoteExec.

        If no instance exists, create one and then return that.
        """
        if not RemoteFactory.instance:
            RemoteFactory.instance = RemoteExec(RemoteFactory.command,
                                                RemoteFactory.cp_command,
                                                False)
        return RemoteFactory.instance

    def enable_qarsh(self):
        """Enable the QA remote shell."""
        # http://nstraz.wordpress.com/2008/12/03/introducing-qarsh/
        print("Using QARSH for connections to cluster nodes")

        RemoteFactory.command = "qarsh -t 300 -l root"
        RemoteFactory.cp_command = "qacp -q"
