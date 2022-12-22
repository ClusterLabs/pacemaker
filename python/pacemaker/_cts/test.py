# Copyright 2009-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.

__all__ = ["Test"]

import os
import re
import shlex
import subprocess
import sys
import time

from pacemaker._cts.errors import *
from pacemaker._cts.process import pipe_communicate
from pacemaker.buildoptions import BuildOptions
from pacemaker.exitstatus import ExitStatus

def find_validator(rng_file):
    if os.access("/usr/bin/xmllint", os.X_OK):
        if rng_file == None:
            return ["xmllint", "-"]
        else:
            return ["xmllint", "--relaxng", rng_file, "-"]
    else:
        return None


def rng_directory():
    if "PCMK_schema_directory" in os.environ:
        return os.environ["PCMK_schema_directory"]
    elif os.path.exists("%s/cts-fencing.in" % sys.path[0]):
        return "xml"
    else:
        return BuildOptions.SCHEMA_DIR


class Test(object):
    """ The base class for a single regression test.  A single regression test
        may still run multiple commands as part of its execution.
    """

    def __init__(self, name, description, **kwargs):
        """ Create a new Test instance.  This method must be provided by all
            subclasses, which must call Test.__init__ first.

            Arguments:

            description -- A user-readable description of the test, helpful in
                           identifying what test is running or has failed.
            name        -- The name of the test.  Command line tools use this
                           attribute to allow running only tests with the exact
                           name, or tests whose name matches a given pattern.
                           This should be unique among all tests.

            Keyword arguments:

            force_wait  --
            logdir      -- The base directory under which to create a directory
                           to store output and temporary data.
            timeout     -- How long to wait for the test to complete.
            verbose     -- Whether to print additional information, including
                           verbose command output and daemon log files.
        """

        self.description = description
        self.executed = False
        self.name = name

        self.force_wait = kwargs.get("force_wait", False)
        self.logdir = kwargs.get("logdir", "/tmp")
        self.timeout = kwargs.get("timeout", 2)
        self.verbose = kwargs.get("verbose", False)

        self._cmds = []
        self._daemon_location = None
        self._result_exitcode = ExitStatus.OK
        self._result_txt = ""
        self._stonith_process = None

    ###
    ### PROPERTIES
    ###

    @property
    def exitcode(self):
        """ The final exitcode of the Test.  If all commands pass, this property
            will be ExitStatus.OK.  Otherwise, this property will be the exitcode
            of the first command to fail.
        """
        return self._result_exitcode

    @exitcode.setter
    def exitcode(self, value):
        self._result_exitcode = value

    @property
    def logpath(self):
        """ The path to the log for whatever daemon is being tested.  Note that
            this requires all subclasses to sef self._daemon_location before
            accessing this property or an exception will be raised.
        """
        return os.path.join(self.logdir, self._daemon_location + ".log")

    ###
    ### PRIVATE METHODS
    ###

    def _new_cmd(self, cmd, args, exitcode, **kwargs):
        """ Add a command to be executed as part of this test.

            Arguments:

            cmd         -- The program to run.
            args        -- Commands line arguments to pass to cmd, as a string.
            exitcode    -- The expected exit code of cmd.  This can be used to
                           run a command that is expected to fail.

            Keyword arguments:

            stdout_match          -- If not None, a string that is expected to be
                                     present in the stdout of cmd.  This can be a
                                     regular expression.
            no_wait               -- Do not wait for cmd to complete.
            stdout_negative_match -- If not None, a string that is expected to be
                                     missing in the stdout of cmd.  This can be a
                                     regualr expression.
            kill                  -- A command to be run after cmd, typically in
                                     order to kill a failed process.  This should be
                                     the entire command line including arguments as
                                     a single string.
            validate              -- If True, the output of cmd will be passed to
                                     xmllint for validation.  If validation fails,
                                     XmlValidationError will be raised.
            check_rng             -- If True and validate is True, command output
                                     will additionally be checked against the
                                     api-result.rng file.
            check_stderr          -- If True, the stderr of cmd will be included in
                                     output.
        """

        self._cmds.append(
            {
                "args": args,
                "check_rng": kwargs.get("check_rng", True),
                "check_stderr": kwargs.get("check_stderr", True),
                "cmd": cmd,
                "expected_exitcode": exitcode,
                "kill": kwargs.get("kill", None),
                "no_wait": kwargs.get("no_wait", False),
                "stdout_match": kwargs.get("stdout_match", None),
                "stdout_negative_match": kwargs.get("stdout_negative_match", None),
                "validate": kwargs.get("validate", True),
            }
        )

    ###
    ### PUBLIC METHODS
    ###

    def add_cmd(self, cmd, args, validate=True, check_rng=True, check_stderr=True):
        """ Add a simple command to be executed as part of this test """

        self._new_cmd(cmd, args, ExitStatus.OK, validate=validate, check_rng=check_rng,
                      check_stderr=check_stderr)

    def add_cmd_and_kill(self, cmd, args, kill_proc):
        """ Add a command and system command to be executed as part of this test """

        self._new_cmd(cmd, args, ExitStatus.OK, kill=kill_proc)

    def add_cmd_check_stdout(self, cmd, args, match, no_match=None):
        """ Add a simple command with expected output to be executed as part of this test """

        self._new_cmd(cmd, args, ExitStatus.OK, stdout_match=match,
                      stdout_negative_match=no_match)

    def add_cmd_expected_fail(self, cmd, args, exitcode=ExitStatus.ERROR):
        """ Add a command that is expected to fail to be executed as part of this test """

        self._new_cmd(cmd, args, exitcode)

    def add_cmd_no_wait(self, cmd, args):
        """ Add a simple command to be executed (without waiting) as part of this test """

        self._new_cmd(cmd, args, ExitStatus.OK, no_wait=True)

    def run_cmd(self, args):
        """ Execute a command as part of this test """

        cmd = shlex.split(args['args'])
        cmd.insert(0, args['cmd'])

        if self.verbose:
            print("\n\nRunning: %s" % " ".join(cmd))

        test = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if args['kill']:
            if self.verbose:
                print("Also running: %s" % args['kill'])

            ### Typically, the kill argument is used to detect some sort of
            ### failure. Without yielding for a few seconds here, the process
            ### launched earlier that is listening for the failure may not have
            ### time to connect to pacemaker-execd.
            time.sleep(2)
            subprocess.Popen(shlex.split(args['kill']))

        if not args['no_wait']:
            test.wait()
        else:
            return ExitStatus.OK

        output = pipe_communicate(test, check_stderr=args['check_stderr'])

        if self.verbose:
            print(output)

        if test.returncode != args['expected_exitcode']:
            raise ExitCodeError(test.returncode)

        if args['stdout_match'] is not None and \
           re.search(args['stdout_match'], output) is None:
            raise OutputNotFoundError(output)

        if args['stdout_negative_match'] is not None and \
           re.search(args['stdout_negative_match'], output) is not None:
            raise OutputFoundError(output)

        if args['validate']:
            if args['check_rng']:
                rng_file = rng_directory() + "/api/api-result.rng"
            else:
                rng_file = None

            cmd = find_validator(rng_file)
            if not cmd:
                return

            if self.verbose:
                print("\nRunning: %s" % " ".join(cmd))

            validator = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = pipe_communicate(validator, check_stderr=True, stdin=output)

            if self.verbose:
                print(output)

            if validator.returncode != 0:
                raise XmlValidationError(output)
