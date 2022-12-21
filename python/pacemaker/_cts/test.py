""" A module providing base classes for defining regression tests and groups of
    regression tests.  Everything exported here should be considered an abstract
    class that needs to be subclassed in order to do anything useful.  Various
    functions will raise NotImplementedError if not overridden by a subclass.
"""

__copyright__ = "Copyright 2009-2023 the Pacemaker project contributors"
__license__ = "LGPLv2.1+"

import os

from pacemaker.exitstatus import ExitStatus

class Test:
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
            this requires all subclasses to set self._daemon_location before
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
