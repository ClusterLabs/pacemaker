""" A module providing base classes for defining regression tests and groups of
    regression tests.  Everything exported here should be considered an abstract
    class that needs to be subclassed in order to do anything useful.  Various
    functions will raise NotImplementedError if not overridden by a subclass.
"""

__copyright__ = "Copyright 2009-2023 the Pacemaker project contributors"
__license__ = "LGPLv2.1+"

__all__ = ["Test", "Tests"]

import io
import os
import re
import shlex
import signal
import subprocess
import sys
import time

from pacemaker._cts.errors import ExitCodeError, OutputFoundError, OutputNotFoundError, XmlValidationError
from pacemaker._cts.process import pipe_communicate
from pacemaker.buildoptions import BuildOptions
from pacemaker.exitstatus import ExitStatus

def find_validator(rng_file):
    """ Return the command line used to validate XML output, or None if the validator
        is not installed.
    """

    if os.access("/usr/bin/xmllint", os.X_OK):
        if rng_file is None:
            return ["xmllint", "-"]

        return ["xmllint", "--relaxng", rng_file, "-"]

    return None


def rng_directory():
    """ Which directory contains the RNG schema files? """

    if "PCMK_schema_directory" in os.environ:
        return os.environ["PCMK_schema_directory"]

    if os.path.exists("%s/cts-fencing.in" % sys.path[0]):
        return "xml"

    return BuildOptions.SCHEMA_DIR


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
        self._daemon_output = ""
        self._daemon_process = None

        self._log_patterns = []
        self._negative_log_patterns = []

        self._result_exitcode = ExitStatus.OK
        self._result_txt = ""

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

    def _count_negative_matches(self, outline):
        """ Return 1 if a line matches patterns that shouldn't have occurred """

        count = 0
        for line in self._negative_log_patterns:
            if outline.count(line):
                count = 1
                if self.verbose:
                    print("This pattern should not have matched = '%s" % line)

        return count

    def _kill_daemons(self):
        """ Kill any running daemons in preparation for executing the test """
        raise NotImplementedError("_kill_daemons not provided by subclass")

    def _match_log_patterns(self):
        """ Check test output for expected patterns, setting self.exitcode and
            self._result_txt as appropriate.  Not all subclass will need to do
            this.
        """
        if len(self._log_patterns) == 0 and len(self._negative_log_patterns) == 0:
            return

        negative_matches = 0
        cur = 0
        pats = self._log_patterns
        total_patterns = len(self._log_patterns)

        for line in self._daemon_output.split("\n"):
            negative_matches += self._count_negative_matches(line)

            if len(pats) == 0:
                continue

            cur = -1
            for pat in pats:
                cur += 1
                if line.count(pats[cur]):
                    del pats[cur]
                    break

        if len(pats) > 0 or negative_matches:
            if self.verbose:
                for pat in pats:
                    print("Pattern Not Matched = '%s'" % pat)

            msg = "FAILURE - '%s' failed. %d patterns out of %d not matched. %d negative matches."
            self._result_txt = msg % (self.name, len(pats), total_patterns, negative_matches)
            self.exitcode = ExitStatus.ERROR

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

    def _start_daemons(self):
        """ Start any necessary daemons in preparation for executing the test """
        raise NotImplementedError("_start_daemons not provided by subclass")

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

    def add_log_pattern(self, pattern):
        """ Add a pattern that should appear in the test's logs """

        self._log_patterns.append(pattern)

    def add_negative_log_pattern(self, pattern):
        """ Add a pattern that should not occur in the test's logs """

        self._negative_log_patterns.append(pattern)

    def clean_environment(self):
        """ Clean up the host after executing a test """

        if self._daemon_process:
            if self._daemon_process.poll() is None:
                self._daemon_process.terminate()
                self._daemon_process.wait()
            else:
                return_code = {
                    getattr(signal, _signame): _signame
                        for _signame in dir(signal)
                        if _signame.startswith('SIG') and not _signame.startswith("SIG_")
                }.get(-self._daemon_process.returncode, "RET=%d" % (self._daemon_process.returncode))
                msg = "FAILURE - '%s' failed. %s abnormally exited during test (%s)."
                self._result_txt = msg % (self.name, self._daemon_location, return_code)
                self.exitcode = ExitStatus.ERROR

        self._daemon_process = None
        self._daemon_output = ""

        # the default for utf-8 encoding would error out if e.g. memory corruption
        # makes fenced output any kind of 8 bit value - while still interesting
        # for debugging and we'd still like the regression-test to go over the
        # full set of test-cases
        with open(self.logpath, 'rt', encoding = "ISO-8859-1") as logfile:
            for line in logfile.readlines():
                self._daemon_output += line

        if self.verbose:
            print("Daemon Output Start")
            print(self._daemon_output)
            print("Daemon Output End")

    def print_result(self, filler):
        """ Print the result of the last test execution """

        print("%s%s" % (filler, self._result_txt))

    def run(self):
        """ Execute this test """

        i = 1

        self.start_environment()

        if self.verbose:
            print("\n--- START TEST - %s" % self.name)

        self._result_txt = "SUCCESS - '%s'" % (self.name)
        self.exitcode = ExitStatus.OK

        for cmd in self._cmds:
            try:
                self.run_cmd(cmd)
            except ExitCodeError as e:
                print("Step %d FAILED - command returned %s, expected %d" % (i, e, cmd['expected_exitcode']))
                self.set_error(i, cmd)
                break
            except OutputNotFoundError as e:
                print("Step %d FAILED - '%s' was not found in command output: %s" % (i, cmd['stdout_match'], e))
                self.set_error(i, cmd)
                break
            except OutputFoundError as e:
                print("Step %d FAILED - '%s' was found in command output: %s" % (i, cmd['stdout_negative_match'], e))
                self.set_error(i, cmd)
                break
            except XmlValidationError as e:
                print("Step %d FAILED - xmllint failed: %s" % (i, e))
                self.set_error(i, cmd)
                break

            if self.verbose:
                print("Step %d SUCCESS" % (i))

            i = i + 1

        self.clean_environment()

        if self.exitcode == ExitStatus.OK:
            self._match_log_patterns()

        print(self._result_txt)
        if self.verbose:
            print("--- END TEST - %s\n" % self.name)

        self.executed = True

    def run_cmd(self, args):
        """ Execute a command as part of this test """

        cmd = shlex.split(args['args'])
        cmd.insert(0, args['cmd'])

        if self.verbose:
            print("\n\nRunning: %s" % " ".join(cmd))

        # FIXME: Using "with" here breaks fencing merge tests.
        # pylint: disable=consider-using-with
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
                raise XmlValidationError("Could not find validator for %s" % rng_file)

            if self.verbose:
                print("\nRunning: %s" % " ".join(cmd))

            with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as validator:
                output = pipe_communicate(validator, check_stderr=True, stdin=output)

                if self.verbose:
                    print(output)

                if validator.returncode != 0:
                    raise XmlValidationError(output)

        return ExitStatus.OK

    def set_error(self, step, cmd):
        """ Record failure of this test """

        msg = "FAILURE - '%s' failed at step %d. Command: %s %s"
        self._result_txt = msg % (self.name, step, cmd['cmd'], cmd['args'])
        self.exitcode = ExitStatus.ERROR

    def start_environment(self):
        """ Prepare the host for executing a test """

        if os.path.exists(self.logpath):
            os.remove(self.logpath)

        self._kill_daemons()
        self._start_daemons()

        logfile = None

        init_time = time.time()
        update_time = init_time

        while True:
            # FIXME: Eventually use 'with' here, which seems complicated given
            # everything happens in a loop.
            # pylint: disable=consider-using-with
            time.sleep(0.1)

            if not self.force_wait and logfile is None \
               and os.path.exists(self.logpath):
                logfile = io.open(self.logpath, 'rt', encoding = "ISO-8859-1")

            if not self.force_wait and logfile is not None:
                for line in logfile.readlines():
                    if "successfully started" in line:
                        return

            now = time.time()

            if self.timeout > 0 and (now - init_time) >= self.timeout:
                if not self.force_wait:
                    print("\tDaemon %s doesn't seem to have been initialized within %fs."
                          "\n\tConsider specifying a longer '--timeout' value."
                          %(self._daemon_location, self.timeout))
                return

            if self.verbose and (now - update_time) >= 5:
                print("Waiting for %s to be initialized: %fs ..."
                      %(self._daemon_location, now - init_time))
                update_time = now


class Tests:
    """ The base class for a collection of regression tests """

    def __init__(self, **kwargs):
        """ Create a new Tests instance.  This method must be provided by all
            subclasses, which must call Tests.__init__ first.

            Keywork arguments:

            force_wait  --
            logdir      -- The base directory under which to create a directory
                           to store output and temporary data.
            timeout     -- How long to wait for the test to complete.
            verbose     -- Whether to print additional information, including
                           verbose command output and daemon log files.
        """

        self.force_wait = kwargs.get("force_wait", False)
        self.logdir = kwargs.get("logdir", "/tmp")
        self.timeout = kwargs.get("timeout", 2)
        self.verbose = kwargs.get("verbose", False)

        self._tests = []

    def exit(self):
        """ Exit (with error status code if any test failed) """

        for test in self._tests:
            if not test.executed:
                continue

            if test.exitcode != ExitStatus.OK:
                sys.exit(ExitStatus.ERROR)

        sys.exit(ExitStatus.OK)

    def print_list(self):
        """ List all registered tests """

        print("\n==== %d TESTS FOUND ====" % len(self._tests))
        print("%35s - %s" % ("TEST NAME", "TEST DESCRIPTION"))
        print("%35s - %s" % ("--------------------", "--------------------"))

        for test in self._tests:
            print("%35s - %s" % (test.name, test.description))

        print("==== END OF LIST ====\n")

    def print_results(self):
        """ Print summary of results of executed tests """

        failures = 0
        success = 0

        print("\n\n======= FINAL RESULTS ==========")
        print("\n--- FAILURE RESULTS:")

        for test in self._tests:
            if not test.executed:
                continue

            if test.exitcode != ExitStatus.OK:
                failures = failures + 1
                test.print_result("    ")
            else:
                success = success + 1

        if failures == 0:
            print("    None")

        print("\n--- TOTALS\n    Pass:%d\n    Fail:%d\n" % (success, failures))

    def run_single(self, name):
        """ Run a single named test """

        for test in self._tests:
            if test.name == name:
                test.run()
                break

    def run_tests(self):
        """ Run all tests """

        for test in self._tests:
            test.run()

    def run_tests_matching(self, pattern):
        """ Run all tests whose name matches a pattern """

        for test in self._tests:
            if test.name.count(pattern) != 0:
                test.run()
