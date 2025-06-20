"""
A module providing base classes.

These classes are used for defining regression tests and groups of regression
tests.  Everything exported here should be considered an abstract class that
needs to be subclassed in order to do anything useful.  Various functions
will raise NotImplementedError if not overridden by a subclass.
"""

__copyright__ = "Copyright 2009-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+)"

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
from pacemaker._cts.validate import validate
from pacemaker.exitstatus import ExitStatus


class Pattern:
    """A class for checking log files for a given pattern."""

    def __init__(self, pat, negative=False, regex=False):
        """
        Create a new Pattern instance.

        Arguments:
        pat      -- The string to search for
        negative -- If True, pat must not be found in any input
        regex    -- If True, pat is a regex and not a substring
        """
        self._pat = pat
        self.negative = negative
        self.regex = regex

    def __str__(self):
        return self._pat

    def match(self, line):
        """Return True if this pattern is found in the given line."""
        if self.regex:
            return re.search(self._pat, line) is not None

        return self._pat in line


class Test:
    """
    The base class for a single regression test.

    A single regression test may still run multiple commands as part of its
    execution.
    """

    def __init__(self, name, description, **kwargs):
        """
        Create a new Test instance.

        This method must be provided by all subclasses, which must call
        Test.__init__ first.

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
        self._patterns = []

        self._daemon_location = None
        self._daemon_output = ""
        self._daemon_process = None

        self._result_exitcode = ExitStatus.OK
        self._result_txt = ""

    #
    # PROPERTIES
    #

    @property
    def exitcode(self):
        """
        Return the final exitcode of the Test.

        If all commands pass, this property will be ExitStatus.OK.  Otherwise,
        this property will be the exitcode of the first command to fail.
        """
        return self._result_exitcode

    @exitcode.setter
    def exitcode(self, value):
        self._result_exitcode = value

    @property
    def logpath(self):
        """
        Return the path to the log for whatever daemon is being tested.

        Note that this requires all subclasses to set self._daemon_location
        before accessing this property or an exception will be raised.
        """
        return os.path.join(self.logdir, f"{self._daemon_location}.log")

    #
    # PRIVATE METHODS
    #

    def _kill_daemons(self):
        """Kill any running daemons in preparation for executing the test."""
        raise NotImplementedError("_kill_daemons not provided by subclass")

    def _match_log_patterns(self):
        """
        Check test output for expected patterns.

        Set self.exitcode and self._result_txt as appropriate.  Not all subclass
        will need to do this.
        """
        if len(self._patterns) == 0:
            return

        n_failed_matches = 0
        n_negative_matches = 0

        output = self._daemon_output.split("\n")

        for pat in self._patterns:
            positive_match = False

            for line in output:
                if pat.match(line):
                    if pat.negative:
                        n_negative_matches += 1

                        if self.verbose:
                            print(f"This pattern should not have matched = '{pat}'")

                        break

                    positive_match = True
                    break

            if not pat.negative and not positive_match:
                n_failed_matches += 1
                print(f"Pattern Not Matched = '{pat}'")

        if n_failed_matches > 0 or n_negative_matches > 0:
            msg = "FAILURE - '%s' failed. %d patterns out of %d not matched. %d negative matches."
            self._result_txt = msg % (self.name, n_failed_matches, len(self._patterns), n_negative_matches)
            self.exitcode = ExitStatus.ERROR

    def _start_daemons(self):
        """Start any necessary daemons in preparation for executing the test."""
        raise NotImplementedError("_start_daemons not provided by subclass")

    #
    # PUBLIC METHODS
    #

    def add_cmd(self, cmd=None, **kwargs):
        """
        Add a command to be executed as part of this test.

        Arguments:
        cmd         -- The program to run.

        Keyword arguments:
        args                -- Commands line arguments to pass to cmd, as a string.
        check_rng           -- If True and validate is True, command output will
                               additionally be checked against the api-result.rng file.
        check_stderr        -- If True, the stderr of cmd will be included in output.
        env                 -- If not None, variables to set in the environment
        expected_exitcode   -- The expected exit code of cmd.  This can be used to run
                               a command that is expected to fail.
        kill                -- A command to be run after cmd, typically in order to
                               kill a failed process.  This should be the entire
                               command line including arguments as a single string.
        no_wait             -- Do not wait for cmd to complete.
        stdout_match        -- If not None, a string that is expected to be present
                               in the stdout of cmd.  This can be a regular
                               expression.
        stdout_no_match     -- If not None, a string that is expected to be missing
                               in the stdout of cmd.  This can be a regular
                               expression.
        validate            -- If True, the output of cmd will be passed to xmllint
                               for validation.  If validation fails,
                               XmlValidationError will be raised.
        """
        if cmd is None:
            raise ValueError("cmd cannot be None")

        self._cmds.append(
            {
                "args": kwargs.get("args", ""),
                "check_rng": kwargs.get("check_rng", True),
                "check_stderr": kwargs.get("check_stderr", True),
                "cmd": cmd,
                "expected_exitcode": kwargs.get("expected_exitcode", ExitStatus.OK),
                "kill": kwargs.get("kill"),
                "no_wait": kwargs.get("no_wait", False),
                "stdout_match": kwargs.get("stdout_match"),
                "stdout_no_match": kwargs.get("stdout_no_match"),
                "validate": kwargs.get("validate", True),
                "env": kwargs.get("env"),
            }
        )

    def add_log_pattern(self, pattern, negative=False, regex=False):
        """Add a pattern that should appear in the test's logs."""
        self._patterns.append(Pattern(pattern, negative=negative, regex=regex))

    def _signal_dict(self):
        """Return a dictionary mapping signal numbers to their names."""
        # FIXME: When we support python >= 3.5, this function can be replaced with:
        #   signal.Signals(self.daemon_process.returncode).name
        return {
            getattr(signal, _signame): _signame
            for _signame in dir(signal)
            if _signame.startswith("SIG") and not _signame.startswith("SIG_")
        }

    def clean_environment(self):
        """Clean up the host after executing a test."""
        if self._daemon_process:
            if self._daemon_process.poll() is None:
                self._daemon_process.terminate()
                self._daemon_process.wait()
            else:
                rc = self._daemon_process.returncode
                signame = self._signal_dict().get(-rc, f"RET={rc}")
                msg = "FAILURE - '%s' failed. %s abnormally exited during test (%s)."

                self._result_txt = msg % (self.name, self._daemon_location, signame)
                self.exitcode = ExitStatus.ERROR

        self._daemon_process = None
        self._daemon_output = ""

        # the default for utf-8 encoding would error out if e.g. memory corruption
        # makes fenced output any kind of 8 bit value - while still interesting
        # for debugging and we'd still like the regression-test to go over the
        # full set of test-cases
        with open(self.logpath, 'rt', encoding="ISO-8859-1") as logfile:
            for line in logfile.readlines():
                self._daemon_output += line

        if self.verbose:
            print("Daemon Output Start")
            print(self._daemon_output)
            print("Daemon Output End")

    def print_result(self, filler):
        """Print the result of the last test execution."""
        print(f"{filler}{self._result_txt}")

    def run(self):
        """Execute this test."""
        i = 1

        self.start_environment()

        if self.verbose:
            print(f"\n--- START TEST - {self.name}")

        self._result_txt = f"SUCCESS - '{self.name}'"
        self.exitcode = ExitStatus.OK

        for cmd in self._cmds:
            try:
                self.run_cmd(cmd)
            except ExitCodeError as e:
                print(f"Step {i} FAILED - command returned {e}, expected {cmd['expected_exitcode']}")
                self.set_error(i, cmd)
                break
            except OutputNotFoundError as e:
                print(f"""Step {i} FAILED - '{cmd["stdout_match"]}' was not found in command output: {e}""")
                self.set_error(i, cmd)
                break
            except OutputFoundError as e:
                print(f"""Step {i} FAILED - '{cmd["stdout_no_match"]}' was found in command output: {e}""")
                self.set_error(i, cmd)
                break
            except XmlValidationError as e:
                print(f"Step {i} FAILED - xmllint failed: {e}")
                self.set_error(i, cmd)
                break

            if self.verbose:
                print(f"Step {i} SUCCESS")

            i += 1

        self.clean_environment()

        if self.exitcode == ExitStatus.OK:
            self._match_log_patterns()

        print(self._result_txt)
        if self.verbose:
            print(f"--- END TEST - {self.name}\n")

        self.executed = True

    def run_cmd(self, args):
        """Execute a command as part of this test."""
        cmd = shlex.split(args['args'])
        cmd.insert(0, args['cmd'])

        if self.verbose:
            s = " ".join(cmd)
            print(f"\n\nRunning: {s}")

        # FIXME: Using "with" here breaks fencing merge tests.
        # pylint: disable=consider-using-with
        if args['env']:
            new_env = os.environ.copy()
            new_env.update(args['env'])
            test = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=new_env)
        else:
            test = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if args['kill']:
            if self.verbose:
                print(f"Also running: {args['kill']}")

            # Typically, the kill argument is used to detect some sort of
            # failure. Without yielding for a few seconds here, the process
            # launched earlier that is listening for the failure may not have
            # time to connect to pacemaker-execd.
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

        if args['stdout_no_match'] is not None and \
           re.search(args['stdout_no_match'], output) is not None:
            raise OutputFoundError(output)

        if args['validate']:
            output = validate(output, args['check_rng'], self.verbose)

            if self.verbose:
                print(output)

        return ExitStatus.OK

    def set_error(self, step, cmd):
        """Record failure of this test."""
        msg = "FAILURE - '%s' failed at step %d. Command: %s %s"
        self._result_txt = msg % (self.name, step, cmd['cmd'], cmd['args'])
        self.exitcode = ExitStatus.ERROR

    def start_environment(self):
        """Prepare the host for executing a test."""
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
                logfile = io.open(self.logpath, 'rt', encoding="ISO-8859-1")

            if not self.force_wait and logfile is not None:
                for line in logfile.readlines():
                    if "successfully started" in line:
                        return

            now = time.time()

            if self.timeout > 0 and (now - init_time) >= self.timeout:
                if not self.force_wait:
                    print(f"\tDaemon {self._daemon_location} doesn't seem to have "
                          f"been initialized within {self.timeout}s.\n\tConsider "
                          "specifying a longer '--timeout' value.")
                return

            if self.verbose and (now - update_time) >= 5:
                print(f"Waiting for {self._daemon_location} to be initialized: "
                      f"{now - init_time}s ...")
                update_time = now


class Tests:
    """The base class for a collection of regression tests."""

    def __init__(self, **kwargs):
        """
        Create a new Tests instance.

        This method must be provided by all subclasses, which must call
        Tests.__init__ first.

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
        """Exit (with error status code if any test failed)."""
        for test in self._tests:
            if not test.executed:
                continue

            if test.exitcode != ExitStatus.OK:
                sys.exit(ExitStatus.ERROR)

        sys.exit(ExitStatus.OK)

    def print_list(self):
        """List all registered tests."""
        print(f"\n==== {len(self._tests)} TESTS FOUND ====")
        s = "TEST NAME"
        print(f"{s:35} - TEST DESCRIPTION")
        s = "--------------------"
        print(f"{s:35} - {s}")

        for test in self._tests:
            print(f"{test.name:35} - {test.description}")

        print("==== END OF LIST ====\n")

    def print_results(self):
        """Print summary of results of executed tests."""
        failures = 0
        success = 0

        print("\n\n======= FINAL RESULTS ==========")
        print("\n--- FAILURE RESULTS:")

        for test in self._tests:
            if not test.executed:
                continue

            if test.exitcode != ExitStatus.OK:
                failures += 1
                test.print_result("    ")
            else:
                success += 1

        if failures == 0:
            print("    None")

        print(f"\n--- TOTALS\n    Pass:{success}\n    Fail:{failures}\n")

    def run_single(self, name):
        """Run a single named test."""
        for test in self._tests:
            if test.name == name:
                test.run()
                break

    def run_tests(self):
        """Run all tests."""
        for test in self._tests:
            test.run()

    def run_tests_matching(self, pattern):
        """Run all tests whose name matches a pattern."""
        for test in self._tests:
            if test.name.count(pattern) != 0:
                test.run()
