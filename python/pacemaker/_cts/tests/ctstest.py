"""Base classes for CTS tests."""

__all__ = ["CTSTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re

from pacemaker._cts import logging
from pacemaker._cts.environment import EnvFactory
from pacemaker._cts.remote import RemoteFactory
from pacemaker._cts.timer import Timer
from pacemaker._cts.watcher import LogWatcher

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.


class CTSTest:
    """
    The base class for all cluster tests.

    This implements a basic set of properties and behaviors like setup, tear
    down, time keeping, and statistics tracking.  It is up to specific tests
    to implement their own specialized behavior on top of this class.
    """

    def __init__(self, cm):
        """
        Create a new CTSTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        # pylint: disable=invalid-name

        self.audits = []
        self.name = None

        self.stats = {
            "auditfail": 0,
            "calls": 0,
            "failure": 0,
            "skipped": 0,
            "success": 0
        }

        self._cm = cm
        self._env = EnvFactory().getInstance()
        self._rsh = RemoteFactory().getInstance()
        self._timers = {}

        self.benchmark = True  # which tests to benchmark
        self.failed = False
        self.is_unsafe = False
        self.passed = True

    def log(self, args):
        """Log a message."""
        logging.log(args)

    def debug(self, args):
        """Log a debug message."""
        logging.debug(args)

    def get_timer(self, key="test"):
        """Get the start time of the given timer."""
        try:
            return self._timers[key].start_time
        except KeyError:
            return 0

    def set_timer(self, key="test"):
        """Set the start time of the given timer to now, and return that time."""
        if key not in self._timers:
            self._timers[key] = Timer(self.name, key)

        self._timers[key].start()
        return self._timers[key].start_time

    def log_timer(self, key="test"):
        """Log the elapsed time of the given timer."""
        if key not in self._timers:
            return

        elapsed = self._timers[key].elapsed
        self.debug(f"{self.name}:{key} runtime: {elapsed:.2f}")
        del self._timers[key]

    def incr(self, name):
        """Increment the given stats key."""
        if name not in self.stats:
            self.stats[name] = 0

        self.stats[name] += 1

        # Reset the test passed boolean
        if name == "calls":
            self.passed = True

    def failure(self, reason="none"):
        """Increment the failure count, with an optional failure reason."""
        self.passed = False
        self.incr("failure")
        logging.log(f"{f'Test {self.name}':<35} FAILED: {reason}")

        return False

    def success(self):
        """Increment the success count."""
        self.incr("success")
        return True

    def skipped(self):
        """Increment the skipped count."""
        self.incr("skipped")
        return True

    def __call__(self, node):
        """Perform this test."""
        raise NotImplementedError

    def audit(self):
        """Perform all the relevant audits (see ClusterAudit), returning whether or not they all passed."""
        passed = True

        for audit in self.audits:
            if not audit():
                logging.log(f"Internal {self.name} Audit {audit.name} FAILED.")
                self.incr("auditfail")
                passed = False

        return passed

    def setup(self, node):
        """Set up this test."""
        # node is used in subclasses
        # pylint: disable=unused-argument

        return self.success()

    def teardown(self, node):
        """Tear down this test."""
        # node is used in subclasses
        # pylint: disable=unused-argument

        return self.success()

    def create_watch(self, patterns, timeout, name=None):
        """
        Create a new LogWatcher object.

        This object can be used to search log files for matching patterns
        during this test's run.

        Arguments:
        patterns -- A list of regular expressions to match against the log
        timeout  -- Default number of seconds to watch a log file at a time;
                    this can be overridden by the timeout= parameter to
                    self.look on an as-needed basis
        name     -- A unique name to use when logging about this watch
        """
        if not name:
            name = self.name

        return LogWatcher(self._env["LogFileName"], patterns,
                          self._env["nodes"], self._env["log_kind"], name,
                          timeout)

    def local_badnews(self, prefix, watch, local_ignore=None):
        """
        Search through log files for messages.

        Arguments:
        prefix       -- The string to look for at the beginning of lines,
                        or "LocalBadNews:" if None.
        watch        -- The LogWatcher object to use for searching.
        local_ignore -- A list of regexes that, if found in a line, will
                        cause that line to be ignored.

        Return the number of matches found.
        """
        errcount = 0
        if not prefix:
            prefix = "LocalBadNews:"

        ignorelist = [" CTS: ", prefix]

        if local_ignore:
            ignorelist += local_ignore

        while errcount < 100:
            match = watch.look(0)
            if match:
                add_err = True

                for ignore in ignorelist:
                    if add_err and re.search(ignore, match):
                        add_err = False

                if add_err:
                    logging.log(f"{prefix} {match}")
                    errcount += 1
            else:
                break
        else:
            logging.log("Too many errors!")

        watch.end()
        return errcount

    def is_applicable(self):
        """
        Return True if this test is applicable in the current test configuration.

        This method must be implemented by all subclasses.
        """
        if self.is_unsafe and not self._env["unsafe-tests"]:
            return False

        if self._env["benchmark"] and not self.benchmark:
            return False

        return True

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return []
