"""Logging classes for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["add_file", "add_stderr", "log", "debug", "traceback"]
__copyright__ = "Copyright 2014-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import os
import sys
import time


_log_methods = []
_HAVE_STDERR = False


def add_file(filename):
    """When logging messages, log them to specified file."""
    if filename:
        _log_methods.append(FileLog(filename))


def add_stderr():
    """When logging messages, log them to standard error."""
    # pylint: disable=global-statement
    global _HAVE_STDERR

    if not _HAVE_STDERR:
        _HAVE_STDERR = True
        _log_methods.append(StdErrLog(None))


def log(args):
    """Log a message (to all configured log destinations)."""
    for logfn in _log_methods:
        logfn(args.strip())


def debug(args):
    """Log a debug message (to all configured log destinations)."""
    for logfn in _log_methods:
        if logfn.is_debug_target:
            logfn(f"debug: {args.strip()}")


def traceback(traceback_obj):
    """Log a stack trace (to all configured log destinations)."""
    for logfn in _log_methods:
        traceback_obj.print_exc(50, logfn)


class Logger:
    """Abstract class to use as parent for CTS logging classes."""

    TimeFormat = "%b %d %H:%M:%S\t"

    def __init__(self, filename=None):
        # Whether this logger should print debug messages
        self._debug_target = True

        self._logfile = filename

    def __call__(self, lines):
        """Log specified messages."""
        raise ValueError("Abstract class member (__call__)")

    def write(self, line):
        """Log a single line excluding trailing whitespace."""
        return self(line.rstrip())

    def writelines(self, lines):
        """Log a series of lines excluding trailing whitespace."""
        for line in lines:
            self.write(line)

    @property
    def is_debug_target(self):
        """Return True if this logger should receive debug messages."""
        return self._debug_target


class StdErrLog(Logger):
    """Class to log to standard error."""

    def __init__(self, filename):
        Logger.__init__(self, filename)
        self._debug_target = False

    def __call__(self, lines):
        """Log specified lines to stderr."""
        timestamp = time.strftime(Logger.TimeFormat,
                                  time.localtime(time.time()))
        if isinstance(lines, str):
            lines = [lines]

        for line in lines:
            print(f"{timestamp}{line}", file=sys.__stderr__)

        sys.__stderr__.flush()


class FileLog(Logger):
    """Class to log to a file."""

    def __init__(self, filename):
        Logger.__init__(self, filename)
        self._hostname = os.uname()[1]

    def __call__(self, lines):
        """Log specified lines to the file."""
        with open(self._logfile, "at", encoding="utf-8") as logf:
            timestamp = time.strftime(Logger.TimeFormat,
                                      time.localtime(time.time()))

            if isinstance(lines, str):
                lines = [lines]

            for line in lines:
                print(f"{timestamp}{self._hostname} {line}", file=logf)
