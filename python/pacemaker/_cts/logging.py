""" Logging classes for Pacemaker's Cluster Test Suite (CTS) """

__all__ = ["LogFactory"]
__copyright__ = "Copyright 2014-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import os
import sys
import time


class Logger:
    """ Abstract class to use as parent for CTS logging classes """

    TimeFormat = "%b %d %H:%M:%S\t"

    def __init__(self, filename=None, tag=None):
        # Whether this logger should print debug messages
        self._debug_target = True

        self._logfile = filename

        if tag:
            self._source = "%s: " % tag
        else:
            self._source = ""

    def __call__(self, lines):
        """ Log specified messages """

        raise ValueError("Abstract class member (__call__)")

    def write(self, line):
        """ Log a single line excluding trailing whitespace """

        return self(line.rstrip())

    def writelines(self, lines):
        """ Log a series of lines excluding trailing whitespace """

        for line in lines:
            self.write(line)

    @property
    def is_debug_target(self):
        """ Return True if this logger should receive debug messages """

        return self._debug_target


class StdErrLog(Logger):
    """ Class to log to standard error """

    def __init__(self, filename, tag):
        Logger.__init__(self, filename, tag)
        self._debug_target = False

    def __call__(self, lines):
        """ Log specified lines to stderr """

        timestamp = time.strftime(Logger.TimeFormat,
                                  time.localtime(time.time()))
        if isinstance(lines, str):
            lines = [lines]

        for line in lines:
            print("%s%s" % (timestamp, line), file=sys.__stderr__)

        sys.__stderr__.flush()


class FileLog(Logger):
    """ Class to log to a file """

    def __init__(self, filename, tag):
        Logger.__init__(self, filename, tag)
        self._hostname = os.uname()[1]

    def __call__(self, lines):
        """ Log specified lines to the file """

        with open(self._logfile, "at", encoding="utf-8") as logf:
            timestamp = time.strftime(Logger.TimeFormat,
                                      time.localtime(time.time()))

            if isinstance(lines, str):
                lines = [lines]

            for line in lines:
                print("%s%s %s%s" % (timestamp, self._hostname, self._source, line),
                      file=logf)


class LogFactory:
    """ Singleton to log messages to various destinations """

    log_methods = []
    have_stderr = False

    def add_file(self, filename, tag=None):
        """ When logging messages, log them to specified file """

        if filename:
            LogFactory.log_methods.append(FileLog(filename, tag))

    def add_stderr(self):
        """ When logging messages, log them to standard error """

        if not LogFactory.have_stderr:
            LogFactory.have_stderr = True
            LogFactory.log_methods.append(StdErrLog(None, None))

    def log(self, args):
        """ Log a message (to all configured log destinations) """

        for logfn in LogFactory.log_methods:
            logfn(args.strip())

    def debug(self, args):
        """ Log a debug message (to all configured log destinations) """

        for logfn in LogFactory.log_methods:
            if logfn.is_debug_target:
                logfn("debug: %s" % args.strip())

    def traceback(self, traceback):
        """ Log a stack trace (to all configured log destinations) """

        for logfn in LogFactory.log_methods:
            traceback.print_exc(50, logfn)
