""" Logging classes for Pacemaker's Cluster Test Suite (CTS)
"""

# Pacemaker targets compatibility with Python 2.6+ and 3.2+
from __future__ import print_function, unicode_literals, absolute_import, division

__copyright__ = "Copyright (C) 2014-2016 Andrew Beekhof <andrew@beekhof.net>"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import io
import os
import sys
import time


# Wrapper to detect a string under Python 2 or 3
try:
    _StringType = basestring
except NameError:
    _StringType = str

def _is_string(obj):
    """ Return True if obj is a simple string. """

    return isinstance(obj, _StringType)


def _strip(line):
    """ Wrapper for strip() that works regardless of Python version """

    if sys.version_info < (3,):
        return line.decode('utf-8').strip()
    else:
        return line.strip()


def _rstrip(line):
    """ Wrapper for rstrip() that works regardless of Python version """

    if sys.version_info < (3,):
        return line.decode('utf-8').rstrip()
    else:
        return line.rstrip()


class Logger(object):
    """ Abstract class to use as parent for CTS logging classes """

    TimeFormat = "%b %d %H:%M:%S\t"

    def __init__(self):
        # Whether this logger should print debug messages
        self.debug_target = True

    def __call__(self, lines):
        """ Log specified messages """

        raise ValueError("Abstract class member (__call__)")

    def write(self, line):
        """ Log a single line excluding trailing whitespace """

        return self(_rstrip(line))

    def writelines(self, lines):
        """ Log a series of lines excluding trailing whitespace """

        for line in lines:
            self.write(line)
        return 1

    def is_debug_target(self):
        """ Return True if this logger should receive debug messages """

        return self.debug_target


class StdErrLog(Logger):
    """ Class to log to standard error """

    def __init__(self, filename, tag):
        Logger.__init__(self)
        self.debug_target = False

    def __call__(self, lines):
        """ Log specified lines to stderr """

        timestamp = time.strftime(Logger.TimeFormat,
                                  time.localtime(time.time()))
        if _is_string(lines):
            lines = [lines]
        for line in lines:
            print("%s%s" % (timestamp, line), file=sys.__stderr__)
        sys.__stderr__.flush()


class FileLog(Logger):
    """ Class to log to a file """

    def __init__(self, filename, tag):
        Logger.__init__(self)
        self.logfile = filename
        self.hostname = os.uname()[1]
        if tag:
            self.source = tag + ": "
        else:
            self.source = ""

    def __call__(self, lines):
        """ Log specified lines to the file """

        logf = io.open(self.logfile, "at")
        timestamp = time.strftime(Logger.TimeFormat,
                                  time.localtime(time.time()))
        if _is_string(lines):
            lines = [lines]
        for line in lines:
            print("%s%s %s%s" % (timestamp, self.hostname, self.source, line),
                  file=logf)
        logf.close()


class LogFactory(object):
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
            logfn(_strip(args))

    def debug(self, args):
        """ Log a debug message (to all configured log destinations) """

        for logfn in LogFactory.log_methods:
            if logfn.is_debug_target():
                logfn("debug: %s" % _strip(args))

    def traceback(self, traceback):
        """ Log a stack trace (to all configured log destinations) """

        for logfn in LogFactory.log_methods:
            traceback.print_exc(50, logfn)
