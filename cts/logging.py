'''
Classes related to producing logs
'''

__copyright__='''
Copyright (C) 2014 Andrew Beekhof <andrew@beekhof.net>
Licensed under the GNU GPL.
'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

import types, string, sys, time, re, os, syslog

class Logger:
    TimeFormat = "%b %d %H:%M:%S\t"

    def __call__(self, lines):
        raise ValueError("Abstract class member (__call__)")
    def write(self, line):
        return self(line.rstrip())
    def writelines(self, lines):
        for s in lines:
            self.write(s)
        return 1
    def flush(self):
        return 1
    def isatty(self):
        return None

class StdErrLog(Logger):

    def __init__(self, filename, tag):
        pass

    def __call__(self, lines):
        t = time.strftime(Logger.TimeFormat, time.localtime(time.time()))
        if isinstance(lines, types.StringType):
            sys.__stderr__.writelines([t, lines, "\n"])
        else:
            for line in lines:
                sys.__stderr__.writelines([t, line, "\n"])
        sys.__stderr__.flush()

    def name(self):
        return "StdErrLog"

class FileLog(Logger):
    def __init__(self, filename, tag):
        self.logfile=filename
        import os
        self.hostname = os.uname()[1]+" "

        self.source = ""
        if tag:
            self.source = tag+": "

    def __call__(self, lines):

        fd = open(self.logfile, "a")
        t = time.strftime(Logger.TimeFormat, time.localtime(time.time()))

        if isinstance(lines, types.StringType):
            fd.writelines([t, self.hostname, self.source, lines, "\n"])
        else:
            for line in lines:
                fd.writelines([t, self.hostname, self.source, line, "\n"])
        fd.close()

    def name(self):
        return "FileLog"

class LogFactory:

    log_methods=[]
    have_stderr = False

    def __init__(self):
        pass

    def add_file(self, filename, tag=None):
        if filename:
            LogFactory.log_methods.append(FileLog(filename, tag))

    def add_stderr(self):
        if not LogFactory.have_stderr:
            LogFactory.have_stderr = True
            LogFactory.log_methods.append(StdErrLog(None, None))

    def log(self, args):
        for logfn in LogFactory.log_methods:
            logfn(string.strip(args))

    def debug(self, args):
        for logfn in LogFactory.log_methods:
            if logfn.name() != "StdErrLog":
                logfn("debug: %s" % string.strip(args))

    def traceback(self, traceback):
        for logfn in LogFactory.log_methods:
            traceback.print_exc(50, logfn)
