'''
Classes related to searching logs
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

import types, string, select, sys, time, re, os, struct, signal
import time, syslog, random, traceback, base64, pickle, binascii, fcntl
import threading


from cts.remote import *
from cts.logging import *

has_log_watcher = {}
log_watcher_bin = CTSvars.CRM_DAEMON_DIR + "/cts_log_watcher.py"
log_watcher = """
import sys, os, fcntl

'''
Remote logfile reader for CTS
Reads a specified number of lines from the supplied offset
Returns the current offset

Contains logic for handling truncation
'''

limit    = 0
offset   = 0
prefix   = ''
filename = '/var/log/messages'

skipthis=None
args=sys.argv[1:]
for i in range(0, len(args)):
    if skipthis:
        skipthis=None
        continue

    elif args[i] == '-l' or args[i] == '--limit':
        skipthis=1
        limit = int(args[i+1])

    elif args[i] == '-f' or args[i] == '--filename':
        skipthis=1
        filename = args[i+1]

    elif args[i] == '-o' or args[i] == '--offset':
        skipthis=1
        offset = args[i+1]

    elif args[i] == '-p' or args[i] == '--prefix':
        skipthis=1
        prefix = args[i+1]

    elif args[i] == '-t' or args[i] == '--tag':
        skipthis=1

if not os.access(filename, os.R_OK):
    print prefix + 'Last read: %d, limit=%d, count=%d - unreadable' % (0, limit, 0)
    sys.exit(1)

logfile=open(filename, 'r')
logfile.seek(0, os.SEEK_END)
newsize=logfile.tell()

if offset != 'EOF':
    offset = int(offset)
    if newsize >= offset:
        logfile.seek(offset)
    else:
        print prefix + ('File truncated from %d to %d' % (offset, newsize))
        if (newsize*1.05) < offset:
            logfile.seek(0)
        # else: we probably just lost a few logs after a fencing op
        #       continue from the new end
        # TODO: accept a timestamp and discard all messages older than it

# Don't block when we reach EOF
fcntl.fcntl(logfile.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

count = 0
while True:
    if logfile.tell() >= newsize:   break
    elif limit and count >= limit: break

    line = logfile.readline()
    if not line: break

    print line.strip()
    count += 1

print prefix + 'Last read: %d, limit=%d, count=%d' % (logfile.tell(), limit, count)
logfile.close()
"""

class SearchObj:
    def __init__(self, filename, host=None, name=None):

        self.limit = None
        self.cache = []
        self.logger = LogFactory()
        self.host = host
        self.name = name
        self.filename = filename
        self.rsh = RemoteFactory().getInstance()

        self.offset = "EOF"

        if host == None:
            host = "localhost"

    def __str__(self):
        if self.host:
            return "%s:%s" % (self.host, self.filename)
        return self.filename

    def log(self, args):
        message = "lw: %s: %s" % (self, args)
        self.logger.log(message)

    def debug(self, args):
        message = "lw: %s: %s" % (self, args)
        self.logger.debug(message)

    def harvest(self, delegate=None):
        async = self.harvest_async(delegate)
        async.join()

    def harvest_async(self, delegate=None):
        self.log("Not implemented")
        raise

    def end(self):
        self.debug("Unsetting the limit")
        # Unset the limit
        self.limit = None

class FileObj(SearchObj):
    def __init__(self, filename, host=None, name=None):
        global has_log_watcher
        SearchObj.__init__(self, filename, host, name)

        if not has_log_watcher.has_key(host):

            global log_watcher
            global log_watcher_bin

            self.debug("Installing %s on %s" % (log_watcher_bin, host))

            os.system("cat << END >> %s\n%s\nEND" %(log_watcher_bin, log_watcher))
            os.system("chmod 755 %s" %(log_watcher_bin))

            self.rsh.cp(log_watcher_bin, "root@%s:%s" % (host, log_watcher_bin))
            has_log_watcher[host] = 1

        self.harvest()

    def async_complete(self, pid, returncode, outLines, errLines):
        for line in outLines:
            match = re.search("^CTSwatcher:Last read: (\d+)", line)
            if match:
                last_offset = self.offset
                self.offset = match.group(1)
                #if last_offset == "EOF": self.debug("Got %d lines, new offset: %s" % (len(outLines), self.offset))
                self.debug("Got %d lines, new offset: %s  %s" % (len(outLines), self.offset, repr(self.delegate)))

            elif re.search("^CTSwatcher:.*truncated", line):
                self.log(line)
            elif re.search("^CTSwatcher:", line):
                self.debug("Got control line: "+ line)
            else:
                self.cache.append(line)

        if self.delegate:
            self.delegate.async_complete(pid, returncode, self.cache, errLines)

    def harvest_async(self, delegate=None):
        self.delegate = delegate
        self.cache = []

        if self.limit != None and self.offset > self.limit:
            if self.delegate:
                self.delegate.async_complete(-1, -1, [], [])
            return None

        global log_watcher_bin
        return self.rsh.call_async(self.host,
                                   "python %s -t %s -p CTSwatcher: -l 200 -f %s -o %s -t %s" % (log_watcher_bin, self.name, self.filename, self.offset, self.name),
                completionDelegate=self)

    def setend(self):
        if self.limit: 
            return

        global log_watcher_bin
        (rc, lines) = self.rsh(self.host,
                               "python %s -t %s -p CTSwatcher: -l 2 -f %s -o %s -t %s" % (log_watcher_bin, self.name, self.filename, "EOF", self.name),
                 None, silent=True)

        for line in lines:
            match = re.search("^CTSwatcher:Last read: (\d+)", line)
            if match:
                last_offset = self.offset
                self.limit = int(match.group(1))
                #if last_offset == "EOF": self.debug("Got %d lines, new offset: %s" % (len(lines), self.offset))
                self.debug("Set limit to: %d" % self.limit)

        return

class JournalObj(SearchObj):

    def __init__(self, host=None, name=None):
        SearchObj.__init__(self, name, host, name)
        self.harvest()

    def async_complete(self, pid, returncode, outLines, errLines):
        #self.log( "%d returned on %s" % (pid, self.host))
        foundCursor = False
        for line in outLines:
            match = re.search("^-- cursor: ([^.]+)", line)
            if match:
                foundCursor = True
                last_offset = self.offset
                self.offset = match.group(1).strip()
                self.debug("Got %d lines, new cursor: %s" % (len(outLines), self.offset))
            else:
                self.cache.append(line)

        if self.limit and not foundCursor:
            self.hitLimit = True
            self.debug("Got %d lines but no cursor: %s" % (len(outLines), self.offset))
            
            # Get the current cursor
            (rc, outLines) = self.rsh(self.host, "journalctl -q -n 0 --show-cursor", stdout=None, silent=True, synchronous=True)
            for line in outLines:
                match = re.search("^-- cursor: ([^.]+)", line)
                if match:
                    last_offset = self.offset
                    self.offset = match.group(1).strip()
                    self.debug("Got %d lines, new cursor: %s" % (len(outLines), self.offset))
                else:
                    self.log("Not a new cursor: %s" % line)
                    self.cache.append(line)

        if self.delegate:
            self.delegate.async_complete(pid, returncode, self.cache, errLines)

    def harvest_async(self, delegate=None):
        self.delegate = delegate
        self.cache = []

        # Use --lines to prevent journalctl from overflowing the Popen input buffer
        if self.limit and self.hitLimit:
            return None

        elif self.limit:
            command = "journalctl -q --after-cursor='%s' --until '%s' --lines=200 --show-cursor" % (self.offset, self.limit)
        else:
            command = "journalctl -q --after-cursor='%s' --lines=200 --show-cursor" % (self.offset)

        if self.offset == "EOF":
            command = "journalctl -q -n 0 --show-cursor"

        return self.rsh.call_async(self.host, command, completionDelegate=self)

    def setend(self):
        if self.limit: 
            return

        self.hitLimit = False
        (rc, lines) = self.rsh(self.host, "date +'%Y-%m-%d %H:%M:%S'", stdout=None, silent=True)

        for line in lines:
            self.limit = line.strip()
            self.debug("Set limit to: %s" % self.limit)


        return

class LogWatcher(RemoteExec):

    '''This class watches logs for messages that fit certain regular
       expressions.  Watching logs for events isn't the ideal way
       to do business, but it's better than nothing :-)

       On the other hand, this class is really pretty cool ;-)

       The way you use this class is as follows:
          Construct a LogWatcher object
          Call setwatch() when you want to start watching the log
          Call look() to scan the log looking for the patterns
    '''

    def __init__(self, log, regexes, name="Anon", timeout=10, debug_level=None, silent=False, hosts=None, kind=None):
        '''This is the constructor for the LogWatcher class.  It takes a
        log name to watch, and a list of regular expressions to watch for."
        '''
        self.logger = LogFactory()

        self.name        = name
        self.regexes     = regexes
        self.debug_level = debug_level
        self.whichmatch  = -1
        self.unmatched   = None
        self.cache_lock = threading.Lock()

        self.file_list = []
        self.line_cache = []

        #  Validate our arguments.  Better sooner than later ;-)
        for regex in regexes:
            assert re.compile(regex)

        if kind:
            self.kind    = kind
        else:
            raise
            self.kind    = self.Env["LogWatcher"]

        if log:
            self.filename    = log
        else:
            raise
            self.filename    = self.Env["LogFileName"]

        if hosts:
            self.hosts = hosts
        else:
            raise
            self.hosts = self.Env["nodes"]

        if trace_lw:
            self.debug_level = 3
            silent = False

        if not silent:
            for regex in self.regexes:
                self.debug("Looking for regex: "+regex)

        self.Timeout = int(timeout)
        self.returnonlymatch = None

    def debug(self, args):
        message = "lw: %s: %s" % (self.name, args)
        self.logger.debug(message)

    def setwatch(self):
        '''Mark the place to start watching the log from.
        '''

        if self.kind == "remote":
            for node in self.hosts:
                self.file_list.append(FileObj(self.filename, node, self.name))

        elif self.kind == "journal":
            for node in self.hosts:
                self.file_list.append(JournalObj(node, self.name))

        else:
            self.file_list.append(FileObj(self.filename))

        # print "%s now has %d files" % (self.name, len(self.file_list))

    def __del__(self):
        if self.debug_level > 1: self.debug("Destroy")

    def ReturnOnlyMatch(self, onlymatch=1):
        '''Specify one or more subgroups of the match to return rather than the whole string
           http://www.python.org/doc/2.5.2/lib/match-objects.html
        '''
        self.returnonlymatch = onlymatch

    def async_complete(self, pid, returncode, outLines, errLines):
        # TODO: Probably need a lock for updating self.line_cache
        self.logger.debug("%s: Got %d lines from %d (total %d)" % (self.name, len(outLines), pid, len(self.line_cache)))
        if len(outLines):
            self.cache_lock.acquire()
            self.line_cache.extend(outLines)
            self.cache_lock.release()

    def __get_lines(self, timeout):
        count=0
        if not len(self.file_list):
            raise ValueError("No sources to read from")

        pending = []
        #print "%s waiting for %d operations" % (self.name, self.pending)
        for f in self.file_list:
            t = f.harvest_async(self)
            if t:
                pending.append(t)

        for t in pending:
            t.join(60.0)
            if t.isAlive():
                self.logger.log("%s: Aborting after 20s waiting for %s logging commands" % (self.name, repr(t)))
                return

        #print "Got %d lines" % len(self.line_cache)

    def end(self):
        for f in self.file_list:
            f.end()

    def look(self, timeout=None, silent=False):
        '''Examine the log looking for the given patterns.
        It starts looking from the place marked by setwatch().
        This function looks in the file in the fashion of tail -f.
        It properly recovers from log file truncation, but not from
        removing and recreating the log.  It would be nice if it
        recovered from this as well :-)

        We return the first line which matches any of our patterns.
        '''
        if timeout == None: timeout = self.Timeout

        if trace_lw:
            silent = False

        lines=0
        needlines=True
        begin=time.time()
        end=begin+timeout+1
        if self.debug_level > 2: self.debug("starting single search: timeout=%d, begin=%d, end=%d" % (timeout, begin, end))

        if not self.regexes:
            self.debug("Nothing to look for")
            return None

        if timeout == 0:
            for f in self.file_list:
                f.setend()

        while True:
            if len(self.line_cache):
                lines += 1

                self.cache_lock.acquire()
                line = self.line_cache[0]
                self.line_cache.remove(line)
                self.cache_lock.release()

                which=-1
                if re.search("CTS:", line):
                    continue
                if self.debug_level > 2: self.debug("Processing: "+ line)
                for regex in self.regexes:
                    which=which+1
                    if self.debug_level > 3: self.debug("Comparing line to: "+ regex)
                    #matchobj = re.search(string.lower(regex), string.lower(line))
                    matchobj = re.search(regex, line)
                    if matchobj:
                        self.whichmatch=which
                        if self.returnonlymatch:
                            return matchobj.group(self.returnonlymatch)
                        else:
                            self.debug("Matched: "+line)
                            if self.debug_level > 1: self.debug("With: "+ regex)
                            return line

            elif timeout > 0 and end < time.time():
                if self.debug_level > 1: self.debug("hit timeout: %d" % timeout)

                timeout = 0
                for f in self.file_list:
                    f.setend()

            else:
                self.__get_lines(timeout)
                if len(self.line_cache) == 0 and end < time.time():
                    self.debug("Single search terminated: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), lines))
                    return None
                else:
                    self.debug("Waiting: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), len(self.line_cache)))
                    time.sleep(1)

        self.debug("How did we get here")
        return None

    def lookforall(self, timeout=None, allow_multiple_matches=None, silent=False):
        '''Examine the log looking for ALL of the given patterns.
        It starts looking from the place marked by setwatch().

        We return when the timeout is reached, or when we have found
        ALL of the regexes that were part of the watch
        '''

        if timeout == None: timeout = self.Timeout
        save_regexes = self.regexes
        returnresult = []

        if trace_lw:
            silent = False

        if not silent:
            self.debug("starting search: timeout=%d" % timeout)
            for regex in self.regexes:
                if self.debug_level > 2: self.debug("Looking for regex: "+regex)

        while (len(self.regexes) > 0):
            oneresult = self.look(timeout)
            if not oneresult:
                self.unmatched = self.regexes
                self.matched = returnresult
                self.regexes = save_regexes
                self.end()
                return None

            returnresult.append(oneresult)
            if not allow_multiple_matches:
                del self.regexes[self.whichmatch]

            else:
                # Allow multiple regexes to match a single line
                tmp_regexes = self.regexes
                self.regexes = []
                which = 0
                for regex in tmp_regexes:
                    matchobj = re.search(regex, oneresult)
                    if not matchobj:
                        self.regexes.append(regex)

        self.unmatched = None
        self.matched = returnresult
        self.regexes = save_regexes
        return returnresult

