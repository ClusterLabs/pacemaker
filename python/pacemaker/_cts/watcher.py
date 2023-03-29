""" Log searching classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2014-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import os
import time
import threading

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteExec, RemoteFactory

LOG_WATCHER_BIN = BuildOptions.DAEMON_DIR + "/cts-log-watcher"

class SearchObj:
    def __init__(self, filename, host=None, name=None):
        self.cache = []
        self.filename = filename
        self.limit = None
        self.logger = LogFactory()
        self.name = name
        self.offset = "EOF"
        self.rsh = RemoteFactory().getInstance()

        if host:
            self.host = host
        else:
            self.host = "localhost"

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
        async_task = self.harvest_async(delegate)
        async_task.join()

    def harvest_async(self, delegate=None):
        raise NotImplementedError

    def end(self):
        self.debug("Unsetting the limit")
        self.limit = None

class FileObj(SearchObj):
    def __init__(self, filename, host=None, name=None):
        SearchObj.__init__(self, filename, host, name)
        self._delegate = None

        self.harvest()

    def async_complete(self, pid, returncode, out, err):
        for line in out:
            match = re.search("^CTSwatcher:Last read: (\d+)", line)

            if match:
                self.offset = match.group(1)
                self.debug("Got %d lines, new offset: %s  %s" % (len(out), self.offset, repr(self._delegate)))
            elif re.search("^CTSwatcher:.*truncated", line):
                self.log(line)
            elif re.search("^CTSwatcher:", line):
                self.debug("Got control line: %s" % line)
            else:
                self.cache.append(line)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, self.cache, err)

    def harvest_async(self, delegate=None):
        self._delegate = delegate
        self.cache = []

        if self.limit and (self.offset == "EOF" or int(self.offset) > self.limit):
            if self._delegate:
                self._delegate.async_complete(-1, -1, [], [])

            return None

        return self.rsh.call_async(self.host,
                                   "%s -t %s -p CTSwatcher: -l 200 -f %s -o %s" % (LOG_WATCHER_BIN, self.name, self.filename, self.offset),
                                   delegate=self)

    def set_end(self):
        if self.limit:
            return

        (_, lines) = self.rsh(self.host,
                              "%s -t %s -p CTSwatcher: -l 2 -f %s -o %s" % (LOG_WATCHER_BIN, self.name, self.filename, "EOF"),
                              verbose=0)

        for line in lines:
            match = re.search("^CTSwatcher:Last read: (\d+)", line)
            if match:
                self.limit = int(match.group(1))
                self.debug("Set limit to: %d" % self.limit)

class JournalObj(SearchObj):
    def __init__(self, host=None, name=None):
        SearchObj.__init__(self, name, host, name)
        self._delegate = None
        self._hit_limit = False

        self.harvest()

    def async_complete(self, pid, returncode, out, err):
        found_cursor = False
        for line in out:
            match = re.search("^-- cursor: ([^.]+)", line)

            if match:
                found_cursor = True
                self.offset = match.group(1).strip()
                self.debug("Got %d lines, new cursor: %s" % (len(out), self.offset))
            else:
                self.cache.append(line)

        if self.limit and not found_cursor:
            self._hit_limit = True
            self.debug("Got %d lines but no cursor: %s" % (len(out), self.offset))

            # Get the current cursor
            (_, out) = self.rsh(self.host, "journalctl -q -n 0 --show-cursor", verbose=0)
            for line in out:
                match = re.search("^-- cursor: ([^.]+)", line)

                if match:
                    self.offset = match.group(1).strip()
                    self.debug("Got %d lines, new cursor: %s" % (len(out), self.offset))
                else:
                    self.log("Not a new cursor: %s" % line)
                    self.cache.append(line)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, self.cache, err)

    def harvest_async(self, delegate=None):
        self._delegate = delegate
        self.cache = []

        # Use --lines to prevent journalctl from overflowing the Popen input buffer
        if self.limit and self._hit_limit:
            return None

        if self.offset == "EOF":
            command = "journalctl -q -n 0 --show-cursor"
        elif self.limit:
            command = "journalctl -q --after-cursor='%s' --until '%s' --lines=200 --show-cursor" % (self.offset, self.limit)
        else:
            command = "journalctl -q --after-cursor='%s' --lines=200 --show-cursor" % (self.offset)

        return self.rsh.call_async(self.host, command, delegate=self)

    def set_end(self):
        if self.limit:
            return

        self._hit_limit = False
        (rc, lines) = self.rsh(self.host, "date +'%Y-%m-%d %H:%M:%S'", verbose=0)

        if rc == 0 and len(lines) == 1:
            self.limit = lines[0].strip()
            self.debug("Set limit to: %s" % self.limit)
        else:
            self.debug("Unable to set limit for %s because date returned %d lines with status %d" % (self.host,
                len(lines), rc))

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

    def __init__(self, log, regexes, hosts, kind, name="Anon", timeout=10, debug_level=None, silent=False):
        '''This is the constructor for the LogWatcher class.  It takes a
        log name to watch, and a list of regular expressions to watch for."
        '''
        self.logger = LogFactory()

        self.hosts = hosts
        self.kind = kind
        self.filename = log
        self.name = name
        self.regexes = regexes

        if debug_level:
            self.debug_level = debug_level
        else:
            self.debug_level = 1

        self.whichmatch = -1
        self.unmatched = None
        self.cache_lock = threading.Lock()

        self.file_list = []
        self.line_cache = []

        #  Validate our arguments.  Better sooner than later ;-)
        for regex in regexes:
            re.compile(regex)

        if not self.hosts:
            raise ValueError("LogWatcher requires hosts argument")

        if not self.kind:
            raise ValueError("LogWatcher requires kind argument")

        if not self.filename:
            raise ValueError("LogWatcher requires log argument")

        if not silent:
            for regex in self.regexes:
                self.debug("Looking for regex: %s" % regex)

        self.Timeout = int(timeout)

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

    def __del__(self):
        if self.debug_level > 1:
            self.debug("Destroy")

    def async_complete(self, pid, returncode, outLines, errLines):
        # TODO: Probably need a lock for updating self.line_cache
        self.logger.debug("%s: Got %d lines from %d (total %d)" % (self.name, len(outLines), pid, len(self.line_cache)))

        if outLines:
            self.cache_lock.acquire()
            self.line_cache.extend(outLines)
            self.cache_lock.release()

    def __get_lines(self):
        if not self.file_list:
            raise ValueError("No sources to read from")

        pending = []

        for f in self.file_list:
            t = f.harvest_async(self)
            if t:
                pending.append(t)

        for t in pending:
            t.join(60.0)
            if t.is_alive():
                self.logger.log("%s: Aborting after 20s waiting for %s logging commands" % (self.name, repr(t)))
                return

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
        if not timeout:
            timeout = self.Timeout

        lines = 0
        begin = time.time()
        end = begin + timeout + 1

        if self.debug_level > 2:
            self.debug("starting single search: timeout=%d, begin=%d, end=%d" % (timeout, begin, end))

        if not self.regexes:
            self.debug("Nothing to look for")
            return None

        if timeout == 0:
            for f in self.file_list:
                f.set_end()

        while True:
            if self.line_cache:
                lines += 1

                self.cache_lock.acquire()
                line = self.line_cache[0]
                self.line_cache.remove(line)
                self.cache_lock.release()

                which = -1

                if re.search("CTS:", line):
                    continue

                if self.debug_level > 2:
                    self.debug("Processing: "+ line)

                for regex in self.regexes:
                    which = which + 1

                    if self.debug_level > 3:
                        self.debug("Comparing line to: %s" % regex)

                    matchobj = re.search(regex, line)

                    if matchobj:
                        self.whichmatch = which

                        self.debug("Matched: %s" % line)

                        if self.debug_level > 1:
                            self.debug("With: %s" % regex)

                        return line

            elif timeout > 0 and end < time.time():
                if self.debug_level > 1:
                    self.debug("hit timeout: %d" % timeout)

                timeout = 0
                for f in self.file_list:
                    f.set_end()

            else:
                self.__get_lines()

                if not self.line_cache and end < time.time():
                    self.debug("Single search terminated: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), lines))
                    return None

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

        if not timeout:
            timeout = self.Timeout

        save_regexes = self.regexes
        returnresult = []

        if not silent:
            self.debug("starting search: timeout=%d" % timeout)
            for regex in self.regexes:
                if self.debug_level > 2:
                    self.debug("Looking for regex: %s" % regex)

        while self.regexes:
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

                for regex in tmp_regexes:
                    matchobj = re.search(regex, oneresult)
                    if not matchobj:
                        self.regexes.append(regex)

        self.unmatched = None
        self.matched = returnresult
        self.regexes = save_regexes
        return returnresult
