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
from pacemaker._cts.remote import RemoteFactory

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

class LogWatcher:
    '''This class watches logs for messages that fit certain regular
       expressions.  Watching logs for events isn't the ideal way
       to do business, but it's better than nothing :-)

       On the other hand, this class is really pretty cool ;-)

       The way you use this class is as follows:
          Construct a LogWatcher object
          Call set_watch() when you want to start watching the log
          Call look() to scan the log looking for the patterns
    '''

    def __init__(self, log, regexes, hosts, kind, name="Anon", timeout=10, silent=False):
        '''This is the constructor for the LogWatcher class.  It takes a
        log name to watch, and a list of regular expressions to watch for."
        '''
        self.filename = log
        self.hosts = hosts
        self.kind = kind
        self.name = name
        self.regexes = regexes
        self.unmatched = None
        self.whichmatch = -1

        self._cache_lock = threading.Lock()
        self._file_list = []
        self._line_cache = []
        self._logger = LogFactory()
        self._timeout = int(timeout)

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
                self._debug("Looking for regex: %s" % regex)

    def _debug(self, args):
        message = "lw: %s: %s" % (self.name, args)
        self._logger.debug(message)

    def set_watch(self):
        '''Mark the place to start watching the log from.
        '''

        if self.kind == "remote":
            for node in self.hosts:
                self._file_list.append(FileObj(self.filename, node, self.name))

        elif self.kind == "journal":
            for node in self.hosts:
                self._file_list.append(JournalObj(node, self.name))

        else:
            self._file_list.append(FileObj(self.filename))

    def async_complete(self, pid, returncode, out, err):
        # TODO: Probably need a lock for updating self._line_cache
        self._logger.debug("%s: Got %d lines from %d (total %d)" % (self.name, len(out), pid, len(self._line_cache)))

        if out:
            with self._cache_lock:
                self._line_cache.extend(out)

    def __get_lines(self):
        if not self._file_list:
            raise ValueError("No sources to read from")

        pending = []

        for f in self._file_list:
            t = f.harvest_async(self)
            if t:
                pending.append(t)

        for t in pending:
            t.join(60.0)
            if t.is_alive():
                self._logger.log("%s: Aborting after 20s waiting for %s logging commands" % (self.name, repr(t)))
                return

    def end(self):
        for f in self._file_list:
            f.end()

    def look(self, timeout=None):
        '''Examine the log looking for the given patterns.
        It starts looking from the place marked by set_watch().
        This function looks in the file in the fashion of tail -f.
        It properly recovers from log file truncation, but not from
        removing and recreating the log.  It would be nice if it
        recovered from this as well :-)

        We return the first line which matches any of our patterns.
        '''
        if not timeout:
            timeout = self._timeout

        lines = 0
        begin = time.time()
        end = begin + timeout + 1

        if not self.regexes:
            self._debug("Nothing to look for")
            return None

        if timeout == 0:
            for f in self._file_list:
                f.set_end()

        while True:
            if self._line_cache:
                lines += 1

                with self._cache_lock:
                    line = self._line_cache[0]
                    self._line_cache.remove(line)

                which = -1

                if re.search("CTS:", line):
                    continue

                for regex in self.regexes:
                    which += 1

                    matchobj = re.search(regex, line)

                    if matchobj:
                        self.whichmatch = which
                        self._debug("Matched: %s" % line)
                        return line

            elif timeout > 0 and end < time.time():
                timeout = 0
                for f in self._file_list:
                    f.set_end()

            else:
                self.__get_lines()

                if not self._line_cache and end < time.time():
                    self._debug("Single search terminated: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), lines))
                    return None

                self._debug("Waiting: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), len(self._line_cache)))
                time.sleep(1)

        self._debug("How did we get here")
        return None

    def look_for_all(self, allow_multiple_matches=False, silent=False):
        '''Examine the log looking for ALL of the given patterns.
        It starts looking from the place marked by set_watch().

        We return when the timeout is reached, or when we have found
        ALL of the regexes that were part of the watch
        '''

        save_regexes = self.regexes
        result = []

        if not silent:
            self._debug("starting search: timeout=%d" % self._timeout)

        while self.regexes:
            one_result = self.look(self._timeout)
            if not one_result:
                self.unmatched = self.regexes
                self.regexes = save_regexes
                self.end()
                return None

            result.append(one_result)
            if not allow_multiple_matches:
                del self.regexes[self.whichmatch]

            else:
                # Allow multiple regexes to match a single line
                tmp_regexes = self.regexes
                self.regexes = []

                for regex in tmp_regexes:
                    matchobj = re.search(regex, one_result)
                    if not matchobj:
                        self.regexes.append(regex)

        self.unmatched = None
        self.regexes = save_regexes
        return result
