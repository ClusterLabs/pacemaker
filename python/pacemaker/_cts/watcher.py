""" Log searching classes for Pacemaker's Cluster Test Suite (CTS) """

__all__ = ["LogKind", "LogWatcher"]
__copyright__ = "Copyright 2014-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from enum import Enum, unique
import re
import time
import threading

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteFactory

LOG_WATCHER_BIN = BuildOptions.DAEMON_DIR + "/cts-log-watcher"

@unique
class LogKind(Enum):
    """ The various kinds of log files that can be watched """

    ANY         = 0
    FILE        = 1
    REMOTE_FILE = 2
    JOURNAL     = 3

    def __str__(self):
        if self.value == 0:
            return "any"
        if self.value == 1:
            return "combined syslog"
        if self.value == 2:
            return "remote"

        return "journal"

class SearchObj:
    """ The base class for various kinds of log watchers.  Log-specific watchers
        need to be built on top of this one.
    """

    def __init__(self, filename, host=None, name=None):
        """ Create a new SearchObj instance

            Arguments:

            filename -- The log to watch
            host     -- The cluster node on which to watch the log
            name     -- A unique name to use when logging about this watch
        """

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
        """ Log a message """

        message = "lw: %s: %s" % (self, args)
        self.logger.log(message)

    def debug(self, args):
        """ Log a debug message """

        message = "lw: %s: %s" % (self, args)
        self.logger.debug(message)

    def harvest(self, delegate=None):
        """ Collect lines from a log, optionally calling delegate when complete """

        async_task = self.harvest_async(delegate)
        async_task.join()

    def harvest_async(self, delegate=None):
        """ Collect lines from a log asynchronously, optionally calling delegate
            when complete.  This method must be implemented by all subclasses.
        """

        raise NotImplementedError

    def end(self):
        """ Mark that a log is done being watched, resetting internal data structures
            to the beginning of the file.  Subsequent watches will therefore start
            from the beginning again.
        """

        self.debug("Unsetting the limit")
        self.limit = None

class FileObj(SearchObj):
    """ A specialized SearchObj subclass for watching log files """

    def __init__(self, filename, host=None, name=None):
        """ Create a new FileObj instance

            Arguments:

            filename -- The file to watch
            host     -- The cluster node on which to watch the file
            name     -- A unique name to use when logging about this watch
        """

        SearchObj.__init__(self, filename, host, name)
        self._delegate = None

        self.harvest()

    def async_complete(self, pid, returncode, out, err):
        """ Called when an asynchronous log file read is complete.  This function
            saves the output from that read for look()/look_for_all() to process
            and records the current position in the journal.  Future reads will
            pick back up from that spot.

            Arguments:

            pid         -- The ID of the process that did the read
            returncode  -- The return code of the process that did the read
            out         -- stdout from the file read
            err         -- stderr from the file read
        """

        for line in out:
            match = re.search(r"^CTSwatcher:Last read: (\d+)", line)

            if match:
                self.offset = match.group(1)
                self.debug("Got %d lines, new offset: %s  %s" % (len(out), self.offset, repr(self._delegate)))
            elif re.search(r"^CTSwatcher:.*truncated", line):
                self.log(line)
            elif re.search(r"^CTSwatcher:", line):
                self.debug("Got control line: %s" % line)
            else:
                self.cache.append(line)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, self.cache, err)

    def harvest_async(self, delegate=None):
        """ Collect lines from the log file on a single host asynchronously,
            optionally calling delegate when complete.  This can be called
            repeatedly, reading a chunk each time or until the end of the log
            file is hit.
        """

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
        """ Internally record where we expect to find the end of a log file,
            which is just the number of lines in the file.  Calls to harvest
            from the log file will not go any farther than what this function
            records.
        """

        if self.limit:
            return

        # pylint: disable=not-callable
        (_, lines) = self.rsh(self.host,
                              "%s -t %s -p CTSwatcher: -l 2 -f %s -o %s" % (LOG_WATCHER_BIN, self.name, self.filename, "EOF"),
                              verbose=0)

        for line in lines:
            match = re.search(r"^CTSwatcher:Last read: (\d+)", line)
            if match:
                self.limit = int(match.group(1))
                self.debug("Set limit to: %d" % self.limit)

class JournalObj(SearchObj):
    """ A specialized SearchObj subclass for watching systemd journals """

    def __init__(self, host=None, name=None):
        """ Create a new JournalObj instance

            Arguments:

            host     -- The cluster node on which to watch the journal
            name     -- A unique name to use when logging about this watch
        """

        SearchObj.__init__(self, name, host, name)
        self._delegate = None
        self._hit_limit = False

        self.harvest()

    def async_complete(self, pid, returncode, out, err):
        """ Called when an asynchronous journal read is complete.  This function
            saves the output from that read for look()/look_for_all() to process
            and records the current position in the journal.  Future reads will
            pick back up from that spot.

            Arguments:

            pid         -- The ID of the process that did the journal read
            returncode  -- The return code of the process that did the journal read
            out         -- stdout from the journal read
            err         -- stderr from the journal read
        """

        found_cursor = False
        for line in out:
            match = re.search(r"^-- cursor: ([^.]+)", line)

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
            # pylint: disable=not-callable
            (_, out) = self.rsh(self.host, "journalctl -q -n 0 --show-cursor", verbose=0)
            for line in out:
                match = re.search(r"^-- cursor: ([^.]+)", line)

                if match:
                    self.offset = match.group(1).strip()
                    self.debug("Got %d lines, new cursor: %s" % (len(out), self.offset))
                else:
                    self.log("Not a new cursor: %s" % line)
                    self.cache.append(line)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, self.cache, err)

    def harvest_async(self, delegate=None):
        """ Collect lines from the journal on a single host asynchronously,
            optionally calling delegate when complete.  This can be called
            repeatedly, reading a chunk each time or until the end of the
            journal is hit.
        """

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
        """ Internally record where we expect to find the end of a host's journal,
            which is just the current time.  Calls to harvest from the journal will
            not go any farther than what this function records.
        """

        if self.limit:
            return

        self._hit_limit = False
        # pylint: disable=not-callable
        (rc, lines) = self.rsh(self.host, "date +'%Y-%m-%d %H:%M:%S'", verbose=0)

        if rc == 0 and len(lines) == 1:
            self.limit = lines[0].strip()
            self.debug("Set limit to: %s" % self.limit)
        else:
            self.debug("Unable to set limit for %s because date returned %d lines with status %d" % (self.host,
                len(lines), rc))

class LogWatcher:
    """ A class for watching a single log file or journal across multiple hosts,
        looking for lines that match given regular expressions.

        The way you use this class is as follows:
            - Construct a LogWatcher object
            - Call set_watch() when you want to start watching the log
            - Call look() to scan the log looking for the patterns
    """

    def __init__(self, log, regexes, hosts, kind=LogKind.ANY, name="Anon", timeout=10, silent=False):
        """ Create a new LogWatcher instance.

            Arguments:

            log     -- The log file to watch
            regexes -- A list of regular expressions to match against the log
            hosts   -- A list of cluster nodes on which to watch the log
            kind    -- What type of log is this object watching?
            name    -- A unique name to use when logging about this watch
            timeout -- Default number of seconds to watch a log file at a time;
                       this can be overridden by the timeout= parameter to
                       self.look on an as-needed basis
            silent  -- If False, log extra information
        """

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

        if not self.filename:
            raise ValueError("LogWatcher requires log argument")

        if not silent:
            for regex in self.regexes:
                self._debug("Looking for regex: %s" % regex)

    def _debug(self, args):
        """ Log a debug message """

        message = "lw: %s: %s" % (self.name, args)
        self._logger.debug(message)

    def set_watch(self):
        """ Mark the place to start watching the log from """

        if self.kind == LogKind.REMOTE_FILE:
            for node in self.hosts:
                self._file_list.append(FileObj(self.filename, node, self.name))

        elif self.kind == LogKind.JOURNAL:
            for node in self.hosts:
                self._file_list.append(JournalObj(node, self.name))

        else:
            self._file_list.append(FileObj(self.filename))

    def async_complete(self, pid, returncode, out, err):
        """ Called when an asynchronous log file read is complete.  This function
            saves the output from that read for look()/look_for_all() to process
            and records the current position.  Future reads will pick back up
            from that spot.

            Arguments:

            pid         -- The ID of the process that did the read
            returncode  -- The return code of the process that did the read
            out         -- stdout from the file read
            err         -- stderr from the file read
        """

        # It's not clear to me whether this function ever gets called as
        # delegate somewhere, which is what would pass returncode and err
        # as parameters.  Just disable the warning for now.
        # pylint: disable=unused-argument

        # TODO: Probably need a lock for updating self._line_cache
        self._logger.debug("%s: Got %d lines from %d (total %d)" % (self.name, len(out), pid, len(self._line_cache)))

        if out:
            with self._cache_lock:
                self._line_cache.extend(out)

    def __get_lines(self):
        """ Iterate over all watched log files and collect new lines from each """

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
        """ Mark that a log is done being watched, resetting internal data structures
            to the beginning of the file.  Subsequent watches will therefore start
            from the beginning again.
        """

        for f in self._file_list:
            f.end()

    def look(self, timeout=None):
        """ Examine the log looking for the regexes that were given when this
            object was created.  It starts looking from the place marked by
            set_watch(), continuing through the file in the fashion of
            `tail -f`.  It properly recovers from log file truncation but not
            from removing and recreating the log.

            Arguments:

            timeout -- Number of seconds to watch the log file; defaults to
                       seconds argument passed when this object was created

            Returns:

            The first line which matches any regex
        """

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
        """ Like look(), but looks for matches for multiple regexes.  This function
            returns when the timeout is reached or all regexes were matched.  As a
            side effect, self.unmatched will contain regexes that were not matched.
            This can be inspected by the caller.

            Arguments:

            allow_multiple_matches -- If True, allow each regex to match more than
                                      once.  If False (the default), once a regex
                                      matches a line, it will no longer be searched
                                      for.
            silent                 -- If False, log extra information

            Returns:

            If all regexes are matched, return the matching lines.  Otherwise, return
            None.
        """

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
