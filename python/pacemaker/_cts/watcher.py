"""Log searching classes for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["LogKind", "LogWatcher"]
__copyright__ = "Copyright 2014-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from enum import Enum, auto, unique
import re
import time
import threading

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.errors import OutputNotFoundError
from pacemaker._cts import logging
from pacemaker._cts.remote import RemoteExec


CTS_SUPPORT_BIN = f"{BuildOptions.DAEMON_DIR}/cts-support"


@unique
class LogKind(Enum):
    """The various kinds of log files that can be watched."""

    LOCAL_FILE = auto()     # From a local aggregation file on the exerciser
    REMOTE_FILE = auto()    # From a file on each cluster node
    JOURNAL = auto()        # From the systemd journal on each cluster node

    def __str__(self):
        """Return a printable string for a LogKind value."""
        return self.name.lower().replace('_', ' ')


class SearchObj:
    """
    The base class for various kinds of log watchers.

    Log-specific watchers need to be built on top of this one.
    """

    def __init__(self, filename, host=None, name=None):
        """
        Create a new SearchObj instance.

        Arguments:
        filename -- The log to watch
        host     -- The cluster node on which to watch the log
        name     -- A unique name to use when logging about this watch
        """
        self.filename = filename
        self.limit = None
        self.name = name
        self.offset = "EOF"
        self.rsh = RemoteExec()

        if host:
            self.host = host
        else:
            self.host = "localhost"

        self._cache = []
        self._delegate = None

        async_task = self.harvest_async()
        async_task.join()

    def __str__(self):
        if self.host:
            return f"{self.host}:{self.filename}"

        return self.filename

    def log(self, args):
        """Log a message."""
        message = f"lw: {self}: {args}"
        logging.log(message)

    def debug(self, args):
        """Log a debug message."""
        message = f"lw: {self}: {args}"
        logging.debug(message)

    def harvest_async(self, delegate=None):
        """
        Collect lines from a log asynchronously.

        Optionally, also call delegate when complete.  This method must be
        implemented by all subclasses.
        """
        raise NotImplementedError

    def harvest_cached(self):
        """Return cached logs from before the limit timestamp."""
        raise NotImplementedError

    def end(self):
        """
        Mark that a log is done being watched.

        This function also resets internal data structures to the beginning
        of the file.  Subsequent watches will therefore start from the
        beginning again.
        """
        self.debug("Clearing cache and unsetting limit")
        self._cache = []
        self.limit = None


class FileObj(SearchObj):
    """A specialized SearchObj subclass for watching log files."""

    def __init__(self, filename, host=None, name=None):
        """
        Create a new FileObj instance.

        Arguments:
        filename -- The file to watch
        host     -- The cluster node on which to watch the file
        name     -- A unique name to use when logging about this watch
        """
        SearchObj.__init__(self, filename, host, name)

    def async_complete(self, pid, returncode, out, err):
        """
        Handle completion of an asynchronous log file read.

        This function saves the output from that read for look()/look_for_all()
        to process and records the current position in the journal.  Future
        reads will pick back up from that spot.

        Arguments:
        pid         -- The ID of the process that did the read
        returncode  -- The return code of the process that did the read
        out         -- stdout from the file read
        err         -- stderr from the file read
        """
        messages = []
        for line in out:
            match = re.search(r"^CTSwatcher:Last read: (\d+)", line)

            if match:
                self.offset = match.group(1)
                self.debug(f"Got {len(out)} lines, new offset: {self.offset}  {self._delegate!r}")
            elif re.search(r"^CTSwatcher:.*truncated", line):
                self.log(line)
            elif re.search(r"^CTSwatcher:", line):
                self.debug(f"Got control line: {line}")
            else:
                messages.append(line)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, messages, err)

    def harvest_async(self, delegate=None):
        """
        Collect lines from the log file on a single host asynchronously.

        Optionally, call delegate when complete.  This can be called
        repeatedly, reading a chunk each time or until the end of the
        log file is hit.
        """
        self._delegate = delegate

        if self.limit and (self.offset == "EOF" or int(self.offset) > self.limit):
            if self._delegate:
                self._delegate.async_complete(-1, -1, [], [])

            return None

        cmd = f"{CTS_SUPPORT_BIN} watch -p CTSwatcher: -l 200 -f {self.filename} -o {self.offset}"
        return self.rsh.call_async(self.host, cmd, delegate=self)

    def harvest_cached(self):
        """Return cached logs from before the limit timestamp."""
        # cts-log-watcher script renders caching unnecessary for FileObj.
        # @TODO Caching might be slightly more efficient, if not too complex.
        return []

    def set_end(self):
        """
        Internally record where we expect to find the end of a log file.

        Calls to harvest from the log file will not go any farther than
        what this function records.
        """
        if self.limit:
            return

        cmd = f"{CTS_SUPPORT_BIN} watch -p CTSwatcher: -l 2 -f {self.filename} -o EOF"

        (_, lines) = self.rsh.call(self.host, cmd, verbose=0)

        for line in lines:
            match = re.search(r"^CTSwatcher:Last read: (\d+)", line)
            if match:
                self.limit = int(match.group(1))
                self.debug(f"Set limit to: {self.limit}")


class JournalObj(SearchObj):
    """A specialized SearchObj subclass for watching systemd journals."""

    def __init__(self, host=None, name=None):
        """
        Create a new JournalObj instance.

        Arguments:
        host     -- The cluster node on which to watch the journal
        name     -- A unique name to use when logging about this watch
        """
        SearchObj.__init__(self, "journal", host, name)

    def _msg_after_limit(self, msg):
        """
        Check whether a message was logged after the limit timestamp.

        Arguments:
        msg -- Message to check

        Returns `True` if `msg` was logged after `self.limit`, or `False`
        otherwise.
        """
        if not self.limit:
            return False

        match = re.search(r"^\S+", msg)
        if not match:
            return False

        # Seconds and microseconds since epoch
        msg_timestamp = float(match.group(0))
        return msg_timestamp > self.limit

    def _split_msgs_by_limit(self, msgs):
        """
        Split a sorted list of messages relative to the limit timestamp.

        Arguments:
        msgs -- List of messages to split

        Returns a tuple:
        (list of messages logged on or before limit timestamp,
         list of messages logged after limit timestamp).
        """
        # If last message was logged before limit, all messages were
        if msgs and self._msg_after_limit(msgs[-1]):

            # Else find index of first message logged after limit
            for idx, msg in enumerate(msgs):
                if self._msg_after_limit(msg):
                    self.debug(f"Got {idx} lines before passing limit timestamp")
                    return msgs[:idx], msgs[idx:]

        self.debug(f"Got {len(msgs)} lines")
        return msgs, []

    def async_complete(self, pid, returncode, out, err):
        """
        Handle completion of an asynchronous journal read.

        This function saves the output from that read for look()/look_for_all()
        to process and records the current position in the journal.  Future
        reads will pick back up from that spot.

        Arguments:
        pid         -- The ID of the process that did the journal read
        returncode  -- The return code of the process that did the journal read
        out         -- stdout from the journal read
        err         -- stderr from the journal read
        """
        if out:
            # Cursor should always be last line of journalctl output
            out, cursor_line = out[:-1], out[-1]
            match = re.search(r"^-- cursor: ([^.]+)", cursor_line)
            if not match:
                raise OutputNotFoundError(f"Cursor not found at end of output:\n{out}")

            self.offset = match.group(1).strip()
            self.debug(f"Got new cursor: {self.offset}")

        before, after = self._split_msgs_by_limit(out)

        # Save remaining messages after limit for later processing
        self._cache.extend(after)

        if self._delegate:
            self._delegate.async_complete(pid, returncode, before, err)

    def harvest_async(self, delegate=None):
        """
        Collect lines from the journal on a single host asynchronously.

        Optionally, call delegate when complete.  This can be called
        repeatedly, reading a chunk each time or until the end of the journal
        is hit.
        """
        self._delegate = delegate

        # Use --lines to prevent journalctl from overflowing the Popen input
        # buffer
        command = "journalctl --quiet --output=short-unix --show-cursor"
        if self.offset == "EOF":
            command += " --lines 0"
        else:
            command += f" --after-cursor='{self.offset}' --lines=200"

        return self.rsh.call_async(self.host, command, delegate=self)

    def harvest_cached(self):
        """Return cached logs from before the limit timestamp."""
        before, self._cache = self._split_msgs_by_limit(self._cache)
        return before

    def set_end(self):
        """
        Internally record where we expect to find the end of a host's journal.

        Calls to harvest from the journal will not go any farther than what
        this function records.
        """
        if self.limit:
            return

        # Seconds and nanoseconds since epoch
        (rc, lines) = self.rsh.call(self.host, "date +%s.%N", verbose=0)

        if rc == 0 and len(lines) == 1:
            self.limit = float(lines[0].strip())
            self.debug(f"Set limit to: {self.limit}")
        else:
            self.debug(f"Unable to set limit for {self.host} because date returned "
                       f"{len(lines)} lines with status {rc}")


class LogWatcher:
    """
    Watch a single log file or journal across multiple hosts.

    Instances of this class look for lines that match given regular
    expressions.

    The way you use this class is as follows:
        - Construct a LogWatcher object
        - Call set_watch() when you want to start watching the log
        - Call look() to scan the log looking for the patterns
    """

    def __init__(self, log, regexes, hosts, kind, name="Anon", timeout=10,
                 silent=False):
        """
        Create a new LogWatcher instance.

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
        self._timeout = int(timeout)

        #  Validate our arguments.  Better sooner than later ;-)
        for regex in regexes:
            re.compile(regex)

        if not self.hosts:
            raise ValueError("LogWatcher requires hosts argument")

        if self.kind != LogKind.JOURNAL and not self.filename:
            raise ValueError("LogWatcher requires log file name if not journal")

        if not silent:
            for regex in self.regexes:
                self._debug(f"Looking for regex: {regex}")

    def _debug(self, args):
        """Log a debug message."""
        message = f"lw: {self.name}: {args}"
        logging.debug(message)

    def set_watch(self):
        """Mark the place to start watching the log from."""
        if self.kind == LogKind.LOCAL_FILE:
            self._file_list.append(FileObj(self.filename))

        elif self.kind == LogKind.REMOTE_FILE:
            for node in self.hosts:
                self._file_list.append(FileObj(self.filename, node, self.name))

        elif self.kind == LogKind.JOURNAL:
            for node in self.hosts:
                self._file_list.append(JournalObj(node, self.name))

    def async_complete(self, pid, returncode, out, err):
        """
        Handle completion of an asynchronous log file read.

        This function saves the output from that read for look()/look_for_all()
        to process and records the current position.  Future reads will pick
        back up from that spot.

        Arguments:
        pid         -- The ID of the process that did the read
        returncode  -- The return code of the process that did the read
        out         -- stdout from the file read
        err         -- stderr from the file read
        """
        # Called as delegate through {File,Journal}Obj.async_complete()
        # pylint: disable=unused-argument

        # TODO: Probably need a lock for updating self._line_cache
        logging.debug(f"{self.name}: Got {len(out)} lines from {pid} (total {len(self._line_cache)})")

        if out:
            with self._cache_lock:
                self._line_cache.extend(out)

    def __get_lines(self):
        """Iterate over all watched log files and collect new lines from each."""
        if not self._file_list:
            raise ValueError("No sources to read from")

        pending = []

        for f in self._file_list:
            cached = f.harvest_cached()
            if cached:
                self._debug(f"Got {len(cached)} lines from {f.name} cache (total {len(self._line_cache)})")
                with self._cache_lock:
                    self._line_cache.extend(cached)
            else:
                t = f.harvest_async(self)
                if t:
                    pending.append(t)

        for t in pending:
            t.join(60.0)
            if t.is_alive():
                logging.log(f"{self.name}: Aborting after 20s waiting for {t!r} logging commands")
                return

    def end(self):
        """
        Mark that a log is done being watched.

        This function also resets internal data structures to the beginning
        of the file.  Subsequent watches will therefore start from the
        beginning again.
        """
        for f in self._file_list:
            f.end()

    def look(self, timeout=None):
        """
        Examine the log looking for the regexes in this object.

        It starts looking from the place marked by set_watch(), continuing
        through the file in the fashion of `tail -f`.  It properly recovers
        from log file truncation but not from removing and recreating the log.

        Arguments:
        timeout -- Number of seconds to watch the log file; defaults to
                   seconds argument passed when this object was created

        Returns the first line which matches any regex
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
                        self._debug(f"Matched: {line}")
                        return line

            elif timeout > 0 and end < time.time():
                timeout = 0
                for f in self._file_list:
                    f.set_end()

            else:
                self.__get_lines()

                if not self._line_cache and end < time.time():
                    self._debug(f"Single search terminated: start={begin}, end={end}, now={time.time()}, lines={lines}")
                    return None

                self._debug(f"Waiting: start={begin}, end={end}, now={time.time()}, lines={len(self._line_cache)}")
                time.sleep(1)

    def look_for_all(self, allow_multiple_matches=False, silent=False):
        """
        Like look(), but looks for matches for multiple regexes.

        This function returns when the timeout is reached or all regexes were
        matched.  As a side effect, self.unmatched will contain regexes that
        were not matched.  This can be inspected by the caller.

        Arguments:
        allow_multiple_matches -- If True, allow each regex to match more than
                                  once.  If False (the default), once a regex
                                  matches a line, it will no longer be searched
                                  for.
        silent                 -- If False, log extra information

        Returns the matching lines if all regexes are matched, or None.
        """
        save_regexes = self.regexes
        result = []

        if not silent:
            self._debug(f"starting search: timeout={self._timeout}")

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
