'''CTS: Cluster Testing System: Main module

Classes related to testing high-availability clusters...
 '''

__copyright__='''
Copyright (C) 2000, 2001 Alan Robertson <alanr@unix.sh>
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


from socket import gethostbyname_ex
from UserDict import UserDict
from subprocess import Popen,PIPE
from cts.CTSvars import *
from threading import Thread

trace_rsh=None
trace_lw=None

has_log_stats = {}
log_stats_bin = CTSvars.CRM_DAEMON_DIR + "/cts_log_stats.sh"
log_stats = """
#!/bin/bash
# Tool for generating system load reports while CTS runs

trap "" 1

f=$1; shift
action=$1; shift
base=`basename $0`

if [ ! -e $f ]; then
    echo "Time, Load 1, Load 5, Load 15, Test Marker" > $f
fi

function killpid() {
    if [ -e $f.pid ]; then
       kill -9 `cat $f.pid`
       rm -f $f.pid
    fi
}

function status() {
    if [ -e $f.pid ]; then
       kill -0 `cat $f.pid`
       return $?
    else
       return 1
    fi
}

function start() {
    # Is it already running?
    if
	status
    then
        return
    fi

    echo Active as $$
    echo $$ > $f.pid

    while [ 1 = 1 ]; do
        uptime | sed s/up.*:/,/ | tr '\\n' ',' >> $f
        #top -b -c -n1 | grep -e usr/libexec/pacemaker | grep -v -e grep -e python | head -n 1 | sed s@/usr/libexec/pacemaker/@@ | awk '{print " 0, "$9", "$10", "$12}' | tr '\\n' ',' >> $f
        echo 0 >> $f
        sleep 5
    done
}

case $action in
    start)
        start
        ;;
    start-bg|bg)
        # Use c --ssh -- ./stats.sh file start-bg
        nohup $0 $f start >/dev/null 2>&1 </dev/null &
        ;;
    stop)
	killpid
	;;
    delete)
	killpid
	rm -f $f
	;;
    mark)
	uptime | sed s/up.*:/,/ | tr '\\n' ',' >> $f
	echo " $*" >> $f
        start
	;;
    *)
	echo "Unknown action: $action."
	;;
esac
"""

class CtsLab(UserDict):
    '''This class defines the Lab Environment for the Cluster Test System.
    It defines those things which are expected to change from test
    environment to test environment for the same cluster manager.

    It is where you define the set of nodes that are in your test lab
    what kind of reset mechanism you use, etc.

    This class is derived from a UserDict because we hold many
    different parameters of different kinds, and this provides
    provide a uniform and extensible interface useful for any kind of
    communication between the user/administrator/tester and CTS.

    At this point in time, it is the intent of this class to model static
    configuration and/or environmental data about the environment which
    doesn't change as the tests proceed.

    Well-known names (keys) are an important concept in this class.
    The HasMinimalKeys member function knows the minimal set of
    well-known names for the class.

    The following names are standard (well-known) at this time:

        nodes           An array of the nodes in the cluster
        reset           A ResetMechanism object
        logger          An array of objects that log strings...
        CMclass         The type of ClusterManager we are running
                        (This is a class object, not a class instance)
        RandSeed        Random seed.  It is a triple of bytes. (optional)

    The CTS code ignores names it doesn't know about/need.
    The individual tests have access to this information, and it is
    perfectly acceptable to provide hints, tweaks, fine-tuning
    directions or other information to the tests through this mechanism.
    '''

    def __init__(self):
        self.data = {}
        self.rsh = RemoteExec(self)
        self.RandomGen = random.Random()
        self.Scenario = None

        #  Get a random seed for the random number generator.
        self["LogWatcher"] = "any"
        self["LogFileName"] = "/var/log/messages"
        self["OutputFile"] = None
        self["SyslogFacility"] = "daemon"
        self["CMclass"] = None
        self["logger"] = ([StdErrLog(self)])

        self.SeedRandom()

    def SeedRandom(self, seed=None):
        if not seed:
            seed = int(time.time())

        if self.has_key("RandSeed"):
            self.log("New random seed is: " + str(seed))
        else:
            self.log("Random seed is: " + str(seed))

        self["RandSeed"] = seed
        self.RandomGen.seed(str(seed))

    def HasMinimalKeys(self):
        'Return TRUE if our object has the minimal set of keys/values in it'
        result = 1
        for key in self.MinimalKeys:
            if not self.has_key(key):
                result = None
        return result

    def log(self, args):
        "Log using each of the supplied logging methods"
        for logfcn in self._logfunctions:
            logfcn(string.strip(args))

    def debug(self, args):
        "Log using each of the supplied logging methods"
        for logfcn in self._logfunctions:
            if logfcn.name() != "StdErrLog":
                logfcn("debug: %s" % string.strip(args))

    def dump(self):
        keys = []
        for key in self.keys():
            keys.append(key)

        keys.sort()
        for key in keys:
            self.debug("Environment["+key+"]:\t"+str(self[key]))

    def run(self, Scenario, Iterations):
        if not Scenario:
            self.log("No scenario was defined")
            return 1

        self.log("Cluster nodes: ")
        for node in self["nodes"]:
            self.log("    * %s" % (node))

        self.StatsMark(0)
        if not Scenario.SetUp():
            return 1

        try :
            Scenario.run(Iterations)
        except :
            self.log("Exception by %s" % sys.exc_info()[0])
            for logmethod in self["logger"]:
                traceback.print_exc(50, logmethod)

            Scenario.summarize()
            Scenario.TearDown()
            self.StatsExtract()
            return 1

        #ClusterManager.oprofileSave(Iterations)
        Scenario.TearDown()
        self.StatsExtract()

        Scenario.summarize()
        if Scenario.Stats["failure"] > 0:
            return Scenario.Stats["failure"]

        elif Scenario.Stats["success"] != Iterations:
            self.log("No failure count but success != requested iterations")
            return 1

        return 0

    def __setitem__(self, key, value):
        '''Since this function gets called whenever we modify the
        dictionary (object), we can (and do) validate those keys that we
        know how to validate.  For the most part, we know how to validate
        the "MinimalKeys" elements.
        '''

        #
        #        List of nodes in the system
        #
        if key == "nodes":
            self.Nodes = {}
            for node in value:
                # I don't think I need the IP address, etc. but this validates
                # the node name against /etc/hosts and/or DNS, so it's a
                # GoodThing(tm).
                try:
                    self.Nodes[node] = gethostbyname_ex(node)
                except:
                    print node+" not found in DNS... aborting"
                    raise
        #
        #        List of Logging Mechanism(s)
        #
        elif key == "logger":
            if len(value) < 1:
                raise ValueError("Must have at least one logging mechanism")
            for logger in value:
                if not callable(logger):
                    raise ValueError("'logger' elements must be callable")
            self._logfunctions = value
        #
        #        Cluster Manager Class
        #
        elif key == "CMclass":
            if value and not issubclass(value, ClusterManager):
                raise ValueError("'CMclass' must be a subclass of"
                " ClusterManager")
        #
        #        Initial Random seed...
        #
        #elif key == "RandSeed":
        #    if len(value) != 3:
        #        raise ValueError("'Randseed' must be a 3-element list/tuple")
        #    for elem in value:
        #        if not isinstance(elem, types.IntType):
        #            raise ValueError("'Randseed' list must all be ints")

        self.data[key] = value

    def IsValidNode(self, node):
        'Return TRUE if the given node is valid'
        return self.Nodes.has_key(node)

    def __CheckNode(self, node):
        "Raise a ValueError if the given node isn't valid"

        if not self.IsValidNode(node):
            raise ValueError("Invalid node [%s] in CheckNode" % node)

    def RandomNode(self):
        '''Choose a random node from the cluster'''
        return self.RandomGen.choice(self["nodes"])

    def StatsExtract(self):
        if not self["stats"]:
            return

        for host in self["nodes"]:
            log_stats_file = "%s/cts-stats.csv" % CTSvars.CRM_DAEMON_DIR
            if has_log_stats.has_key(host):
                self.rsh(host, '''bash %s %s stop''' % (log_stats_bin, log_stats_file))
                (rc, lines) = self.rsh(host, '''cat %s''' % log_stats_file, stdout=2)
                self.rsh(host, '''bash %s %s delete''' % (log_stats_bin, log_stats_file))

                fname = "cts-stats-%d-nodes-%s.csv" % (len(self["nodes"]), host)
                print "Extracted stats: %s" % fname
                fd = open(fname, "a")
                fd.writelines(lines)
                fd.close()

    def StatsMark(self, testnum):
        '''Mark the test number in the stats log'''

        global has_log_stats
        if not self["stats"]:
            return

        for host in self["nodes"]:
            log_stats_file = "%s/cts-stats.csv" % CTSvars.CRM_DAEMON_DIR
            if not has_log_stats.has_key(host):

                global log_stats
                global log_stats_bin
                script=log_stats
                #script = re.sub("\\\\", "\\\\", script)
                script = re.sub('\"', '\\\"', script)
                script = re.sub("'", "\'", script)
                script = re.sub("`", "\`", script)
                script = re.sub("\$", "\\\$", script)

                self.debug("Installing %s on %s" % (log_stats_bin, host))
                self.rsh(host, '''echo "%s" > %s''' % (script, log_stats_bin), silent=True)
                self.rsh(host, '''bash %s %s delete''' % (log_stats_bin, log_stats_file))
                has_log_stats[host] = 1

            # Now mark it
            self.rsh(host, '''bash %s %s mark %s''' % (log_stats_bin, log_stats_file, testnum), synchronous=0)

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

class SysLog(Logger):
    # http://docs.python.org/lib/module-syslog.html
    defaultsource="CTS"
    map = {
            "kernel":   syslog.LOG_KERN,
            "user":     syslog.LOG_USER,
            "mail":     syslog.LOG_MAIL,
            "daemon":   syslog.LOG_DAEMON,
            "auth":     syslog.LOG_AUTH,
            "lpr":      syslog.LOG_LPR,
            "news":     syslog.LOG_NEWS,
            "uucp":     syslog.LOG_UUCP,
            "cron":     syslog.LOG_CRON,
            "local0":   syslog.LOG_LOCAL0,
            "local1":   syslog.LOG_LOCAL1,
            "local2":   syslog.LOG_LOCAL2,
            "local3":   syslog.LOG_LOCAL3,
            "local4":   syslog.LOG_LOCAL4,
            "local5":   syslog.LOG_LOCAL5,
            "local6":   syslog.LOG_LOCAL6,
            "local7":   syslog.LOG_LOCAL7,
    }
    def __init__(self, labinfo):

        if labinfo.has_key("syslogsource"):
            self.source=labinfo["syslogsource"]
        else:
            self.source=SysLog.defaultsource

	self.facility="daemon"

        if labinfo.has_key("SyslogFacility") and labinfo["SyslogFacility"]:
	    if SysLog.map.has_key(labinfo["SyslogFacility"]):
		self.facility=labinfo["SyslogFacility"]
	    else:
                raise ValueError("%s: bad syslog facility"%labinfo["SyslogFacility"])

	self.facility=SysLog.map[self.facility]
        syslog.openlog(self.source, 0, self.facility)

    def setfacility(self, facility):
        self.facility = facility
        if SysLog.map.has_key(self.facility):
          self.facility=SysLog.map[self.facility]
        syslog.closelog()
        syslog.openlog(self.source, 0, self.facility)


    def __call__(self, lines):
        if isinstance(lines, types.StringType):
            syslog.syslog(lines)
        else:
            for line in lines:
                syslog.syslog(line)

    def name(self):
        return "Syslog"

class StdErrLog(Logger):

    def __init__(self, labinfo):
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
    def __init__(self, labinfo, filename=None):

        if filename == None:
            filename=labinfo["LogFileName"]

        self.logfile=filename
        import os
        self.hostname = os.uname()[1]+" "
        self.source = "CTS: "
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

class AsyncWaitProc(Thread):
    def __init__(self, proc, node, command, Env):
        self.Env = Env
        self.proc = proc
        self.node = node
        self.command = command
        Thread.__init__(self)

    def log(self, args):
        if not self.Env:
            print (args)
        else:
            self.Env.log(args)

    def debug(self, args):
        if not self.Env:
            print (args)
        else:
            self.Env.debug(args)
    def run(self):
        self.debug("cmd: async: target=%s, pid=%d: %s" % (self.node, self.proc.pid, self.command))

        self.proc.wait()
        self.debug("cmd: pid %d returned %d" % (self.proc.pid, self.proc.returncode))

        if self.proc.stderr:
            lines = self.proc.stderr.readlines()
            self.proc.stderr.close()
            for line in lines:
                self.debug("cmd: stderr[%d]: %s" % (self.proc.pid, line))

        if self.proc.stdout:
            lines = self.proc.stdout.readlines()
            self.proc.stdout.close()
            for line in lines:
                self.debug("cmd: stdout[%d]: %s" % (self.proc.pid, line))

class RemoteExec:
    '''This is an abstract remote execution class.  It runs a command on another
       machine - somehow.  The somehow is up to us.  This particular
       class uses ssh.
       Most of the work is done by fork/exec of ssh or scp.
    '''

    def __init__(self, Env=None, silent=False):
        self.Env = Env
        self.async = []
        self.silent = silent

        if trace_rsh:
            self.silent = False

        #   -n: no stdin, -x: no X11,
        #   -o ServerAliveInterval=5 disconnect after 3*5s if the server stops responding
        self.Command = "ssh -l root -n -x -o ServerAliveInterval=5 -o ConnectTimeout=10 -o TCPKeepAlive=yes -o ServerAliveCountMax=3 "
        #        -B: batch mode, -q: no stats (quiet)
        self.CpCommand = "scp -B -q"

        self.OurNode=string.lower(os.uname()[1])

    def enable_qarsh(self):
        # http://nstraz.wordpress.com/2008/12/03/introducing-qarsh/
        self.log("Using QARSH for connections to cluster nodes")

        self.Command = "qarsh -t 300 -l root"
        self.CpCommand = "qacp -q"

    def _fixcmd(self, cmd):
        return re.sub("\'", "'\\''", cmd)

    def _cmd(self, *args):

        '''Compute the string that will run the given command on the
        given remote system'''

        args= args[0]
        sysname = args[0]
        command = args[1]

        #print "sysname: %s, us: %s" % (sysname, self.OurNode)
        if sysname == None or string.lower(sysname) == self.OurNode or sysname == "localhost":
            ret = command
        else:
            ret = self.Command + " " + sysname + " '" + self._fixcmd(command) + "'"
        #print ("About to run %s\n" % ret)
        return ret

    def log(self, args):
        if not self.silent:
            if not self.Env:
                print (args)
            else:
                self.Env.log(args)

    def debug(self, args):
        if not self.silent:
            if not self.Env:
                print (args)
            else:
                self.Env.debug(args)

    def __call__(self, node, command, stdout=0, synchronous=1, silent=False, blocking=True):
        '''Run the given command on the given remote system
        If you call this class like a function, this is the function that gets
        called.  It just runs it roughly as though it were a system() call
        on the remote machine.  The first argument is name of the machine to
        run it on.
        '''

        if trace_rsh:
            silent = False

        rc = 0
        result = None
        proc = Popen(self._cmd([node, command]),
                     stdout = PIPE, stderr = PIPE, close_fds = True, shell = True)

        if not synchronous and proc.pid > 0 and not self.silent:
            aproc = AsyncWaitProc(proc, node, command, self.Env)
            aproc.start()
            return 0

        #if not blocking:
        #    fcntl.fcntl(proc.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

        if proc.stdout:
            if stdout == 1:
                result = proc.stdout.readline()
            else:
                result = proc.stdout.readlines()
            proc.stdout.close()
        else:
            self.log("No stdout stream")

        rc = proc.wait()

        if not silent: self.debug("cmd: target=%s, rc=%d: %s" % (node, rc, command))

        if stdout == 1:
            return result

        if proc.stderr:
            errors = proc.stderr.readlines()
            proc.stderr.close()
            if not silent:
                for err in errors:
                    if stdout == 3:
                        result.append("error: "+err)
                    else:
                        self.debug("cmd: stderr: %s" % err)

        if stdout == 0:
            if not silent and result:
                for line in result:
                    self.debug("cmd: stdout: %s" % line)
            return rc

        return (rc, result)

    def cp(self, source, target, silent=False):
        '''Perform a remote copy'''
        cpstring = self.CpCommand  + " \'" + source + "\'"  + " \'" + target + "\'"
        rc = os.system(cpstring)
        if trace_rsh:
            silent = False
        if not silent: self.debug("cmd: rc=%d: %s" % (rc, cpstring))

        return rc


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
    def __init__(self, Env, filename, host=None, name=None):

        self.Env = Env
        self.host = host
        self.name = name
        self.filename = filename

        self.offset = "EOF"

        if host == None:
            host = "localhost"

    def __str__(self):
        if self.host:
            return "%s:%s" % (self.host, self.filename)
        return self.filename

    def log(self, args):
        message = "lw: %s: %s" % (self, args)
        if not self.Env:
            print (message)
        else:
            self.Env.log(message)

    def debug(self, args):
        message = "lw: %s: %s" % (self, args)
        if not self.Env:
            print (message)
        else:
            self.Env.debug(message)

    def next(self):
        self.log("Not implemented")

class FileObj(SearchObj):
    def __init__(self, Env, filename, host=None, name=None):
        global has_log_watcher
        SearchObj.__init__(self, Env, filename, host, name)

        if not has_log_watcher.has_key(host):

            global log_watcher
            global log_watcher_bin

            self.debug("Installing %s on %s" % (log_watcher_bin, host))
            self.Env.rsh(host, '''echo "%s" > %s''' % (log_watcher, log_watcher_bin), silent=True)
            has_log_watcher[host] = 1

        self.next()

    def next(self):
        cache = []

        global log_watcher_bin
        (rc, lines) = self.Env.rsh(
                self.host,
                "python %s -t %s -p CTSwatcher: -f %s -o %s" % (log_watcher_bin, self.name, self.filename, self.offset),
                stdout=None, silent=True, blocking=False)

        for line in lines:
            match = re.search("^CTSwatcher:Last read: (\d+)", line)
            if match:
                last_offset = self.offset
                self.offset = match.group(1)
                #if last_offset == "EOF": self.debug("Got %d lines, new offset: %s" % (len(lines), self.offset))

            elif re.search("^CTSwatcher:.*truncated", line):
                self.log(line)
            elif re.search("^CTSwatcher:", line):
                self.debug("Got control line: "+ line)
            else:
                cache.append(line)

        return cache

class JournalObj(SearchObj):

    def __init__(self, Env, host=None, name=None):
        SearchObj.__init__(self, Env, name, host, name)
        self.next()

    def next(self):
        cache = []
        command = "journalctl -q --after-cursor='%s' --show-cursor" % (self.offset)
        if self.offset == "EOF":
            command = "journalctl -q -n 0 --show-cursor"

        (rc, lines) = self.Env.rsh(self.host, command, stdout=None, silent=True, blocking=False)

        for line in lines:
            match = re.search("^-- cursor: ([^.]+)", line)
            if match:
                last_offset = self.offset
                self.offset = match.group(1)
                if last_offset == "EOF": self.debug("Got %d lines, new cursor: %s" % (len(lines), self.offset))
            else:
                cache.append(line)

        return cache

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

    def __init__(self, Env, log, regexes, name="Anon", timeout=10, debug_level=None, silent=False, hosts=None, kind=None):
        '''This is the constructor for the LogWatcher class.  It takes a
        log name to watch, and a list of regular expressions to watch for."
        '''
        RemoteExec.__init__(self, Env)

        #  Validate our arguments.  Better sooner than later ;-)
        for regex in regexes:
            assert re.compile(regex)

        if kind:
            self.kind    = kind
        else:
            self.kind    = self.Env["LogWatcher"]

        self.name        = name
        self.regexes     = regexes
        self.filename    = log
        self.debug_level = debug_level
        self.whichmatch  = -1
        self.unmatched   = None

        self.file_list = []
        self.line_cache = []

        if hosts:
            self.hosts = hosts
        else:
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
        if not self.Env:
            print (message)
        else:
            self.Env.debug(message)

    def setwatch(self):
        '''Mark the place to start watching the log from.
        '''

        if self.kind == "remote":
            for node in self.hosts:
                self.file_list.append(FileObj(self.Env, self.filename, node, self.name))

        elif self.kind == "journal":
            for node in self.hosts:
                self.file_list.append(JournalObj(self.Env, node, self.name))

        else:
            self.file_list.append(FileObj(self.Env, self.filename))

    def __del__(self):
        if self.debug_level > 1: self.debug("Destroy")

    def ReturnOnlyMatch(self, onlymatch=1):
        '''Specify one or more subgroups of the match to return rather than the whole string
           http://www.python.org/doc/2.5.2/lib/match-objects.html
        '''
        self.returnonlymatch = onlymatch

    def __get_lines(self):
        if not len(self.file_list):
            raise ValueError("No sources to read from")

        for f in self.file_list:
            lines = f.next()
            if len(lines):
                self.line_cache.extend(lines)

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

        while True:

            if len(self.line_cache):
                lines += 1
                line = self.line_cache[0]
                self.line_cache.remove(line)

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

            elif timeout > 0 and end > time.time():
                if self.debug_level > 1: self.debug("lines during timeout")
                time.sleep(1)
                self.__get_lines()

            elif needlines:
                # Grab any relevant messages that might have arrived since
                # the last time the buffer was populated
                if self.debug_level > 1: self.debug("lines without timeout")
                self.__get_lines()

                # Don't come back here again
                needlines = False

            else:
                self.debug("Single search terminated: start=%d, end=%d, now=%d, lines=%d" % (begin, end, time.time(), lines))
                return None

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

class NodeStatus:
    def __init__(self, Env):
        self.Env = Env

    def IsNodeBooted(self, node):
        '''Return TRUE if the given node is booted (responds to pings)'''
        return self.Env.rsh("localhost", "ping -nq -c1 -w1 %s" % node, silent=True) == 0

    def IsSshdUp(self, node):
        rc = self.Env.rsh(node, "true", silent=True)
        return rc == 0

    def WaitForNodeToComeUp(self, node, Timeout=300):
        '''Return TRUE when given node comes up, or None/FALSE if timeout'''
        timeout=Timeout
        anytimeouts=0
        while timeout > 0:
            if self.IsNodeBooted(node) and self.IsSshdUp(node):
                if anytimeouts:
                     # Fudge to wait for the system to finish coming up
                     time.sleep(30)
                     self.Env.debug("Node %s now up" % node)
                return 1

            time.sleep(30)
            if (not anytimeouts):
                self.Env.debug("Waiting for node %s to come up" % node)

            anytimeouts=1
            timeout = timeout - 1

        self.Env.log("%s did not come up within %d tries" % (node, Timeout))
        answer = raw_input('Continue? [nY]')
        if answer and answer == "n":
            raise ValueError("%s did not come up within %d tries" % (node, Timeout))

    def WaitForAllNodesToComeUp(self, nodes, timeout=300):
        '''Return TRUE when all nodes come up, or FALSE if timeout'''

        for node in nodes:
            if not self.WaitForNodeToComeUp(node, timeout):
                return None
        return 1

class ClusterManager(UserDict):
    '''The Cluster Manager class.
    This is an subclass of the Python dictionary class.
    (this is because it contains lots of {name,value} pairs,
    not because it's behavior is that terribly similar to a
    dictionary in other ways.)

    This is an abstract class which class implements high-level
    operations on the cluster and/or its cluster managers.
    Actual cluster managers classes are subclassed from this type.

    One of the things we do is track the state we think every node should
    be in.
    '''


    def __InitialConditions(self):
        #if os.geteuid() != 0:
        #  raise ValueError("Must Be Root!")
        None

    def _finalConditions(self):
        for key in self.keys():
            if self[key] == None:
                raise ValueError("Improper derivation: self[" + key
                +   "] must be overridden by subclass.")

    def __init__(self, Environment, randseed=None):
        self.Env = Environment
        self.__InitialConditions()
        self.clear_cache = 0
        self.TestLoggingLevel=0
        self.data = {
            "up"             : "up",        # Status meaning up
            "down"           : "down",  # Status meaning down
            "StonithCmd"     : "stonith -t baytech -p '10.10.10.100 admin admin' %s",
            "DeadTime"       : 30,        # Max time to detect dead node...
            "StartTime"      : 90,        # Max time to start up
    #
    # These next values need to be overridden in the derived class.
    #
            "Name"           : None,
            "StartCmd"       : None,
            "StopCmd"        : None,
            "StatusCmd"      : None,
            #"RereadCmd"      : None,
            "BreakCommCmd"   : None,
            "FixCommCmd"     : None,
            #"TestConfigDir"  : None,
            "LogFileName"    : None,

            #"Pat:Master_started"   : None,
            #"Pat:Slave_started" : None,
            "Pat:We_stopped"   : None,
            "Pat:They_stopped" : None,

            "Pat:InfraUp"      : "%s",
            "Pat:PacemakerUp"  : "%s",

            "BadRegexes"     : None,        # A set of "bad news" regexes
                                        # to apply to the log
        }

        self.rsh = self.Env.rsh
        self.ShouldBeStatus={}
        self.ns = NodeStatus(self.Env)
        self.OurNode=string.lower(os.uname()[1])
        self.__instance_errorstoignore = []

    def key_for_node(self, node):
        return node

    def instance_errorstoignore_clear(self):
        '''Allows the test scenario to reset instance errors to ignore on each iteration.'''
        self.__instance_errorstoignore = []

    def instance_errorstoignore(self):
        '''Return list of errors which are 'normal' for a specific test instance'''
        return self.__instance_errorstoignore

    def errorstoignore(self):
        '''Return list of errors which are 'normal' and should be ignored'''
        return []

    def log(self, args):
        self.Env.log(args)

    def debug(self, args):
        self.Env.debug(args)

    def prepare(self):
        '''Finish the Initialization process. Prepare to test...'''

        for node in self.Env["nodes"]:
            if self.StataCM(node):
                self.ShouldBeStatus[node]="up"
            else:
                self.ShouldBeStatus[node]="down"

            self.unisolate_node(node)

    def upcount(self):
        '''How many nodes are up?'''
        count=0
        for node in self.Env["nodes"]:
          if self.ShouldBeStatus[node]=="up":
            count=count+1
        return count

    def install_helper(self, filename, destdir=None, nodes=None, sourcedir=None):
        if sourcedir == None:
            sourcedir = CTSvars.CTS_home
        file_with_path="%s/%s" % (sourcedir, filename)
        if not nodes:
            nodes = self.Env["nodes"]

        if not destdir:
            destdir=CTSvars.CTS_home

        self.debug("Installing %s to %s on %s" % (filename, destdir, repr(self.Env["nodes"])))
        for node in nodes:
            self.rsh(node, "mkdir -p %s" % destdir)
            self.rsh.cp(file_with_path, "root@%s:%s/%s" % (node, destdir, filename))
        return file_with_path

    def install_config(self, node):
        return None

    def clear_all_caches(self):
        if self.clear_cache:
            for node in self.Env["nodes"]:
                if self.ShouldBeStatus[node] == "down":
                    self.debug("Removing cache file on: "+node)
                    self.rsh(node, "rm -f "+CTSvars.HA_VARLIBHBDIR+"/hostcache")
                else:
                    self.debug("NOT Removing cache file on: "+node)

    def prepare_fencing_watcher(self, node):
        # If we don't have quorum now but get it as a result of starting this node,
        # then a bunch of nodes might get fenced
        upnode=None
        if self.HasQuorum(None):
            return None

        if not self.has_key("Pat:Fencing_start"):
            return None

        if not self.has_key("Pat:Fencing_ok"):
            return None

        stonith = None
        stonithPats = []
        for peer in self.Env["nodes"]:
            if peer != node and self.ShouldBeStatus[peer] != "up":
                stonithPats.append(self["Pat:Fencing_ok"] % peer)
                stonithPats.append(self["Pat:Fencing_start"] % peer)
            elif self.Env["Stack"] == "corosync (cman)":
                # There is a delay between gaining quorum and CMAN starting fencing
                # This can mean that even nodes that are fully up get fenced
                # There is no use fighting it, just look for everyone so that CTS doesn't get confused
                stonithPats.append(self["Pat:Fencing_ok"] % peer)
                stonithPats.append(self["Pat:Fencing_start"] % peer)

            if peer != node and not upnode and self.ShouldBeStatus[peer] == "up":
                upnode = peer

        # Look for STONITH ops, depending on Env["at-boot"] we might need to change the nodes status
        if not upnode:
            return None

        stonith = LogWatcher(self.Env, self["LogFileName"], stonithPats, "StartupFencing", 0, hosts=[upnode])
        stonith.setwatch()
        return stonith

    def fencing_cleanup(self, node, stonith):
        peer_list = []
        peer_state = {}

        self.debug("Looking for nodes that were fenced as a result of %s starting" % node)

        # If we just started a node, we may now have quorum (and permission to fence)
        if not stonith:
            self.debug("Nothing to do")
            return peer_list

        q = self.HasQuorum(None)
        if not q and len(self.Env["nodes"]) > 2:
            # We didn't gain quorum - we shouldn't have shot anyone
            self.debug("Quorum: %d Len: %d" % (q, len(self.Env["nodes"])))
            return peer_list

        # Now see if any states need to be updated
        self.debug("looking for: " + repr(stonith.regexes))
        shot = stonith.look(0)
        while shot:
            line = repr(shot)
            self.debug("Found: "+ line)
            del stonith.regexes[stonith.whichmatch]

            # Extract node name
            for n in self.Env["nodes"]:
                if re.search(self["Pat:Fencing_ok"] % n, shot):
                    peer = n
                    peer_state[peer] = "complete"
                    self.__instance_errorstoignore.append(self["Pat:Fencing_ok"] % peer)

                elif re.search(self["Pat:Fencing_start"] % n, shot):
                    peer = n
                    peer_state[peer] = "in-progress"
                    self.__instance_errorstoignore.append(self["Pat:Fencing_start"] % peer)

            if not peer:
                self.log("ERROR: Unknown stonith match: %s" % line)

            elif not peer in peer_list:
                self.debug("Found peer: "+ peer)
                peer_list.append(peer)

            # Get the next one
            shot = stonith.look(60)

        for peer in peer_list:

            self.debug("   Peer %s was fenced as a result of %s starting: %s" % (peer, node, peer_state[peer]))
            if self.Env["at-boot"]:
                self.ShouldBeStatus[peer] = "up"
            else:
                self.ShouldBeStatus[peer] = "down"

            if peer_state[peer] == "in-progress":
                # Wait for any in-progress operations to complete
                shot = stonith.look(60)
                while len(stonith.regexes) and shot:
                    line = repr(shot)
                    self.debug("Found: "+ line)
                    del stonith.regexes[stonith.whichmatch]
                    shot = stonith.look(60)

            # Now make sure the node is alive too
            self.ns.WaitForNodeToComeUp(peer, self["DeadTime"])

            # Poll until it comes up
            if self.Env["at-boot"]:
                if not self.StataCM(peer):
                    time.sleep(self["StartTime"])

                if not self.StataCM(peer):
                    self.log("ERROR: Peer %s failed to restart after being fenced" % peer)
                    return None

        return peer_list

    def StartaCM(self, node, verbose=False):

        '''Start up the cluster manager on a given node'''
        if verbose: self.log("Starting %s on node %s" %(self["Name"], node))
        else: self.debug("Starting %s on node %s" %(self["Name"], node))
        ret = 1

        if not self.ShouldBeStatus.has_key(node):
            self.ShouldBeStatus[node] = "down"

        if self.ShouldBeStatus[node] != "down":
            return 1

        patterns = []
        # Technically we should always be able to notice ourselves starting
        patterns.append(self["Pat:Local_started"] % node)
        if self.upcount() == 0:
            patterns.append(self["Pat:Master_started"] % node)
        else:
            patterns.append(self["Pat:Slave_started"] % node)

        watch = LogWatcher(
            self.Env, self["LogFileName"], patterns, "StartaCM", self["StartTime"]+10)

        self.install_config(node)

        self.ShouldBeStatus[node] = "any"
        if self.StataCM(node) and self.cluster_stable(self["DeadTime"]):
            self.log ("%s was already started" %(node))
            return 1

        # Clear out the host cache so autojoin can be exercised
        if self.clear_cache:
            self.debug("Removing cache file on: "+node)
            self.rsh(node, "rm -f "+CTSvars.HA_VARLIBHBDIR+"/hostcache")

        if not(self.Env["valgrind-tests"]):
            startCmd = self["StartCmd"]
        else:
            if self.Env["valgrind-prefix"]:
                prefix = self.Env["valgrind-prefix"]
            else:
                prefix = "cts"

            startCmd = """G_SLICE=always-malloc HA_VALGRIND_ENABLED='%s' VALGRIND_OPTS='%s --log-file=/tmp/%s-%s.valgrind' %s""" % (
                self.Env["valgrind-procs"], self.Env["valgrind-opts"], prefix, """%p""", self["StartCmd"])

        stonith = self.prepare_fencing_watcher(node)

        watch.setwatch()

        if self.rsh(node, startCmd) != 0:
            self.log ("Warn: Start command failed on node %s" %(node))
            self.fencing_cleanup(node, stonith)
            return None

        self.ShouldBeStatus[node]="up"
        watch_result = watch.lookforall()

        if watch.unmatched:
            for regex in watch.unmatched:
                self.log ("Warn: Startup pattern not found: %s" %(regex))

        if watch_result and self.cluster_stable(self["DeadTime"]):
            #self.debug("Found match: "+ repr(watch_result))
            self.fencing_cleanup(node, stonith)
            return 1

        elif self.StataCM(node) and self.cluster_stable(self["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return 1

        self.log ("Warn: Start failed for node %s" %(node))
        return None

    def StartaCMnoBlock(self, node, verbose=False):

        '''Start up the cluster manager on a given node with none-block mode'''

        if verbose: self.log("Starting %s on node %s" %(self["Name"], node))
        else: self.debug("Starting %s on node %s" %(self["Name"], node))

        # Clear out the host cache so autojoin can be exercised
        if self.clear_cache:
            self.debug("Removing cache file on: "+node)
            self.rsh(node, "rm -f "+CTSvars.HA_VARLIBHBDIR+"/hostcache")

        self.install_config(node)
        if not(self.Env["valgrind-tests"]):
            startCmd = self["StartCmd"]
        else:
            if self.Env["valgrind-prefix"]:
                prefix = self.Env["valgrind-prefix"]
            else:
                prefix = "cts"

            startCmd = """G_SLICE=always-malloc HA_VALGRIND_ENABLED='%s' VALGRIND_OPTS='%s --log-file=/tmp/%s-%s.valgrind' %s""" % (
                self.Env["valgrind-procs"], self.Env["valgrind-opts"], prefix, """%p""", self["StartCmd"])

        self.rsh(node, startCmd, synchronous=0)
        self.ShouldBeStatus[node]="up"
        return 1

    def StopaCM(self, node, verbose=False, force=False):

        '''Stop the cluster manager on a given node'''

        if verbose: self.log("Stopping %s on node %s" %(self["Name"], node))
        else: self.debug("Stopping %s on node %s" %(self["Name"], node))

        if self.ShouldBeStatus[node] != "up" and force == False:
            return 1

        if self.rsh(node, self["StopCmd"]) == 0:
            # Make sure we can continue even if corosync leaks
            # fdata-* is the old name
            #self.rsh(node, "rm -f /dev/shm/qb-* /dev/shm/fdata-*")
            self.ShouldBeStatus[node]="down"
            self.cluster_stable(self["DeadTime"])
            return 1
        else:
            self.log ("ERROR: Could not stop %s on node %s" %(self["Name"], node))

        return None

    def StopaCMnoBlock(self, node):

        '''Stop the cluster manager on a given node with none-block mode'''

        self.debug("Stopping %s on node %s" %(self["Name"], node))

        self.rsh(node, self["StopCmd"], synchronous=0)
        self.ShouldBeStatus[node]="down"
        return 1

    def cluster_stable(self, timeout = None):
        time.sleep(self["StableTime"])
        return 1

    def node_stable(self, node):
        return 1

    def RereadCM(self, node):

        '''Force the cluster manager on a given node to reread its config
           This may be a no-op on certain cluster managers.
        '''
        rc=self.rsh(node, self["RereadCmd"])
        if rc == 0:
            return 1
        else:
            self.log ("Could not force %s on node %s to reread its config"
            %        (self["Name"], node))
        return None


    def StataCM(self, node):

        '''Report the status of the cluster manager on a given node'''

        out=self.rsh(node, self["StatusCmd"] % node, 1)
        ret= (string.find(out, 'stopped') == -1)

        try:
            if ret:
                if self.ShouldBeStatus[node] == "down":
                    self.log(
                    "Node status for %s is %s but we think it should be %s"
                    %        (node, "up", self.ShouldBeStatus[node]))
            else:
                if self.ShouldBeStatus[node] == "up":
                    self.log(
                    "Node status for %s is %s but we think it should be %s"
                    %        (node, "down", self.ShouldBeStatus[node]))
        except KeyError:        pass

        if ret:        self.ShouldBeStatus[node]="up"
        else:        self.ShouldBeStatus[node]="down"
        return ret

    def startall(self, nodelist=None, verbose=False, quick=False):

        '''Start the cluster manager on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''
        map = {}
        if not nodelist:
            nodelist=self.Env["nodes"]

        for node in nodelist:
            if self.ShouldBeStatus[node] == "down":
                self.ns.WaitForAllNodesToComeUp(nodelist, 300)

        if not quick:
            if not self.StartaCM(node, verbose=verbose):
                return 0
            return 1

        # Approximation of SimulStartList for --boot 
        watchpats = [ ]
        watchpats.append(self["Pat:DC_IDLE"])
        for node in nodelist:
            watchpats.append(self["Pat:Local_started"] % node)
            watchpats.append(self["Pat:InfraUp"] % node)
            watchpats.append(self["Pat:PacemakerUp"] % node)

        #   Start all the nodes - at about the same time...
        watch = LogWatcher(self.Env, self["LogFileName"], watchpats, "fast-start", self["DeadTime"]+10)
        watch.setwatch()

        if not self.StartaCM(nodelist[0], verbose=verbose):
            return 0
        for node in nodelist:
            self.StartaCMnoBlock(node, verbose=verbose)

        watch.lookforall()
        if watch.unmatched:
            for regex in watch.unmatched:
                self.log ("Warn: Startup pattern not found: %s" %(regex))

        if not self.cluster_stable():
            self.log("Cluster did not stabilize")
            return 0

        return 1

    def stopall(self, nodelist=None, verbose=False, force=False):

        '''Stop the cluster managers on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        ret = 1
        map = {}
        if not nodelist:
            nodelist=self.Env["nodes"]
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up" or force == True:
                if not self.StopaCM(node, verbose=verbose, force=force):
                    ret = 0
        return ret

    def rereadall(self, nodelist=None):

        '''Force the cluster managers on every node in the cluster
        to reread their config files.  We can do it on a subset of the
        cluster if nodelist is not None.
        '''

        map = {}
        if not nodelist:
            nodelist=self.Env["nodes"]
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                self.RereadCM(node)


    def statall(self, nodelist=None):

        '''Return the status of the cluster managers in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        result={}
        if not nodelist:
            nodelist=self.Env["nodes"]
        for node in nodelist:
            if self.StataCM(node):
                result[node] = "up"
            else:
                result[node] = "down"
        return result

    def isolate_node(self, target, nodes=None):
        '''isolate the communication between the nodes'''
        if not nodes:
            nodes = self.Env["nodes"]

        for node in nodes:
            if node != target:
                rc = self.rsh(target, self["BreakCommCmd"] % self.key_for_node(node))
                if rc != 0:
                    self.log("Could not break the communication between %s and %s: %d" % (target, node, rc))
                    return None
                else:
                    self.debug("Communication cut between %s and %s" % (target, node))
        return 1

    def unisolate_node(self, target, nodes=None):
        '''fix the communication between the nodes'''
        if not nodes:
            nodes = self.Env["nodes"]

        for node in nodes:
            if node != target:
                restored = 0

                # Limit the amount of time we have asynchronous connectivity for
                # Restore both sides as simultaneously as possible
                self.rsh(target, self["FixCommCmd"] % self.key_for_node(node), synchronous=0)
                self.rsh(node, self["FixCommCmd"] % self.key_for_node(target), synchronous=0)
                self.debug("Communication restored between %s and %s" % (target, node))

    def reducecomm_node(self,node):
        '''reduce the communication between the nodes'''
        rc = self.rsh(node, self["ReduceCommCmd"]%(self.Env["XmitLoss"],self.Env["RecvLoss"]))
        if rc == 0:
            return 1
        else:
            self.log("Could not reduce the communication between the nodes from node: %s" % node)
        return None

    def restorecomm_node(self,node):
        '''restore the saved communication between the nodes'''
        rc = 0
        if float(self.Env["XmitLoss"])!=0 or float(self.Env["RecvLoss"])!=0 :
            rc = self.rsh(node, self["RestoreCommCmd"]);
        if rc == 0:
            return 1
        else:
            self.log("Could not restore the communication between the nodes from node: %s" % node)
        return None

    def HasQuorum(self, node_list):
        "Return TRUE if the cluster currently has quorum"
        # If we are auditing a partition, then one side will
        #   have quorum and the other not.
        # So the caller needs to tell us which we are checking
        # If no value for node_list is specified... assume all nodes
        raise ValueError("Abstract Class member (HasQuorum)")

    def Components(self):
        raise ValueError("Abstract Class member (Components)")

    def oprofileStart(self, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileStart(n)

        elif node in self.Env["oprofile"]:
            self.debug("Enabling oprofile on %s" % node)
            self.rsh(node, "opcontrol --init")
            self.rsh(node, "opcontrol --setup --no-vmlinux --separate=lib --callgraph=20 --image=all")
            self.rsh(node, "opcontrol --start")
            self.rsh(node, "opcontrol --reset")

    def oprofileSave(self, test, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileSave(test, n)

        elif node in self.Env["oprofile"]:
            self.rsh(node, "opcontrol --dump")
            self.rsh(node, "opcontrol --save=cts.%d" % test)
            # Read back with: opreport -l session:cts.0 image:/usr/lib/heartbeat/c*
            if None:
                self.rsh(node, "opcontrol --reset")
            else:
                self.oprofileStop(node)
                self.oprofileStart(node)

    def oprofileStop(self, node=None):
        if not node:
            for n in self.Env["oprofile"]:
                self.oprofileStop(n)

        elif node in self.Env["oprofile"]:
            self.debug("Stopping oprofile on %s" % node)
            self.rsh(node, "opcontrol --reset")
            self.rsh(node, "opcontrol --shutdown 2>&1 > /dev/null")


class Resource:
    '''
    This is an HA resource (not a resource group).
    A resource group is just an ordered list of Resource objects.
    '''

    def __init__(self, cm, rsctype=None, instance=None):
        self.CM = cm
        self.ResourceType = rsctype
        self.Instance = instance
        self.needs_quorum = 1

    def Type(self):
        return self.ResourceType

    def Instance(self, nodename):
        return self.Instance

    def IsRunningOn(self, nodename):
        '''
        This member function returns true if our resource is running
        on the given node in the cluster.
        It is analagous to the "status" operation on SystemV init scripts and
        heartbeat scripts.  FailSafe calls it the "exclusive" operation.
        '''
        raise ValueError("Abstract Class member (IsRunningOn)")
        return None

    def IsWorkingCorrectly(self, nodename):
        '''
        This member function returns true if our resource is operating
        correctly on the given node in the cluster.
        Heartbeat does not require this operation, but it might be called
        the Monitor operation, which is what FailSafe calls it.
        For remotely monitorable resources (like IP addresses), they *should*
        be monitored remotely for testing.
        '''
        raise ValueError("Abstract Class member (IsWorkingCorrectly)")
        return None


    def Start(self, nodename):
        '''
        This member function starts or activates the resource.
        '''
        raise ValueError("Abstract Class member (Start)")
        return None

    def Stop(self, nodename):
        '''
        This member function stops or deactivates the resource.
        '''
        raise ValueError("Abstract Class member (Stop)")
        return None

    def __repr__(self):
        if (self.Instance and len(self.Instance) > 1):
                return "{" + self.ResourceType + "::" + self.Instance + "}"
        else:
                return "{" + self.ResourceType + "}"
class Component:
    def kill(self, node):
        None

class Process(Component):
    def __init__(self, cm, name, process=None, dc_only=0, pats=[], dc_pats=[], badnews_ignore=[], common_ignore=[], triggersreboot=0):
        self.name = str(name)
        self.dc_only = dc_only
        self.pats = pats
        self.dc_pats = dc_pats
        self.CM = cm
        self.badnews_ignore = badnews_ignore
        self.badnews_ignore.extend(common_ignore)
	self.triggersreboot = triggersreboot

        if process:
            self.proc = str(process)
        else:
            self.proc = str(name)
        self.KillCmd = "killall -9 " + self.proc

    def kill(self, node):
        if self.CM.rsh(node, self.KillCmd) != 0:
            self.CM.log ("ERROR: Kill %s failed on node %s" %(self.name,node))
            return None
        return 1
