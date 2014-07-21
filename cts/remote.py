'''
Classes related to running command remotely
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

from cts.logging import LogFactory 

from socket import gethostbyname_ex
from UserDict import UserDict
from subprocess import Popen,PIPE

pdir=os.path.dirname(sys.path[0])
sys.path.insert(0, pdir) # So that things work from the source directory

from cts.CTSvars import *
from cts.logging import *
from threading import Thread

trace_rsh=None
trace_lw=None

class AsyncWaitProc(Thread):
    def __init__(self, proc, node, command, completionDelegate=None):
        self.proc = proc
        self.node = node
        self.command = command
        self.logger = LogFactory()
        self.delegate = completionDelegate;
        Thread.__init__(self)

    def run(self):
        outLines = None
        errLines = None
        self.logger.debug("cmd: async: target=%s, pid=%d: %s" % (self.node, self.proc.pid, self.command))

        self.proc.wait()
        self.logger.debug("cmd: pid %d returned %d" % (self.proc.pid, self.proc.returncode))

        if self.proc.stderr:
            errLines = self.proc.stderr.readlines()
            self.proc.stderr.close()
            for line in errLines:
                self.logger.debug("cmd: stderr[%d]: %s" % (self.proc.pid, line))

        if self.proc.stdout:
            outLines = self.proc.stdout.readlines()
            self.proc.stdout.close()
#            for line in outLines:
#                self.logger.debug("cmd: stdout[%d]: %s" % (self.proc.pid, line))

        if self.delegate:
            self.delegate.async_complete(self.proc.pid, self.proc.returncode, outLines, errLines)

class RemotePrimitives:
    def __init__(self, Command=None, CpCommand=None):
        if CpCommand:
            self.CpCommand = CpCommand
        else:
            #        -B: batch mode, -q: no stats (quiet)
            self.CpCommand = "scp -B -q"

        if Command:
            self.Command = Command
        else:
            #   -n: no stdin, -x: no X11,
            #   -o ServerAliveInterval=5 disconnect after 3*5s if the server stops responding
            self.Command = "ssh -l root -n -x -o ServerAliveInterval=5 -o ConnectTimeout=10 -o TCPKeepAlive=yes -o ServerAliveCountMax=3 "

class RemoteExec:
    '''This is an abstract remote execution class.  It runs a command on another
       machine - somehow.  The somehow is up to us.  This particular
       class uses ssh.
       Most of the work is done by fork/exec of ssh or scp.
    '''

    def __init__(self, rsh, silent=False):
        print repr(self)
        self.async = []
        self.rsh = rsh
        self.silent = silent
        self.logger = LogFactory()

        if trace_rsh:
            self.silent = False

        self.OurNode=string.lower(os.uname()[1])

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
            ret = self.rsh.Command + " " + sysname + " '" + self._fixcmd(command) + "'"
        #print ("About to run %s\n" % ret)
        return ret

    def log(self, args):
        if not self.silent:
            self.logger.log(args)

    def debug(self, args):
        if not self.silent:
            self.logger.debug(args)

    def __call__(self, node, command, stdout=0, synchronous=1, silent=False, blocking=True, completionDelegate=None):
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

        #if completionDelegate: print "Waiting for %d on %s: %s" % (proc.pid, node, command)
        if not synchronous and proc.pid > 0 and not self.silent:
            aproc = AsyncWaitProc(proc, node, command, completionDelegate=completionDelegate)
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

        if completionDelegate:
            completionDelegate.async_complete(proc.pid, proc.returncode, result, errors)

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
        cpstring = self.rsh.CpCommand  + " \'" + source + "\'"  + " \'" + target + "\'"
        rc = os.system(cpstring)
        if trace_rsh:
            silent = False
        if not silent: self.debug("cmd: rc=%d: %s" % (rc, cpstring))

        return rc

class RemoteFactory:
    # Class variables
    rsh = RemotePrimitives()
    instance = None

    def getInstance(self):
        if not RemoteFactory.instance:
            RemoteFactory.instance = RemoteExec(RemoteFactory.rsh, False)
        return RemoteFactory.instance

    def new(self, silent=False):
        return RemoteExec(RemoteFactory.rsh, silent)

    def enable_qarsh(self):
        # http://nstraz.wordpress.com/2008/12/03/introducing-qarsh/
        print "Using QARSH for connections to cluster nodes"

        RemoteFactory.rsh.Command = "qarsh -t 300 -l root"
        RemoteFactory.rsh.CpCommand = "qacp -q"

