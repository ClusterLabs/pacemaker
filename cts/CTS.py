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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import types, string, select, sys, time, re, os, struct, os, signal
import base64, pickle, binascii
from UserDict import UserDict
from syslog import *
from subprocess import Popen,PIPE
from CTSvars import *

class RemoteExec:
    '''This is an abstract remote execution class.  It runs a command on another
       machine - somehow.  The somehow is up to us.  This particular
       class uses ssh.
       Most of the work is done by fork/exec of ssh or scp.
    '''

    def __init__(self, Env=None):
        self.Env = Env

        #        -n: no stdin, -x: no X11
        self.Command = "ssh -l root -n -x"
        #         -f: ssh to background
        self.CommandnoBlock = "ssh -f -l root -n -x"
        #        -B: batch mode, -q: no stats (quiet)
        self.CpCommand = "scp -B -q"

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
            ret = self.Command + " " + sysname + " '" + self._fixcmd(command) + "'"
        #print ("About to run %s\n" % ret)
        return ret

    def _cmd_noblock(self, *args):

        '''Compute the string that will run the given command on the
        given remote system'''

        args= args[0]
        sysname = args[0]
        command = args[1]

        #print "sysname: %s, us: %s" % (sysname, self.OurNode)
        if sysname == None or string.lower(sysname) == self.OurNode or sysname == "localhost":
            ret = command + " &"
        else:
            ret = self.CommandnoBlock + " " + sysname + " '" + self._fixcmd(command) + "'"
        #print ("About to run %s\n" % ret)
        return ret

    def __call__(self, node, command, stdout=0, blocking=1):
        '''Run the given command on the given remote system
        If you call this class like a function, this is the function that gets
        called.  It just runs it roughly as though it were a system() call
        on the remote machine.  The first argument is name of the machine to
        run it on.
        '''

        rc = 0
        result = None
        if not blocking:
            return os.system(self._cmd_noblock([node, command]))
        
        conn = Popen(self._cmd([node, command]),
                     stdin = PIPE, stdout = PIPE, stderr = PIPE, close_fds = True, shell = True)
        conn.stdin.close()

        if stdout == 1:
            result = conn.stdout.readline()
        else:
            result = conn.stdout.readlines()

        conn.stdout.close()
        rc = conn.wait()

        self.Env.debug("cmd: target=%s, rc=%d: %s" % (node, rc, command))

        if stdout == 1:
            return result

        if conn.stderr:
            errors = conn.stderr.readlines()
            conn.stderr.close()
            for err in errors:
                if not self.Env:
                    print ("stderr: %s" % err)
                else:
                    self.Env.debug("stderr: %s" % err)

        if stdout == 0:
            return rc

        return (rc, result)

    def cp(self, *args):
        '''Perform a remote copy'''
        cpstring = self.CpCommand
        for arg in args:
            cpstring = cpstring + " \'" + arg + "\'"
            
        rc = os.system(cpstring)
        self.Env.debug("cmd: rc=%d: %s" % (rc, cpstring))
        
        return rc

class LogWatcher:

    '''This class watches logs for messages that fit certain regular
       expressions.  Watching logs for events isn't the ideal way
       to do business, but it's better than nothing :-)

       On the other hand, this class is really pretty cool ;-)

       The way you use this class is as follows:
          Construct a LogWatcher object
          Call setwatch() when you want to start watching the log
          Call look() to scan the log looking for the patterns
    '''

    def __init__(self, log, regexes, timeout=10, debug=None):
        '''This is the constructor for the LogWatcher class.  It takes a
        log name to watch, and a list of regular expressions to watch for."
        '''

        #  Validate our arguments.  Better sooner than later ;-)
        for regex in regexes:
            assert re.compile(regex)
        self.regexes = regexes
        self.filename = log
        self.debug=debug
        self.whichmatch = -1
        self.unmatched = None
        if self.debug:
            print "Debug now on for for log", log
        self.Timeout = int(timeout)
        self.returnonlymatch = None
        if not os.access(log, os.R_OK):
            raise ValueError("File [" + log + "] not accessible (r)")

    def setwatch(self, frombeginning=None):
        '''Mark the place to start watching the log from.
        '''
        self.file = open(self.filename, "r")
        self.size = os.path.getsize(self.filename)
        if not frombeginning:
            self.file.seek(0, 2)  # 2 means seek to EOF

    def ReturnOnlyMatch(self, onlymatch=1):
        '''Mark the place to start watching the log from.
        '''
        self.returnonlymatch = onlymatch

    def look(self, timeout=None):
        '''Examine the log looking for the given patterns.
        It starts looking from the place marked by setwatch().
        This function looks in the file in the fashion of tail -f.
        It properly recovers from log file truncation, but not from
        removing and recreating the log.  It would be nice if it
        recovered from this as well :-)

        We return the first line which matches any of our patterns.
        '''
        last_line=None
        first_line=None
        if timeout == None: timeout = self.Timeout

        done=time.time()+timeout+1
        if self.debug:
            print "starting search: timeout=%d" % timeout
            for regex in self.regexes:
                print "Looking for regex: ", regex

        while (timeout <= 0 or time.time() <= done):
            newsize=os.path.getsize(self.filename)
            if self.debug > 4: print "newsize = %d" % newsize
            if newsize < self.size:
                # Somebody truncated the log!
                if self.debug: print "Log truncated!"
                self.setwatch(frombeginning=1)
                continue
            if newsize > self.file.tell():
                line=self.file.readline()
                if self.debug > 2: print "Looking at line:", line
                if line:
                    last_line=line
                    if not first_line:
                        first_line=line
                        if self.debug: print "First line: "+ line
                    which=-1
                    for regex in self.regexes:
                        which=which+1
                        if self.debug > 3: print "Comparing line to ", regex
                        #matchobj = re.search(string.lower(regex), string.lower(line))
                        matchobj = re.search(regex, line)
                        if matchobj:
                            self.whichmatch=which
                            if self.returnonlymatch:
                              return matchobj.group(self.returnonlymatch)
                            else:
                              if self.debug: print "Returning line"
                              return line
            newsize=os.path.getsize(self.filename)
            if self.file.tell() == newsize:
                if timeout > 0:
                    time.sleep(0.025)
                else:
                    if self.debug: print "End of file"
                    if self.debug: print "Last line: "+last_line
                    return None
        if self.debug: print "Timeout"
        if self.debug: print "Last line: "+last_line
        return None

    def lookforall(self, timeout=None, allow_multiple_matches=None):
        '''Examine the log looking for ALL of the given patterns.
        It starts looking from the place marked by setwatch().

        We return when the timeout is reached, or when we have found
        ALL of the regexes that were part of the watch
        '''

        if timeout == None: timeout = self.Timeout
        save_regexes = self.regexes
        returnresult = []

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
        return self.Env.rsh("localhost", "ping -nq -c1 -w1 %s >/dev/null 2>&1" % node, 0) == 0

    def IsSshdUp(self, node):
         #return self.rsh(node, "true") == 0;
        rc = self.Env.rsh(node, "true")
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

            "BadRegexes"     : None,        # A set of "bad news" regexes
                                        # to apply to the log
        }

        self.rsh = self.Env.rsh
        self.ShouldBeStatus={}
        self.OurNode=string.lower(os.uname()[1])
        self.ShouldBeStatus={}
        self.ns = NodeStatus(self.Env)

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

    def TruncLogs(self):
        '''Truncate the log for the cluster manager so we can start clean'''
        if self["LogFileName"] != None:
            self.Env.rsh("localhost", "cp /dev/null " + self["LogFileName"])

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

    def StartaCM(self, node):

        '''Start up the cluster manager on a given node'''
        self.debug("Starting %s on node %s" %(self["Name"], node))
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
            self["LogFileName"], patterns, timeout=self["StartTime"]+10)
        
        watch.setwatch()

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

        if self.rsh(node, startCmd) != 0:
            self.log ("Warn: Start command failed on node %s" %(node))
            return None

        self.ShouldBeStatus[node]="up"

        watch_result = watch.lookforall()
        if watch.unmatched:
            for regex in watch.unmatched:
                self.log ("Warn: Startup pattern not found: %s" %(regex))

        if watch_result:  
            #self.debug("Found match: "+ repr(watch_result))
            self.cluster_stable(self["DeadTime"])
            return 1

        if self.StataCM(node) and self.cluster_stable(self["DeadTime"]):
            return 1

        self.log ("Warn: Start failed for node %s" %(node))
        return None

    def StartaCMnoBlock(self, node):

        '''Start up the cluster manager on a given node with none-block mode'''

        self.debug("Starting %s on node %s" %(self["Name"], node))

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

        self.rsh(node, startCmd, blocking=0)
        self.ShouldBeStatus[node]="up"
        return 1

    def StopaCM(self, node):

        '''Stop the cluster manager on a given node'''

        self.debug("Stopping %s on node %s" %(self["Name"], node))

        if self.ShouldBeStatus[node] != "up":
            return 1

        if self.rsh(node, self["StopCmd"]) == 0:
            self.ShouldBeStatus[node]="down"
            self.cluster_stable(self["DeadTime"])
            return 1
        else:
            self.log ("Could not stop %s on node %s" %(self["Name"], node))

        return None

    def StopaCMnoBlock(self, node):

        '''Stop the cluster manager on a given node with none-block mode'''

        self.debug("Stopping %s on node %s" %(self["Name"], node))

        self.rsh(node, self["StopCmd"], blocking=0)
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

        out=self.rsh(node, self["StatusCmd"], 1)
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

    def startall(self, nodelist=None):

        '''Start the cluster manager on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''
        ret = 1
        map = {}
        if not nodelist:
            nodelist=self.Env["nodes"]
        for node in nodelist:
            if self.ShouldBeStatus[node] == "down":
                if not self.StartaCM(node):
                    ret = 0
        return ret

    def stopall(self, nodelist=None):

        '''Stop the cluster managers on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        ret = 1
        map = {}
        if not nodelist:
            nodelist=self.Env["nodes"]
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                if not self.StopaCM(node):
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
                rc = self.rsh(target, self["BreakCommCmd"] % node)
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
                self.rsh(target, self["FixCommCmd"] % node, blocking=0)
                self.rsh(node, self["FixCommCmd"] % target, blocking=0)
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
            self.rsh(node, "opcontrol --setup --no-vmlinux --separate=lib --callgraph=10 --image=all")
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
    def __init__(self, name, dc_only, pats, dc_pats, badnews_ignore, triggersreboot, cm):
        self.name = str(name)
        self.dc_only = dc_only
        self.pats = pats
        self.dc_pats = dc_pats
        self.CM = cm
        self.badnews_ignore = badnews_ignore
	self.triggersreboot = triggersreboot
        self.KillCmd = "killall -9 " + self.name
        
    def kill(self, node):
        if self.CM.rsh(node, self.KillCmd) != 0:
            self.CM.log ("ERROR: Kill %s failed on node %s" %(self.name,node))
            return None
        return 1

class ScenarioComponent:

    def __init__(self, Env):
        self.Env = Env

    def IsApplicable(self):
        '''Return TRUE if the current ScenarioComponent is applicable
        in the given LabEnvironment given to the constructor.
        '''

        raise ValueError("Abstract Class member (IsApplicable)")

    def SetUp(self, CM):
        '''Set up the given ScenarioComponent'''
        raise ValueError("Abstract Class member (Setup)")

    def TearDown(self, CM):
        '''Tear down (undo) the given ScenarioComponent'''
        raise ValueError("Abstract Class member (Setup)")
        
        

class Scenario:
    (
'''The basic idea of a scenario is that of an ordered list of
ScenarioComponent objects.  Each ScenarioComponent is SetUp() in turn,
and then after the tests have been run, they are torn down using TearDown()
(in reverse order).

A Scenario is applicable to a particular cluster manager iff each
ScenarioComponent is applicable.

A partially set up scenario is torn down if it fails during setup.
''')

    def __init__(self, Components):

        "Initialize the Scenario from the list of ScenarioComponents"

        for comp in Components:

            if not issubclass(comp.__class__, ScenarioComponent):
                raise ValueError("Init value must be subclass of"
                " ScenarioComponent")
        self.Components = Components


    def IsApplicable(self):
        (
'''A Scenario IsApplicable() iff each of its ScenarioComponents IsApplicable()
'''
        )

        for comp in self.Components:
            if not comp.IsApplicable():
                return None
        return 1

    def SetUp(self, CM):
        '''Set up the Scenario. Return TRUE on success.'''

        j=0
        while j < len(self.Components):
            if not self.Components[j].SetUp(CM):
                # OOPS!  We failed.  Tear partial setups down.
                CM.log("Tearing down partial setup")
                self.TearDown(CM, j)
                return None
            j=j+1
        return 1

    def TearDown(self, CM, max=None):

        '''Tear Down the Scenario - in reverse order.'''

        if max == None:
            max = len(self.Components)-1
        j=max
        while j >= 0:
            self.Components[j].TearDown(CM)
            j=j-1


class InitClusterManager(ScenarioComponent):
    (
'''InitClusterManager is the most basic of ScenarioComponents.
This ScenarioComponent simply starts the cluster manager on all the nodes.
It is fairly robust as it waits for all nodes to come up before starting
as they might have been rebooted or crashed for some reason beforehand.
''')
    def __init__(self, Env):
        pass

    def IsApplicable(self):
        '''InitClusterManager is so generic it is always Applicable'''
        return 1

    def SetUp(self, CM):
        '''Basic Cluster Manager startup.  Start everything'''

        CM.prepare()

        #        Clear out the cobwebs ;-)

        self.TearDown(CM)

        # Now start the Cluster Manager on all the nodes.
        CM.log("Starting Cluster Manager on all nodes.")
        return CM.startall()

    def TearDown(self, CM):
        '''Set up the given ScenarioComponent'''

        # Stop the cluster manager everywhere

        CM.log("Stopping Cluster Manager on all nodes")
        return CM.stopall()

class PingFest(ScenarioComponent):
    (
'''PingFest does a flood ping to each node in the cluster from the test machine.

If the LabEnvironment Parameter PingSize is set, it will be used as the size
of ping packet requested (via the -s option).  If it is not set, it defaults
to 1024 bytes.

According to the manual page for ping:
    Outputs packets as fast as they come back or one hundred times per
    second, whichever is more.  For every ECHO_REQUEST sent a period ``.''
    is printed, while for every ECHO_REPLY received a backspace is printed.
    This provides a rapid display of how many packets are being dropped.
    Only the super-user may use this option.  This can be very hard on a net-
    work and should be used with caution.
''' )

    def __init__(self, Env):
        self.Env = Env

    def IsApplicable(self):
        '''PingFests are always applicable ;-)
        '''

        return 1

    def SetUp(self, CM):
        '''Start the PingFest!'''

        self.PingSize=1024
        if CM.Env.has_key("PingSize"):
                self.PingSize=CM.Env["PingSize"]

        CM.log("Starting %d byte flood pings" % self.PingSize)

        self.PingPids=[]
        for node in CM.Env["nodes"]:
            self.PingPids.append(self._pingchild(node))

        CM.log("Ping PIDs: " + repr(self.PingPids))
        return 1

    def TearDown(self, CM):
        '''Stop it right now!  My ears are pinging!!'''

        for pid in self.PingPids:
            if pid != None:
                CM.log("Stopping ping process %d" % pid)
                os.kill(pid, signal.SIGKILL)

    def _pingchild(self, node):

        Args = ["ping", "-qfn", "-s", str(self.PingSize), node]


        sys.stdin.flush()
        sys.stdout.flush()
        sys.stderr.flush()
        pid = os.fork()

        if pid < 0:
            self.Env.log("Cannot fork ping child")
            return None
        if pid > 0:
            return pid


        # Otherwise, we're the child process.

   
        os.execvp("ping", Args)
        self.Env.log("Cannot execvp ping: " + repr(Args))
        sys.exit(1)

class PacketLoss(ScenarioComponent):
    (
'''
It would be useful to do some testing of CTS with a modest amount of packet loss
enabled - so we could see that everything runs like it should with a certain
amount of packet loss present. 
''')

    def IsApplicable(self):
        '''always Applicable'''
        return 1

    def SetUp(self, CM):
        '''Reduce the reliability of communications'''
        if float(CM.Env["XmitLoss"]) == 0 and float(CM.Env["RecvLoss"]) == 0 :
            return 1

        for node in CM.Env["nodes"]:
            CM.reducecomm_node(node)
        
        CM.log("Reduce the reliability of communications")

        return 1


    def TearDown(self, CM):
        '''Fix the reliability of communications'''

        if float(CM.Env["XmitLoss"]) == 0 and float(CM.Env["RecvLoss"]) == 0 :
            return 1
        
        for node in CM.Env["nodes"]:
            CM.unisolate_node(node)

        CM.log("Fix the reliability of communications")


class BasicSanityCheck(ScenarioComponent):
    (
'''
''')

    def IsApplicable(self):
        return self.Env["DoBSC"]

    def SetUp(self, CM):

        CM.prepare()

        # Clear out the cobwebs
        self.TearDown(CM)

        # Now start the Cluster Manager on all the nodes.
        CM.log("Starting Cluster Manager on BSC node(s).")
        return CM.startall()

    def TearDown(self, CM):
        CM.log("Stopping Cluster Manager on BSC node(s).")
        return CM.stopall()
