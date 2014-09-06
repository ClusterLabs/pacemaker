'''CTS: Cluster Testing System: Main module

Classes related to testing high-availability clusters...
 '''

__copyright__ = '''
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
from threading import Thread

from cts.CTSvars     import *
from cts.logging     import LogFactory
from cts.watcher     import LogWatcher
from cts.remote      import RemoteFactory
from cts.environment import EnvFactory
from cts.patterns    import PatternSelector

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

class CtsLab:
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

    def __init__(self, args=None):
        self.Env = EnvFactory().getInstance(args)
        self.Scenario = None
        self.logger = LogFactory()
        self.rsh = RemoteFactory().getInstance()

    def dump(self):
        self.Env.dump()

    def has_key(self, key):
        return self.Env.has_key(key)

    def __getitem__(self, key):
        return self.Env[key]

    def __setitem__(self, key, value):
        self.Env[key] = value

    def HasMinimalKeys(self):
        'Return TRUE if our object has the minimal set of keys/values in it'
        result = 1
        for key in self.MinimalKeys:
            if not self.has_key(key):
                result = None
        return result

    def run(self, Scenario, Iterations):
        if not Scenario:
            self.logger.log("No scenario was defined")
            return 1

        self.logger.log("Cluster nodes: ")
        for node in self.Env["nodes"]:
            self.logger.log("    * %s" % (node))

        if not Scenario.SetUp():
            return 1

        try :
            Scenario.run(Iterations)
        except :
            self.logger.log("Exception by %s" % sys.exc_info()[0])
            self.logger.traceback(traceback)

            Scenario.summarize()
            Scenario.TearDown()
            return 1

        #ClusterManager.oprofileSave(Iterations)
        Scenario.TearDown()

        Scenario.summarize()
        if Scenario.Stats["failure"] > 0:
            return Scenario.Stats["failure"]

        elif Scenario.Stats["success"] != Iterations:
            self.logger.log("No failure count but success != requested iterations")
            return 1

        return 0

    def IsValidNode(self, node):
        'Return TRUE if the given node is valid'
        return self.Nodes.has_key(node)

    def __CheckNode(self, node):
        "Raise a ValueError if the given node isn't valid"

        if not self.IsValidNode(node):
            raise ValueError("Invalid node [%s] in CheckNode" % node)

class NodeStatus:
    def __init__(self, env):
        pass

    def IsNodeBooted(self, node):
        '''Return TRUE if the given node is booted (responds to pings)'''
        return RemoteFactory().getInstance()("localhost", "ping -nq -c1 -w1 %s" % node, silent=True) == 0

    def IsSshdUp(self, node):
        rc = RemoteFactory().getInstance()(node, "true", silent=True)
        return rc == 0

    def WaitForNodeToComeUp(self, node, Timeout=300):
        '''Return TRUE when given node comes up, or None/FALSE if timeout'''
        timeout = Timeout
        anytimeouts = 0
        while timeout > 0:
            if self.IsNodeBooted(node) and self.IsSshdUp(node):
                if anytimeouts:
                     # Fudge to wait for the system to finish coming up
                     time.sleep(30)
                     LogFactory().debug("Node %s now up" % node)
                return 1

            time.sleep(30)
            if (not anytimeouts):
                LogFactory().debug("Waiting for node %s to come up" % node)

            anytimeouts = 1
            timeout = timeout - 1

        LogFactory().log("%s did not come up within %d tries" % (node, Timeout))
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
                raise ValueError("Improper derivation: self[" + key +   "] must be overridden by subclass.")

    def __init__(self, Environment, randseed=None):
        self.Env = EnvFactory().getInstance()
        self.templates = PatternSelector(self.Env["Name"])
        self.__InitialConditions()
        self.logger = LogFactory()
        self.clear_cache = 0
        self.TestLoggingLevel=0
        self.data = {}
        self.name = self.Env["Name"]

        self.rsh = RemoteFactory().getInstance()
        self.ShouldBeStatus={}
        self.ns = NodeStatus(self.Env)
        self.OurNode = string.lower(os.uname()[1])
        self.__instance_errorstoignore = []

    def __getitem__(self, key):
        if key == "Name":
            return self.name

        print "FIXME: Getting %s from %s" % (key, repr(self))
        if self.data.has_key(key):
            return self.data[key]

        return self.templates.get_patterns(self.Env["Name"], key)

    def __setitem__(self, key, value):
        print "FIXME: Setting %s=%s on %s" % (key, value, repr(self))
        self.data[key] = value

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
        self.logger.log(args)

    def debug(self, args):
        self.logger.debug(args)

    def prepare(self):
        '''Finish the Initialization process. Prepare to test...'''

        print repr(self)+"prepare"
        for node in self.Env["nodes"]:
            if self.StataCM(node):
                self.ShouldBeStatus[node] = "up"
            else:
                self.ShouldBeStatus[node] = "down"

            self.unisolate_node(node)

    def upcount(self):
        '''How many nodes are up?'''
        count = 0
        for node in self.Env["nodes"]:
          if self.ShouldBeStatus[node] == "up":
            count = count + 1
        return count

    def install_helper(self, filename, destdir=None, nodes=None, sourcedir=None):
        if sourcedir == None:
            sourcedir = CTSvars.CTS_home
        file_with_path = "%s/%s" % (sourcedir, filename)
        if not nodes:
            nodes = self.Env["nodes"]

        if not destdir:
            destdir = CTSvars.CTS_home

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

    def prepare_fencing_watcher(self, name):
        # If we don't have quorum now but get it as a result of starting this node,
        # then a bunch of nodes might get fenced
        upnode = None
        if self.HasQuorum(None):
            self.debug("Have quorum")
            return None

        if not self.templates["Pat:Fencing_start"]:
            print "No start pattern"
            return None

        if not self.templates["Pat:Fencing_ok"]:
            print "No ok pattern"
            return None

        stonith = None
        stonithPats = []
        for peer in self.Env["nodes"]:
            if self.ShouldBeStatus[peer] != "up":
                stonithPats.append(self.templates["Pat:Fencing_ok"] % peer)
                stonithPats.append(self.templates["Pat:Fencing_start"] % peer)
            elif self.Env["Stack"] == "corosync (cman)":
                # There is a delay between gaining quorum and CMAN starting fencing
                # This can mean that even nodes that are fully up get fenced
                # There is no use fighting it, just look for everyone so that CTS doesn't get confused
                stonithPats.append(self.templates["Pat:Fencing_ok"] % peer)
                stonithPats.append(self.templates["Pat:Fencing_start"] % peer)

        stonith = LogWatcher(self.Env["LogFileName"], stonithPats, "StartupFencing", 0, hosts=self.Env["nodes"], kind=self.Env["LogWatcher"])
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
            self.debug("Found: " + line)
            del stonith.regexes[stonith.whichmatch]

            # Extract node name
            for n in self.Env["nodes"]:
                if re.search(self.templates["Pat:Fencing_ok"] % n, shot):
                    peer = n
                    peer_state[peer] = "complete"
                    self.__instance_errorstoignore.append(self.templates["Pat:Fencing_ok"] % peer)

                elif re.search(self.templates["Pat:Fencing_start"] % n, shot):
                    peer = n
                    peer_state[peer] = "in-progress"
                    self.__instance_errorstoignore.append(self.templates["Pat:Fencing_start"] % peer)

            if not peer:
                self.logger.log("ERROR: Unknown stonith match: %s" % line)

            elif not peer in peer_list:
                self.debug("Found peer: " + peer)
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
                    self.debug("Found: " + line)
                    del stonith.regexes[stonith.whichmatch]
                    shot = stonith.look(60)

            # Now make sure the node is alive too
            self.ns.WaitForNodeToComeUp(peer, self.Env["DeadTime"])

            # Poll until it comes up
            if self.Env["at-boot"]:
                if not self.StataCM(peer):
                    time.sleep(self.Env["StartTime"])

                if not self.StataCM(peer):
                    self.logger.log("ERROR: Peer %s failed to restart after being fenced" % peer)
                    return None

        return peer_list

    def StartaCM(self, node, verbose=False):

        '''Start up the cluster manager on a given node'''
        if verbose: self.logger.log("Starting %s on node %s" % (self.templates["Name"], node))
        else: self.debug("Starting %s on node %s" % (self.templates["Name"], node))
        ret = 1

        if not self.ShouldBeStatus.has_key(node):
            self.ShouldBeStatus[node] = "down"

        if self.ShouldBeStatus[node] != "down":
            return 1

        patterns = []
        # Technically we should always be able to notice ourselves starting
        patterns.append(self.templates["Pat:Local_started"] % node)
        if self.upcount() == 0:
            patterns.append(self.templates["Pat:Master_started"] % node)
        else:
            patterns.append(self.templates["Pat:Slave_started"] % node)

        watch = LogWatcher(
            self.Env["LogFileName"], patterns, "StartaCM", self.Env["StartTime"]+10, hosts=self.Env["nodes"], kind=self.Env["LogWatcher"])

        self.install_config(node)

        self.ShouldBeStatus[node] = "any"
        if self.StataCM(node) and self.cluster_stable(self.Env["DeadTime"]):
            self.logger.log ("%s was already started" % (node))
            return 1

        # Clear out the host cache so autojoin can be exercised
        if self.clear_cache:
            self.debug("Removing cache file on: "+node)
            self.rsh(node, "rm -f "+CTSvars.HA_VARLIBHBDIR+"/hostcache")

        if not(self.Env["valgrind-tests"]):
            startCmd = self.templates["StartCmd"]
        else:
            if self.Env["valgrind-prefix"]:
                prefix = self.Env["valgrind-prefix"]
            else:
                prefix = "cts"

            startCmd = """G_SLICE=always-malloc HA_VALGRIND_ENABLED='%s' VALGRIND_OPTS='%s --log-file=/tmp/%s-%s.valgrind' %s""" % (
                self.Env["valgrind-procs"], self.Env["valgrind-opts"], prefix, """%p""", self.templates["StartCmd"])

        stonith = self.prepare_fencing_watcher(node)

        watch.setwatch()

        if self.rsh(node, startCmd) != 0:
            self.logger.log ("Warn: Start command failed on node %s" % (node))
            self.fencing_cleanup(node, stonith)
            return None

        self.ShouldBeStatus[node] = "up"
        watch_result = watch.lookforall()

        if watch.unmatched:
            for regex in watch.unmatched:
                self.logger.log ("Warn: Startup pattern not found: %s" % (regex))

        if watch_result and self.cluster_stable(self.Env["DeadTime"]):
            #self.debug("Found match: "+ repr(watch_result))
            self.fencing_cleanup(node, stonith)
            return 1

        elif self.StataCM(node) and self.cluster_stable(self.Env["DeadTime"]):
            self.fencing_cleanup(node, stonith)
            return 1

        self.logger.log ("Warn: Start failed for node %s" % (node))
        return None

    def StartaCMnoBlock(self, node, verbose=False):

        '''Start up the cluster manager on a given node with none-block mode'''

        if verbose: self.logger.log("Starting %s on node %s" % (self["Name"], node))
        else: self.debug("Starting %s on node %s" % (self["Name"], node))

        # Clear out the host cache so autojoin can be exercised
        if self.clear_cache:
            self.debug("Removing cache file on: "+node)
            self.rsh(node, "rm -f "+CTSvars.HA_VARLIBHBDIR+"/hostcache")

        self.install_config(node)
        if not(self.Env["valgrind-tests"]):
            startCmd = self.templates["StartCmd"]
        else:
            if self.Env["valgrind-prefix"]:
                prefix = self.Env["valgrind-prefix"]
            else:
                prefix = "cts"

            startCmd = """G_SLICE=always-malloc HA_VALGRIND_ENABLED='%s' VALGRIND_OPTS='%s --log-file=/tmp/%s-%s.valgrind' %s""" % (
                self.Env["valgrind-procs"], self.Env["valgrind-opts"], prefix, """%p""", self.templates["StartCmd"])

        self.rsh(node, startCmd, synchronous=0)
        self.ShouldBeStatus[node] = "up"
        return 1

    def StopaCM(self, node, verbose=False, force=False):

        '''Stop the cluster manager on a given node'''

        if verbose: self.logger.log("Stopping %s on node %s" % (self["Name"], node))
        else: self.debug("Stopping %s on node %s" % (self["Name"], node))

        if self.ShouldBeStatus[node] != "up" and force == False:
            return 1

        if self.rsh(node, self.templates["StopCmd"]) == 0:
            # Make sure we can continue even if corosync leaks
            # fdata-* is the old name
            #self.rsh(node, "rm -f /dev/shm/qb-* /dev/shm/fdata-*")
            self.ShouldBeStatus[node] = "down"
            self.cluster_stable(self.Env["DeadTime"])
            return 1
        else:
            self.logger.log ("ERROR: Could not stop %s on node %s" % (self["Name"], node))

        return None

    def StopaCMnoBlock(self, node):

        '''Stop the cluster manager on a given node with none-block mode'''

        self.debug("Stopping %s on node %s" % (self["Name"], node))

        self.rsh(node, self.templates["StopCmd"], synchronous=0)
        self.ShouldBeStatus[node] = "down"
        return 1

    def cluster_stable(self, timeout = None):
        time.sleep(self.Env["StableTime"])
        return 1

    def node_stable(self, node):
        return 1

    def RereadCM(self, node):

        '''Force the cluster manager on a given node to reread its config
           This may be a no-op on certain cluster managers.
        '''
        rc=self.rsh(node, self.templates["RereadCmd"])
        if rc == 0:
            return 1
        else:
            self.logger.log ("Could not force %s on node %s to reread its config"
            %        (self["Name"], node))
        return None

    def StataCM(self, node):

        '''Report the status of the cluster manager on a given node'''

        out=self.rsh(node, self.templates["StatusCmd"] % node, 1)
        ret= (string.find(out, 'stopped') == -1)

        try:
            if ret:
                if self.ShouldBeStatus[node] == "down":
                    self.logger.log(
                    "Node status for %s is %s but we think it should be %s"
                    %        (node, "up", self.ShouldBeStatus[node]))
            else:
                if self.ShouldBeStatus[node] == "up":
                    self.logger.log(
                    "Node status for %s is %s but we think it should be %s"
                    %        (node, "down", self.ShouldBeStatus[node]))
        except KeyError:        pass

        if ret:
            self.ShouldBeStatus[node] = "up"
        else:
            self.ShouldBeStatus[node] = "down"
        return ret

    def startall(self, nodelist=None, verbose=False, quick=False):

        '''Start the cluster manager on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''
        map = {}
        if not nodelist:
            nodelist = self.Env["nodes"]

        for node in nodelist:
            if self.ShouldBeStatus[node] == "down":
                self.ns.WaitForAllNodesToComeUp(nodelist, 300)

        if not quick:
            if not self.StartaCM(node, verbose=verbose):
                return 0
            return 1

        # Approximation of SimulStartList for --boot 
        watchpats = [ ]
        watchpats.append(self.templates["Pat:DC_IDLE"])
        for node in nodelist:
            watchpats.append(self.templates["Pat:Local_started"] % node)
            watchpats.append(self.templates["Pat:InfraUp"] % node)
            watchpats.append(self.templates["Pat:PacemakerUp"] % node)

        #   Start all the nodes - at about the same time...
        watch = LogWatcher(self.Env["LogFileName"], watchpats, "fast-start", self.Env["DeadTime"]+10, hosts=self.Env["nodes"], kind=self.Env["LogWatcher"])
        watch.setwatch()

        if not self.StartaCM(nodelist[0], verbose=verbose):
            return 0
        for node in nodelist:
            self.StartaCMnoBlock(node, verbose=verbose)

        watch.lookforall()
        if watch.unmatched:
            for regex in watch.unmatched:
                self.logger.log ("Warn: Startup pattern not found: %s" % (regex))

        if not self.cluster_stable():
            self.logger.log("Cluster did not stabilize")
            return 0

        return 1

    def stopall(self, nodelist=None, verbose=False, force=False):

        '''Stop the cluster managers on every node in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        ret = 1
        map = {}
        if not nodelist:
            nodelist = self.Env["nodes"]
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
            nodelist = self.Env["nodes"]
        for node in self.Env["nodes"]:
            if self.ShouldBeStatus[node] == "up":
                self.RereadCM(node)

    def statall(self, nodelist=None):

        '''Return the status of the cluster managers in the cluster.
        We can do it on a subset of the cluster if nodelist is not None.
        '''

        result = {}
        if not nodelist:
            nodelist = self.Env["nodes"]
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
                rc = self.rsh(target, self.templates["BreakCommCmd"] % self.key_for_node(node))
                if rc != 0:
                    self.logger.log("Could not break the communication between %s and %s: %d" % (target, node, rc))
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
                self.rsh(target, self.templates["FixCommCmd"] % self.key_for_node(node), synchronous=0)
                self.rsh(node, self.templates["FixCommCmd"] % self.key_for_node(target), synchronous=0)
                self.debug("Communication restored between %s and %s" % (target, node))

    def reducecomm_node(self,node):
        '''reduce the communication between the nodes'''
        rc = self.rsh(node, self.templates["ReduceCommCmd"]%(self.Env["XmitLoss"],self.Env["RecvLoss"]))
        if rc == 0:
            return 1
        else:
            self.logger.log("Could not reduce the communication between the nodes from node: %s" % node)
        return None

    def restorecomm_node(self,node):
        '''restore the saved communication between the nodes'''
        rc = 0
        if float(self.Env["XmitLoss"]) != 0 or float(self.Env["RecvLoss"]) != 0 :
            rc = self.rsh(node, self.templates["RestoreCommCmd"]);
        if rc == 0:
            return 1
        else:
            self.logger.log("Could not restore the communication between the nodes from node: %s" % node)
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


    def StatsExtract(self):
        if not self.Env["stats"]:
            return

        for host in self.Env["nodes"]:
            log_stats_file = "%s/cts-stats.csv" % CTSvars.CRM_DAEMON_DIR
            if has_log_stats.has_key(host):
                self.rsh(host, '''bash %s %s stop''' % (log_stats_bin, log_stats_file))
                (rc, lines) = self.rsh(host, '''cat %s''' % log_stats_file, stdout=2)
                self.rsh(host, '''bash %s %s delete''' % (log_stats_bin, log_stats_file))

                fname = "cts-stats-%d-nodes-%s.csv" % (len(self.Env["nodes"]), host)
                print "Extracted stats: %s" % fname
                fd = open(fname, "a")
                fd.writelines(lines)
                fd.close()

    def StatsMark(self, testnum):
        '''Mark the test number in the stats log'''

        global has_log_stats
        if not self.Env["stats"]:
            return

        for host in self.Env["nodes"]:
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
            self.CM.log ("ERROR: Kill %s failed on node %s" % (self.name,node))
            return None
        return 1
