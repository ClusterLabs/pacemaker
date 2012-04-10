from CTS import *
from CTStests import CTSTest
from CTSaudits import ClusterAudit
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

    def __init__(self, ClusterManager, Components, Audits, Tests):

        "Initialize the Scenario from the list of ScenarioComponents"
        self.ClusterManager = ClusterManager
        self.Components = Components
        self.Audits  = Audits
        self.Tests = Tests

        self.BadNews = None
        self.TestSets = []
        self.Stats = {"success":0, "failure":0, "BadNews":0, "skipped":0}
        self.Sets = []

        #self.ns=CTS.NodeStatus(self.Env)

        for comp in Components:
            if not issubclass(comp.__class__, ScenarioComponent):
                raise ValueError("Init value must be subclass of ScenarioComponent")

        for audit in Audits:
            if not issubclass(audit.__class__, ClusterAudit):
                raise ValueError("Init value must be subclass of ClusterAudit")

        for test in Tests:
            if not issubclass(test.__class__, CTSTest):
                raise ValueError("Init value must be a subclass of CTSTest")

    def IsApplicable(self):
        (
'''A Scenario IsApplicable() iff each of its ScenarioComponents IsApplicable()
'''
        )

        for comp in self.Components:
            if not comp.IsApplicable():
                return None
        return 1

    def SetUp(self):
        '''Set up the Scenario. Return TRUE on success.'''

        self.ClusterManager.prepare()
        self.ClusterManager.ns.WaitForAllNodesToComeUp(self.ClusterManager.Env["nodes"])

        self.audit()
        if self.ClusterManager.Env["valgrind-tests"]:
            self.ClusterManager.install_helper("cts.supp")

        self.BadNews = LogWatcher(self.ClusterManager.Env, 
                                  self.ClusterManager["LogFileName"], 
                                  self.ClusterManager["BadRegexes"], "BadNews", 0)
        self.BadNews.setwatch() # Call after we've figured out what type of log watching to do in LogAudit

        j=0
        while j < len(self.Components):
            if not self.Components[j].SetUp(self.ClusterManager):
                # OOPS!  We failed.  Tear partial setups down.
                self.audit()
                self.ClusterManager.log("Tearing down partial setup")
                self.TearDown(j)
                return None
            j=j+1

        self.audit()
        return 1

    def TearDown(self, max=None):

        '''Tear Down the Scenario - in reverse order.'''

        if max == None:
            max = len(self.Components)-1
        j=max
        while j >= 0:
            self.Components[j].TearDown(self.ClusterManager)
            j=j-1

        self.audit()

    def incr(self, name):
        '''Increment (or initialize) the value associated with the given name'''
        if not self.Stats.has_key(name):
            self.Stats[name]=0
        self.Stats[name] = self.Stats[name]+1

    def run(self, Iterations):
        self.ClusterManager.oprofileStart() 
        try:
            self.run_loop(Iterations)
            self.ClusterManager.oprofileStop()
        except:
            self.ClusterManager.oprofileStop()
            raise

    def run_loop(self, Iterations):
        raise ValueError("Abstract Class member (run_loop)")

    def run_test(self, test, testcount):
        nodechoice = self.ClusterManager.Env.RandomNode()
        
        ret = 1
        where = ""
        did_run = 0

        self.ClusterManager.instance_errorstoignore_clear()
        self.ClusterManager.log(("Running test %s" % test.name).ljust(35) + (" (%s) " % nodechoice).ljust(15) +"["+ ("%d" % testcount).rjust(3) +"]")

        starttime = test.set_timer()
        if not test.setup(nodechoice):
            self.ClusterManager.log("Setup failed")
            ret = 0
            
        elif not test.canrunnow(nodechoice):
            self.ClusterManager.log("Skipped")
            test.skipped()

        else:
            did_run = 1
            ret = test(nodechoice)

        if not test.teardown(nodechoice):
            self.ClusterManager.log("Teardown failed")
            answer = raw_input('Continue? [nY] ')
            if answer and answer == "n":
                raise ValueError("Teardown of %s on %s failed" % (test.name, nodechoice))
            ret = 0

        stoptime=time.time()
        self.ClusterManager.oprofileSave(testcount)

        elapsed_time = stoptime - starttime
        test_time = stoptime - test.get_timer()
        if not test.has_key("min_time"):
            test["elapsed_time"] = elapsed_time
            test["min_time"] = test_time
            test["max_time"] = test_time
        else:
            test["elapsed_time"] = test["elapsed_time"] + elapsed_time
            if test_time < test["min_time"]:
                test["min_time"] = test_time
            if test_time > test["max_time"]:
                test["max_time"] = test_time
               
        if ret:
            self.incr("success")
            test.log_timer()
        else:
            self.incr("failure")
            self.ClusterManager.statall()
            did_run = 1  # Force the test count to be incrimented anyway so test extraction works

        self.audit(test.errorstoignore())
        return did_run

    def summarize(self):
        self.ClusterManager.log("****************")
        self.ClusterManager.log("Overall Results:" + repr(self.Stats))
        self.ClusterManager.log("****************")

        stat_filter = {   
            "calls":0,
            "failure":0,
            "skipped":0,
            "auditfail":0,
            }
        self.ClusterManager.log("Test Summary")
        for test in self.Tests:
            for key in stat_filter.keys():
                stat_filter[key] = test.Stats[key]
            self.ClusterManager.log(("Test %s: "%test.name).ljust(25) + " %s"%repr(stat_filter))

        self.ClusterManager.debug("Detailed Results")
        for test in self.Tests:
            self.ClusterManager.debug(("Test %s: "%test.name).ljust(25) + " %s"%repr(test.Stats))

        self.ClusterManager.log("<<<<<<<<<<<<<<<< TESTS COMPLETED")

    def audit(self, LocalIgnore=[]):
        errcount=0
        ignorelist = []
        ignorelist.append("CTS:")
        ignorelist.extend(LocalIgnore)
        ignorelist.extend(self.ClusterManager.errorstoignore())
        ignorelist.extend(self.ClusterManager.instance_errorstoignore())

        # This makes sure everything is stabilized before starting...
        failed = 0
        for audit in self.Audits:
            if not audit():
                self.ClusterManager.log("Audit " + audit.name() + " FAILED.")
                failed += 1
            else:
                self.ClusterManager.debug("Audit " + audit.name() + " passed.")

        while errcount < 1000:
            match = None
            if self.BadNews:
                match=self.BadNews.look(0)

            if match:
                add_err = 1
                for ignore in ignorelist:
                    if add_err == 1 and re.search(ignore, match):
                        add_err = 0
                if add_err == 1:
                    self.ClusterManager.log("BadNews: " + match)
                    self.incr("BadNews")
                    errcount=errcount+1
            else:
                break
        else:
            answer = raw_input('Big problems.  Continue? [nY]')
            if answer and answer == "n":
                self.ClusterManager.log("Shutting down.")
                self.summarize()
                self.TearDown()
                raise ValueError("Looks like we hit a BadNews jackpot!")

        return failed

class AllOnce(Scenario):
    '''Every Test Once''' # Accessable as __doc__
    def run_loop(self, Iterations):
        testcount=1
        for test in self.Tests:
            self.run_test(test, testcount)
            testcount += 1

class RandomTests(Scenario):
    '''Random Test Execution'''
    def run_loop(self, Iterations):
        testcount=1
        while testcount <= Iterations:
            test = self.ClusterManager.Env.RandomGen.choice(self.Tests)
            self.run_test(test, testcount)
            testcount += 1

class BasicSanity(Scenario):
    '''Basic Cluster Sanity'''
    def run_loop(self, Iterations):
        testcount=1
        while testcount <= Iterations:
            test = self.Environment.RandomGen.choice(self.Tests)
            self.run_test(test, testcount)
            testcount += 1

class Sequence(Scenario):
    '''Named Tests in Sequence'''
    def run_loop(self, Iterations):
        testcount=1
        while testcount <= Iterations:
            for test in self.Tests:
                self.run_test(test, testcount)
                testcount += 1

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
        return CM.startall(verbose=True)

    def TearDown(self, CM):
        '''Set up the given ScenarioComponent'''

        # Stop the cluster manager everywhere

        CM.log("Stopping Cluster Manager on all nodes")
        return CM.stopall(verbose=True)

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

class Benchmark(ScenarioComponent):
    (
'''
''')

    def IsApplicable(self):
        return self.Env["benchmark"]

    def SetUp(self, CM):

        CM.prepare()

        # Clear out the cobwebs
        self.TearDown(CM)

        # Now start the Cluster Manager on all the nodes.
        CM.log("Starting Cluster Manager on all node(s).")
        return CM.startall()

    def TearDown(self, CM):
        CM.log("Stopping Cluster Manager on all node(s).")
        return CM.stopall()

class RollingUpgrade(ScenarioComponent):
    (
'''
Test a rolling upgrade between two versions of the stack
''')

    def __init__(self, Env):
        self.Env = Env

    def IsApplicable(self):
        if not self.Env["rpm-dir"]:
            return None
        if not self.Env["current-version"]:
            return None
        if not self.Env["previous-version"]:
            return None

        return 1

    def install(self, node, version):

        target_dir = "/tmp/rpm-%s" % version
        src_dir = "%s/%s" % (self.CM.Env["rpm-dir"], version)

        rc = self.CM.rsh(node, "mkdir -p %s" % target_dir)
        rc = self.CM.cp("%s/*.rpm %s:%s" % (src_dir, node, target_dir))
        rc = self.CM.rsh(node, "rpm -Uvh --force %s/*.rpm" % (target_dir))

        return self.success()

    def upgrade(self, node):
        return self.install(node, self.CM.Env["current-version"])

    def downgrade(self, node):
        return self.install(node, self.CM.Env["previous-version"])

    def SetUp(self, CM):
        CM.prepare()

        # Clear out the cobwebs
        CM.stopall()

        CM.log("Downgrading all nodes to %s." % self.Env["previous-version"])

        for node in self.Env["nodes"]:
            if not self.downgrade(node):
                CM.log("Couldn't downgrade %s" % node)
                return None

        return 1

    def TearDown(self, CM):
        # Stop everything
        CM.log("Stopping Cluster Manager on Upgrade nodes.")
        CM.stopall()

        CM.log("Upgrading all nodes to %s." % self.Env["current-version"])
        for node in self.Env["nodes"]:
            if not self.upgrade(node):
                CM.log("Couldn't upgrade %s" % node)
                return None

        return 1

