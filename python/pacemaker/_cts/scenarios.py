"""Test scenario classes for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = [
    "AllOnce",
    "Boot",
    "BootCluster",
    "LeaveBooted",
    "RandomTests",
    "Sequence",
]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re
import time

from pacemaker._cts.audits import ClusterAudit
from pacemaker._cts.input import should_continue
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.watcher import LogWatcher


class ScenarioComponent:
    """
    The base class for all scenario components.

    A scenario component is one single step in a scenario.  Each component is
    basically just a setup and teardown method.
    """

    def __init__(self, cm, env):
        """
        Create a new ScenarioComponent instance.

        Arguments:
        cm  -- A ClusterManager instance
        env -- An Environment instance
        """
        # pylint: disable=invalid-name
        self._cm = cm
        self._env = env

    def is_applicable(self):
        """
        Return True if this component is applicable in the given Environment.

        This method must be provided by all subclasses.
        """
        raise NotImplementedError

    def setup(self):
        """
        Set up the component, returning True on success.

        This method must be provided by all subclasses.
        """
        raise NotImplementedError

    def teardown(self):
        """
        Tear down the given component.

        This method must be provided by all subclasses.
        """
        raise NotImplementedError


class Scenario:
    """
    The base class for scenarios.

    A scenario is an ordered list of ScenarioComponent objects.  A scenario
    proceeds by setting up all its components in sequence, running a list of
    tests and audits, and then tearing down its components in reverse.
    """

    def __init__(self, cm, components, audits, tests):
        """
        Create a new Scenario instance.

        Arguments:
        cm         -- A ClusterManager instance
        components -- A list of ScenarioComponents comprising this Scenario
        audits     -- A list of ClusterAudits that will be performed as
                      part of this Scenario
        tests      -- A list of CTSTests that will be run
        """
        # pylint: disable=invalid-name

        self.stats = {
            "success": 0,
            "failure": 0,
            "BadNews": 0,
            "skipped": 0
        }
        self.tests = tests

        self._audits = audits
        self._bad_news = None
        self._cm = cm
        self._components = components

        for comp in components:
            if not issubclass(comp.__class__, ScenarioComponent):
                raise ValueError("Init value must be subclass of ScenarioComponent")

        for audit in audits:
            if not issubclass(audit.__class__, ClusterAudit):
                raise ValueError("Init value must be subclass of ClusterAudit")

        for test in tests:
            if not issubclass(test.__class__, CTSTest):
                raise ValueError("Init value must be a subclass of CTSTest")

    def is_applicable(self):
        """Return True if all ScenarioComponents are applicable."""
        for comp in self._components:
            if not comp.is_applicable():
                return False

        return True

    def setup(self):
        """
        Set up the scenario, returning True on success.

        If setup fails at some point, tear down those components that did
        successfully set up.
        """
        self._cm.prepare()
        self.audit()  # Also detects remote/local log config
        self._cm.ns.wait_for_all_nodes(self._cm.env["nodes"])

        self.audit()
        self._cm.install_support()

        self._bad_news = LogWatcher(self._cm.env["LogFileName"],
                                    self._cm.templates.get_patterns("BadNews"),
                                    self._cm.env["nodes"],
                                    self._cm.env["log_kind"],
                                    "BadNews", 0)
        self._bad_news.set_watch()  # Call after we've figured out what type of log watching to do in LogAudit

        j = 0
        while j < len(self._components):
            if not self._components[j].setup():
                # OOPS!  We failed.  Tear partial setups down.
                self.audit()
                self._cm.log("Tearing down partial setup")
                self.teardown(j)
                return False

            j += 1

        self.audit()
        return True

    def teardown(self, n_components=None):
        """
        Tear down the scenario in the reverse order it was set up.

        If n_components is not None, only tear down that many components.
        """
        if not n_components:
            n_components = len(self._components) - 1

        j = n_components

        while j >= 0:
            self._components[j].teardown()
            j -= 1

        self.audit()
        self._cm.install_support("uninstall")

    def incr(self, name):
        """Increment the given stats key."""
        if name not in self.stats:
            self.stats[name] = 0

        self.stats[name] += 1

    def run(self, iterations):
        """Run all the tests the given number of times."""
        raise NotImplementedError

    def run_test(self, test, testcount):
        """
        Run the given test.

        testcount is the number of tests (including this one) that have been
        run across all iterations.
        """
        nodechoice = self._cm.env.random_node()

        ret = True
        did_run = False

        self._cm.clear_instance_errors_to_ignore()
        self._cm.log(f"Running test {test.name:<22} {f'({nodechoice})':<15} [{testcount:>3}]")

        starttime = test.set_timer()

        if not test.setup(nodechoice):
            self._cm.log("Setup failed")
            ret = False
        else:
            did_run = True
            ret = test(nodechoice)

        if not test.teardown(nodechoice):
            self._cm.log("Teardown failed")

            if not should_continue(self._cm.env):
                raise ValueError(f"Teardown of {test.name} on {nodechoice} failed")

            ret = False

        stoptime = time.time()

        elapsed_time = stoptime - starttime
        test_time = stoptime - test.get_timer()

        if "min_time" not in test.stats:
            test.stats["elapsed_time"] = elapsed_time
            test.stats["min_time"] = test_time
            test.stats["max_time"] = test_time
        else:
            test.stats["elapsed_time"] += elapsed_time

            if test_time < test.stats["min_time"]:
                test.stats["min_time"] = test_time

            if test_time > test.stats["max_time"]:
                test.stats["max_time"] = test_time

        if ret:
            self.incr("success")
            test.log_timer()
        else:
            self.incr("failure")
            self._cm.statall()
            did_run = True  # Force the test count to be incremented anyway so test extraction works

        self.audit(test.errors_to_ignore)
        return did_run

    def summarize(self):
        """Output scenario results."""
        self._cm.log("****************")
        self._cm.log("Overall Results:%r" % self.stats)
        self._cm.log("****************")

        stat_summary = {}
        summary_keys = ["calls", "failure", "skipped", "auditfail"]

        self._cm.log("Test Summary")
        for test in self.tests:
            if test.name not in stat_summary:
                stat_summary[test.name] = {key: 0 for key in summary_keys}

            for key in summary_keys:
                stat_summary[test.name][key] += test.stats[key]

        for (name, summary) in stat_summary.items():
            self._cm.log(f"{f'Test {name}':<25} {summary!r}")

        self._cm.debug("Detailed Results")
        for test in self.tests:
            self._cm.debug(f"{f'Test {test.name}: ':<25} {test.stats!r}")

        self._cm.log("<<<<<<<<<<<<<<<< TESTS COMPLETED")

    def audit(self, local_ignore=None):
        """
        Perform all scenario audits and log results.

        If there are too many failures, prompt the user to confirm that the
        scenario should continue running.
        """
        errcount = 0

        ignorelist = ["CTS:"]

        if local_ignore:
            ignorelist.extend(local_ignore)

        ignorelist.extend(self._cm.errors_to_ignore)
        ignorelist.extend(self._cm.instance_errors_to_ignore)

        # This makes sure everything is stabilized before starting...
        failed = 0
        for audit in self._audits:
            if not audit():
                self._cm.log(f"Audit {audit.name} FAILED.")
                failed += 1
            else:
                self._cm.debug(f"Audit {audit.name} passed.")

        while errcount < 1000:
            match = None
            if self._bad_news:
                match = self._bad_news.look(0)

            if not match:
                break

            add_err = True

            for ignore in ignorelist:
                if add_err and re.search(ignore, match):
                    add_err = False
                    break

            if add_err:
                self._cm.log(f"BadNews: {match}")
                self.incr("BadNews")
                errcount += 1
        else:
            print("Big problems")
            if not should_continue(self._cm.env):
                self._cm.log("Shutting down.")
                self.summarize()
                self.teardown()
                raise ValueError("Looks like we hit a BadNews jackpot!")

        if self._bad_news:
            self._bad_news.end()

        return failed


class AllOnce(Scenario):
    """Every Test Once."""

    def run(self, iterations):
        testcount = 1

        for test in self.tests:
            self.run_test(test, testcount)
            testcount += 1


class RandomTests(Scenario):
    """Random Test Execution."""

    def run(self, iterations):
        testcount = 1

        while testcount <= iterations:
            test = self._cm.env.random_gen.choice(self.tests)
            self.run_test(test, testcount)
            testcount += 1


class Sequence(Scenario):
    """Named Tests in Sequence."""

    def run(self, iterations):
        testcount = 1

        while testcount <= iterations:
            for test in self.tests:
                self.run_test(test, testcount)
                testcount += 1


class Boot(Scenario):
    """Start the Cluster."""

    def run(self, iterations):
        return


class BootCluster(ScenarioComponent):
    """
    Start the cluster manager on all nodes.

    Wait for each to come up before starting in order to account for the
    possibility that a given node might have been rebooted or crashed
    beforehand.
    """

    def is_applicable(self):
        """Return whether this scenario is applicable."""
        return True

    def setup(self):
        """Set up the component, returning True on success."""
        self._cm.prepare()

        #        Clear out the cobwebs ;-)
        self._cm.stopall(verbose=True, force=True)

        # Now start the Cluster Manager on all the nodes.
        self._cm.log("Starting Cluster Manager on all nodes.")
        return self._cm.startall(verbose=True, quick=True)

    def teardown(self):
        """Tear down the component."""
        self._cm.log("Stopping Cluster Manager on all nodes")
        self._cm.stopall(verbose=True, force=False)


class LeaveBooted(BootCluster):
    """Leave all nodes up when the scenario is complete."""

    def teardown(self):
        """Tear down the component."""
        self._cm.log("Leaving Cluster running on all nodes")
