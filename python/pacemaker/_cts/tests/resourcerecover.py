"""Fail a random resource and verify its fail count increases."""

__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable


class ResourceRecover(CTSTest):
    """Fail a random resource."""

    def __init__(self, cm):
        """
        Create a new ResourceRecover instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.benchmark = True
        self.name = "ResourceRecover"

        self._action = "asyncmon"
        self._interval = 0
        self._rid = None
        self._rid_alt = None
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")

        if not self._startall(None):
            return self.failure("Setup failed")

        # List all resources active on the node (skip test if none)
        resourcelist = self._cm.active_resources(node)
        if not resourcelist:
            logging.log(f"No active resources on {node}")
            return self.skipped()

        # Choose one resource at random
        rsc = self._choose_resource(node, resourcelist)
        if rsc is None:
            return self.failure(f"Could not get details of resource '{self._rid}'")

        if rsc.id == rsc.clone_id:
            self.debug(f"Failing {rsc.id}")
        else:
            self.debug(f"Failing {rsc.id} (also known as {rsc.clone_id})")

        # Log patterns to watch for (failure, plus restart if managed)
        pats = [
            self._cm.templates["Pat:CloneOpFail"] % (self._action, rsc.id, rsc.clone_id)
        ]

        if rsc.managed:
            pats.append(self._cm.templates["Pat:RscOpOK"] % ("stop", self._rid))

            if rsc.unique:
                pats.append(self._cm.templates["Pat:RscOpOK"] % ("start", self._rid))
            else:
                # Anonymous clones may get restarted with a different clone number
                pats.append(self._cm.templates["Pat:RscOpOK"] % ("start", ".*"))

        # Fail resource. (Ideally, we'd fail it twice, to ensure the fail count
        # is incrementing properly, but it might restart on a different node.
        # We'd have to temporarily ban it from all other nodes and ensure the
        # migration-threshold hasn't been reached.)
        if self._fail_resource(rsc, node, pats) is None:
            # self.failure() already called
            return None

        return self.success()

    def _choose_resource(self, node, resourcelist):
        """Choose a random resource to target."""
        self._rid = self._env.random_gen.choice(resourcelist)
        self._rid_alt = self._rid
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

        for line in lines:
            if line.startswith("Resource: "):
                rsc = AuditResource(self._cm, line)

                if rsc.id == self._rid:
                    # Handle anonymous clones that get renamed
                    self._rid = rsc.clone_id
                    return rsc

        return None

    def _get_failcount(self, node):
        """Check the fail count of targeted resource on given node."""
        cmd = "crm_failcount --quiet --query --resource %s --operation %s --interval %d --node %s"
        (rc, lines) = self._rsh(node, cmd % (self._rid, self._action, self._interval, node),
                                verbose=1)

        if rc != 0 or len(lines) != 1:
            lines = [line.strip() for line in lines]
            s = " // ".join(lines)
            logging.log(f"crm_failcount on {node} failed ({rc}): {s}")
            return -1

        try:
            failcount = int(lines[0])
        except (IndexError, ValueError):
            s = " ".join(lines)
            logging.log(f"crm_failcount output on {node} unparseable: {s}")
            return -1

        return failcount

    def _fail_resource(self, rsc, node, pats):
        """Fail the targeted resource, and verify as expected."""
        orig_failcount = self._get_failcount(node)

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._rsh(node, f"crm_resource -V -F -r {self._rid} -H {node} &>/dev/null")

        with Timer(self.name, "recover"):
            watch.look_for_all()

        self._cm.cluster_stable()
        recovered = self._cm.resource_location(self._rid)

        if watch.unmatched:
            return self.failure(f"Patterns not found: {watch.unmatched!r}")

        if rsc.unique and len(recovered) > 1:
            return self.failure(f"{self._rid} is now active on more than one node: {recovered!r}")

        if recovered:
            self.debug(f"{self._rid} is running on: {recovered!r}")

        elif rsc.managed:
            return self.failure(f"{self._rid} was not recovered and is inactive")

        new_failcount = self._get_failcount(node)
        if new_failcount != orig_failcount + 1:
            return self.failure(f"{self._rid} fail count is {new_failcount} not {orig_failcount + 1}")

        # Anything but None is success
        return 0

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        return [
            f"Updating failcount for {self._rid}",
            fr"schedulerd.*: Recover\s+({self._rid}|{self._rid_alt})\s+\(.*\)",
            r"Unknown operation: fail",
            self._cm.templates["Pat:RscOpOK"] % (self._action, self._rid),
            f"(ERROR|error).*: Action {self._rid}_{self._action}_{self._interval} .* initiated outside of a transition",
        ]
