""" Fail a random resource and verify its fail count increases """

__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.timer import Timer


class ResourceRecover(CTSTest):
    """ A concrete test that fails a random resource """

    def __init__(self, cm):
        """ Create a new ResourceRecover instance

            Arguments:

            cm -- A ClusterManager instance
        """

        CTSTest.__init__(self, cm)

        self.action = "asyncmon"
        self.benchmark = True
        self.interval = 0
        self.max = 30
        self.name = "ResourceRecover"
        self.rid = None
        self.rid_alt = None

        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        """ Perform this test """

        self.incr("calls")

        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        # List all resources active on the node (skip test if none)
        resourcelist = self._cm.active_resources(node)
        if len(resourcelist) == 0:
            self._logger.log("No active resources on %s" % node)
            return self.skipped()

        # Choose one resource at random
        rsc = self.choose_resource(node, resourcelist)
        if rsc is None:
            return self.failure("Could not get details of resource '%s'" % self.rid)

        if rsc.id == rsc.clone_id:
            self.debug("Failing " + rsc.id)
        else:
            self.debug("Failing " + rsc.id + " (also known as " + rsc.clone_id + ")")

        # Log patterns to watch for (failure, plus restart if managed)
        pats = []
        pats.append(self.templates["Pat:CloneOpFail"] % (self.action, rsc.id, rsc.clone_id))

        if rsc.managed:
            pats.append(self.templates["Pat:RscOpOK"] % ("stop", self.rid))

            if rsc.unique:
                pats.append(self.templates["Pat:RscOpOK"] % ("start", self.rid))
            else:
                # Anonymous clones may get restarted with a different clone number
                pats.append(self.templates["Pat:RscOpOK"] % ("start", ".*"))

        # Fail resource. (Ideally, we'd fail it twice, to ensure the fail count
        # is incrementing properly, but it might restart on a different node.
        # We'd have to temporarily ban it from all other nodes and ensure the
        # migration-threshold hasn't been reached.)
        if self.fail_resource(rsc, node, pats) is None:
            return None # self.failure() already called

        return self.success()

    def choose_resource(self, node, resourcelist):
        """ Choose a random resource to target """

        self.rid = self._env.random_gen.choice(resourcelist)
        self.rid_alt = self.rid
        (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

        for line in lines:
            if line.startswith("Resource: "):
                rsc = AuditResource(self._cm, line)

                if rsc.id == self.rid:
                    # Handle anonymous clones that get renamed
                    self.rid = rsc.clone_id
                    return rsc

        return None

    def get_failcount(self, node):
        """ Check the fail count of targeted resource on given node """

        (rc, lines) = self._rsh(node,
                               "crm_failcount --quiet --query --resource %s "
                               "--operation %s --interval %d "
                               "--node %s" % (self.rid, self.action,
                               self.interval, node), verbose=1)

        if rc != 0 or len(lines) != 1:
            self._logger.log("crm_failcount on %s failed (%d): %s" % (node, rc,
                            " // ".join(map(str.strip, lines))))
            return -1

        try:
            failcount = int(lines[0])
        except (IndexError, ValueError):
            self._logger.log("crm_failcount output on %s unparseable: %s" % (node,
                            ' '.join(lines)))
            return -1

        return failcount

    def fail_resource(self, rsc, node, pats):
        """ Fail the targeted resource, and verify as expected """

        orig_failcount = self.get_failcount(node)

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._rsh(node, "crm_resource -V -F -r %s -H %s &>/dev/null" % (self.rid, node))

        with Timer(self._logger, self.name, "recover"):
            watch.look_for_all()

        self._cm.cluster_stable()
        recovered = self._cm.ResourceLocation(self.rid)

        if watch.unmatched:
            return self.failure("Patterns not found: %s" % repr(watch.unmatched))

        elif rsc.unique and len(recovered) > 1:
            return self.failure("%s is now active on more than one node: %s"%(self.rid, repr(recovered)))

        elif len(recovered) > 0:
            self.debug("%s is running on: %s" % (self.rid, repr(recovered)))

        elif rsc.managed:
            return self.failure("%s was not recovered and is inactive" % self.rid)

        new_failcount = self.get_failcount(node)
        if new_failcount != (orig_failcount + 1):
            return self.failure("%s fail count is %d not %d" % (self.rid,
                                new_failcount, orig_failcount + 1))

        return 0 # Anything but None is success

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        return [ r"Updating failcount for %s" % self.rid,
                 r"schedulerd.*: Recover\s+(%s|%s)\s+\(.*\)" % (self.rid, self.rid_alt),
                 r"Unknown operation: fail",
                 self.templates["Pat:RscOpOK"] % (self.action, self.rid),
                 r"(ERROR|error).*: Action %s_%s_%d .* initiated outside of a transition" % (self.rid, self.action, self.interval) ]
