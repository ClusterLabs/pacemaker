""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["ComponentFail"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re

from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite


class ComponentFail(CTSTest):
    def __init__(self, cm):
        CTSTest.__init__(self,cm)
        self.name = "ComponentFail"
        self._startall = SimulStartLite(cm)
        self.complist = cm.Components()
        self.patterns = []
        self.okerrpatterns = []
        self.is_unsafe = True

    def __call__(self, node):
        '''Perform the 'ComponentFail' test. '''
        self.incr("calls")
        self.patterns = []
        self.okerrpatterns = []

        # start all nodes
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._cm.cluster_stable(self._env["StableTime"]):
            return self.failure("Setup failed - unstable")

        node_is_dc = self._cm.is_node_dc(node, None)

        # select a component to kill
        chosen = self._env.random_gen.choice(self.complist)
        while chosen.dc_only and node_is_dc == 0:
            chosen = self._env.random_gen.choice(self.complist)

        self.debug("...component %s (dc=%d)" % (chosen.name, node_is_dc))
        self.incr(chosen.name)

        if chosen.name != "corosync":
            self.patterns.append(self.templates["Pat:ChildKilled"] %(node, chosen.name))
            self.patterns.append(self.templates["Pat:ChildRespawn"] %(node, chosen.name))

        self.patterns.extend(chosen.pats)
        if node_is_dc:
          self.patterns.extend(chosen.dc_pats)

        # @TODO this should be a flag in the Component
        if chosen.name in [ "corosync", "pacemaker-based", "pacemaker-fenced" ]:
            # Ignore actions for fence devices if fencer will respawn
            # (their registration will be lost, and probes will fail)
            self.okerrpatterns = [ self.templates["Pat:Fencing_active"] ]
            (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)
            for line in lines:
                if re.search("^Resource", line):
                    r = AuditResource(self._cm, line)
                    if r.rclass == "stonith":
                        self.okerrpatterns.append(self.templates["Pat:Fencing_recover"] % r.id)
                        self.okerrpatterns.append(self.templates["Pat:Fencing_probe"] % r.id)

        # supply a copy so self.patterns doesn't end up empty
        tmpPats = []
        tmpPats.extend(self.patterns)
        self.patterns.extend(chosen.badnews_ignore)

        # Look for STONITH ops, depending on Env["at-boot"] we might need to change the nodes status
        stonithPats = []
        stonithPats.append(self.templates["Pat:Fencing_ok"] % node)
        stonith = self.create_watch(stonithPats, 0)
        stonith.set_watch()

        # set the watch for stable
        watch = self.create_watch(
            tmpPats, self._env["DeadTime"] + self._env["StableTime"] + self._env["StartTime"])
        watch.set_watch()

        # kill the component
        chosen.kill(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for any fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        self._cm.cluster_stable(self._env["StartTime"])

        self.debug("Checking if %s was shot" % node)
        shot = stonith.look(60)
        if shot:
            self.debug("Found: " + repr(shot))
            self.okerrpatterns.append(self.templates["Pat:Fencing_start"] % node)

            if not self._env["at-boot"]:
                self._cm.ShouldBeStatus[node] = "down"

            # If fencing occurred, chances are many (if not all) the expected logs
            # will not be sent - or will be lost when the node reboots
            return self.success()

        # check for logs indicating a graceful recovery
        matched = watch.look_for_all(allow_multiple_matches=True)
        if watch.unmatched:
            self._logger.log("Patterns not found: " + repr(watch.unmatched))

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["StartTime"])

        if not matched:
            return self.failure("Didn't find all expected %s patterns" % chosen.name)
        elif not is_stable:
            return self.failure("Cluster did not become stable after killing %s" % chosen.name)

        return self.success()

    @property
    def errors_to_ignore(self):
        """ Return list of errors which should be ignored """

        # Note that okerrpatterns refers to the last time we ran this test
        # The good news is that this works fine for us...
        self.okerrpatterns.extend(self.patterns)
        return self.okerrpatterns
