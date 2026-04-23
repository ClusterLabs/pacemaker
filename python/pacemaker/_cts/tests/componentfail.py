"""Kill a pacemaker daemon and test how the cluster recovers."""

__all__ = ["ComponentFail"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import re

from pacemaker._cts import logging
from pacemaker._cts.audits import AuditResource
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable
# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


# @TODO Separate this into a separate test for each component, so the patterns
# can be made specific to each component, investigating failures is a little
# easier, and specific testing can be done for each component (for example,
# set attributes before and after killing pacemaker-attrd and check values).
class ComponentFail(CTSTest):
    """Kill a random pacemaker daemon and wait for the cluster to recover."""

    def __init__(self, cm):
        """
        Create a new ComponentFail instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.is_unsafe = True
        self.name = "ComponentFail"

        self._complist = cm.components
        self._okerrpatterns = []
        self._patterns = []
        self._startall = SimulStartLite(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        self._patterns = []
        self._okerrpatterns = []

        # start all nodes
        ret = self._startall(None)
        if not ret:
            return self.failure("Setup failed")

        if not self._cm.cluster_stable(self._env["stable_time"]):
            return self.failure("Setup failed - unstable")

        # select a component to kill
        chosen = self._env.random_gen.choice(self._complist)
        node_is_dc = self._cm.is_node_dc(node, None)

        self.debug(f"...component {chosen.name} (dc={node_is_dc})")
        self.incr(chosen.name)

        if chosen.name != "corosync":
            self._patterns.extend([
                self._cm.templates["Pat:ChildKilled"] % (node, chosen.name),
                self._cm.templates["Pat:ChildRespawn"] % (node, chosen.name),
            ])

        self._patterns.extend(chosen.pats)

        # @TODO this should be a flag in the Component
        if chosen.name in ["corosync", "pacemaker-based", "pacemaker-fenced"]:
            # Ignore actions for fence devices if fencer will respawn
            # (their registration will be lost, and probes will fail)
            self._okerrpatterns = [
                self._cm.templates["Pat:Resource_active"],
            ]
            (_, lines) = self._rsh(node, "crm_resource -c", verbose=1)

            for line in lines:
                if re.search("^Resource", line):
                    r = AuditResource(self._cm, line)

                    if r.rclass == "stonith":
                        self._okerrpatterns.extend([
                            self._cm.templates["Pat:Fencing_recover"] % r.id,
                            self._cm.templates["Pat:Fencing_probe"] % r.id,
                        ])

        # supply a copy so self.patterns doesn't end up empty
        tmp_pats = self._patterns.copy()
        self._patterns.extend(chosen.badnews_ignore)

        # Look for STONITH ops, depending on Env["at-boot"] we might need to change the nodes status
        stonith_pats = [
            self._cm.templates["Pat:Fencing_ok"] % node
        ]
        stonith = self.create_watch(stonith_pats, 0)
        stonith.set_watch()

        # set the watch for stable
        watch = self.create_watch(
            tmp_pats, self._env["dead_time"] + self._env["stable_time"] + self._env["start_time"])

        watch.set_watch()

        # kill the component
        chosen.signal("KILL", node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()

        self.debug("Waiting for any fenced node to come back up")
        self._cm.ns.wait_for_all_nodes(self._env["nodes"], 600)

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        self._cm.cluster_stable(self._env["start_time"])

        self.debug(f"Checking if {node} was shot")
        shot = stonith.look(60)

        if shot:
            self.debug(f"Found: {shot!r}")
            self._okerrpatterns.append(self._cm.templates["Pat:Fencing_start"] % node)

            if not self._env["at-boot"]:
                self._cm.expected_status[node] = "down"

            # If fencing occurred, chances are many (if not all) the expected logs
            # will not be sent - or will be lost when the node reboots
            return self.success()

        # check for logs indicating a graceful recovery
        matched = watch.look_for_all(allow_multiple_matches=True)
        if watch.unmatched:
            logging.log(f"Patterns not found: {watch.unmatched!r}")

        self.debug("Waiting for the cluster to re-stabilize with all nodes")
        is_stable = self._cm.cluster_stable(self._env["start_time"])

        if not matched:
            return self.failure(f"Didn't find all expected {chosen.name} patterns")

        if not is_stable:
            return self.failure(f"Cluster did not become stable after killing {chosen.name}")

        return self.success()

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        # Note that okerrpatterns refers to the last time we ran this test
        # The good news is that this works fine for us...
        self._okerrpatterns.extend(self._patterns)
        return self._okerrpatterns
