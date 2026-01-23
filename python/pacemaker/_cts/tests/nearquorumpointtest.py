"""Randomly start and stop nodes to bring the cluster close to the quorum point."""

__all__ = ["NearQuorumPointTest"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.tests.ctstest import CTSTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable
# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class NearQuorumPointTest(CTSTest):
    """Randomly start and stop nodes to bring the cluster close to the quorum point."""

    def __init__(self, cm):
        """
        Create a new NearQuorumPointTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.name = "NearQuorumPoint"

    def __call__(self, dummy):
        """Perform this test."""
        self.incr("calls")
        startset = []
        stopset = []

        stonith = self._cm.prepare_fencing_watcher()
        # decide what to do with each node
        for node in self._env["nodes"]:
            action = self._env.random_gen.choice(["start", "stop"])

            if action == "start":
                startset.append(node)
            elif action == "stop":
                stopset.append(node)

        self.debug(f"start nodes:{startset!r}")
        self.debug(f"stop nodes:{stopset!r}")

        # add search patterns
        watchpats = []
        for node in stopset:
            if self._cm.expected_status[node] == "up":
                watchpats.append(self._cm.templates["Pat:We_stopped"] % node)

        for node in startset:
            if self._cm.expected_status[node] == "down":
                watchpats.append(self._cm.templates["Pat:Local_started"] % node)
            else:
                for stopping in stopset:
                    if self._cm.expected_status[stopping] == "up":
                        watchpats.append(self._cm.templates["Pat:They_stopped"] % (node, stopping))

        if not watchpats:
            return self.skipped()

        if startset:
            watchpats.append(self._cm.templates["Pat:DC_IDLE"])

        watch = self.create_watch(watchpats, self._env["dead_time"] + 10)

        watch.set_watch()

        # begin actions
        for node in stopset:
            if self._cm.expected_status[node] == "up":
                self._cm.stop_cm_async(node)

        for node in startset:
            if self._cm.expected_status[node] == "down":
                self._cm.start_cm_async(node)

        # get the result
        if watch.look_for_all():
            self._cm.cluster_stable()
            self._cm.fencing_cleanup("NearQuorumPoint", stonith)
            return self.success()

        logging.log(f"Warn: Patterns not found: {watch.unmatched!r}")

        # get the "bad" nodes
        upnodes = []
        for node in stopset:
            if self._cm.stat_cm(node):
                upnodes.append(node)

        downnodes = []
        for node in startset:
            if not self._cm.stat_cm(node):
                downnodes.append(node)

        self._cm.fencing_cleanup("NearQuorumPoint", stonith)
        if not upnodes and not downnodes:
            self._cm.cluster_stable()

            # Make sure they're completely down with no residule
            for node in stopset:
                self._rsh(node, self._cm.templates["StopCmd"])

            return self.success()

        if upnodes:
            logging.log(f"Warn: Unstoppable nodes: {upnodes!r}")

        if downnodes:
            logging.log(f"Warn: Unstartable nodes: {downnodes!r}")

        return self.failure()
