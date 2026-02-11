"""Start a node and then tell it to stop before it is fully running."""

__all__ = ["PartialStart"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.simulstoplite import SimulStopLite
from pacemaker._cts.tests.stoptest import StopTest

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class PartialStart(CTSTest):
    """Interrupt a node before it's finished starting up."""

    def __init__(self, cm):
        """
        Create a new PartialStart instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)

        self.name = "PartialStart"

        self._startall = SimulStartLite(cm)
        self._stop = StopTest(cm)
        self._stopall = SimulStopLite(cm)

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")

        ret = self._stopall(None)
        if not ret:
            return self.failure("Setup failed")

        watchpats = [
            "pacemaker-controld.*Connecting to .* cluster layer"
        ]
        watch = self.create_watch(watchpats, self._env["dead_time"] + 10)
        watch.set_watch()

        self._cm.start_cm_async(node)
        ret = watch.look_for_all()
        if not ret:
            logging.log(f"Patterns not found: {watch.unmatched!r}")
            return self.failure(f"Setup of {node} failed")

        ret = self._stop(node)
        if not ret:
            return self.failure(f"{node} did not stop in time")

        return self.success()

    @property
    def errors_to_ignore(self):
        """Return a list of errors which should be ignored."""
        # We might do some fencing in the 2-node case if we make it up far enough
        return [
            r"Executing reboot fencing operation",
            r"Requesting fencing \([^)]+\) targeting node "
        ]
