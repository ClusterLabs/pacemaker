"""Move a connection resource from one node to another."""

__all__ = ["RemoteMigrate"]
__copyright__ = "Copyright 2000-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts import logging
from pacemaker._cts.tests.remotedriver import RemoteDriver


class RemoteMigrate(RemoteDriver):
    """Move a connection resource from one node to another."""

    def __init__(self, cm, env):
        """
        Create a new RemoteMigrate instance.

        Arguments:
        cm  -- A ClusterManager instance
        env -- An Environment instance
        """
        RemoteDriver.__init__(self, cm, env)

        self.name = "RemoteMigrate"

    def __call__(self, node):
        """Perform this test."""
        # This code is very similar to __call__ in remotestonithd.py, but I don't think
        # it's worth turning into a library function nor making one a subclass of the
        # other.  I think that's more confusing than leaving the duplication.
        # pylint: disable=duplicate-code

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.migrate_connection(node)
        self.cleanup_metal(node)

        logging.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    def is_applicable(self):
        """Return True if this test is applicable in the current test configuration."""
        if not RemoteDriver.is_applicable(self):
            return False

        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        return len(self._env["nodes"]) >= 3
