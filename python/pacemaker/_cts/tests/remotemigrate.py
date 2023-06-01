""" Test-specific classes for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["RemoteMigrate"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.remotedriver import RemoteDriver


class RemoteMigrate(RemoteDriver):
    def __init__(self, cm):
        RemoteDriver.__init__(self, cm)
        self.name = "RemoteMigrate"

    def __call__(self, node):
        '''Perform the 'RemoteMigrate' test. '''

        if not self.start_new_test(node):
            return self.failure(self.fail_string)

        self.migrate_connection(node)
        self.cleanup_metal(node)

        self.debug("Waiting for the cluster to recover")
        self._cm.cluster_stable()
        if self.failed:
            return self.failure(self.fail_string)

        return self.success()

    def is_applicable(self):
        if not RemoteDriver.is_applicable(self):
            return 0
        # This test requires at least three nodes: one to convert to a
        # remote node, one to host the connection originally, and one
        # to migrate the connection to.
        if len(self._env["nodes"]) < 3:
            return 0
        return 1
