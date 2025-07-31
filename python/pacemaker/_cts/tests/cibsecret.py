"""Test managing secrets with cibsecret."""

__all__ = ["CibsecretTest"]
__copyright__ = "Copyright 2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.tests.starttest import StartTest
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object


class CibsecretTest(CTSTest):
    """Test managing secrets with cibsecret."""

    def __init__(self, cm):
        """
        Create a new CibsecretTest instance.

        Arguments:
        cm -- A ClusterManager instance
        """
        CTSTest.__init__(self, cm)
        self.name = "Cibsecret"

        self._secret = "passwd"
        self._secret_val = "SecreT_PASS"

        self._rid = "secretDummy"
        self._start = StartTest(cm)
        self._startall = SimulStartLite(cm)

    def _insert_dummy(self, node):
        """Create a dummy resource on the given node."""
        pats = [
            f"{node}.*" + (self.templates["Pat:RscOpOK"] % ("start", self._rid))
        ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.add_dummy_rsc(node, self._rid)

        with Timer(self._logger, self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding dummy resource")
            return repr(watch.unmatched)

        return ""

    def _check_cib_value(self, node, expected):
        (rc, lines) = self._rsh(node, f"crm_resource -r {self._rid} -g {self._secret}",
                                verbose=1)
        s = " ".join(lines).strip()

        if rc != 0 or s != expected:
            return self.failure(f"Secret set to '{s}', not '{expected}'")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_check(self, node):
        (rc, _) = self._rsh(node, f"cibsecret check {self._rid} {self._secret}",
                            verbose=1)
        if rc != 0:
            return self.failure("Failed to check secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_delete(self, node):
        (rc, _) = self._rsh(node, f"cibsecret delete {self._rid} {self._secret}",
                            verbose=2)
        if rc != 0:
            return self.failure("Failed to delete secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_get(self, node, expected):
        (rc, lines) = self._rsh(node, f"cibsecret get {self._rid} {self._secret}",
                                verbose=1)
        s = " ".join(lines).strip()

        if rc != 0 or s != expected:
            return self.failure(f"Secret set to '{s}', not '{expected}'")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_set(self, node):
        (rc, _) = self._rsh(node, f"cibsecret set {self._rid} {self._secret} {self._secret_val}",
                            verbose=2)
        if rc != 0:
            return self.failure("Failed to set secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_stash(self, node):
        (rc, _) = self._rsh(node, f"cibsecret stash {self._rid} {self._secret}",
                            verbose=2)
        if rc != 0:
            return self.failure(f"Failed to stash secret {self._secret}")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_unstash(self, node):
        (rc, _) = self._rsh(node, f"cibsecret unstash {self._rid} {self._secret}",
                            verbose=2)
        if rc != 0:
            return self.failure(f"Failed to unstash secret {self._secret}")

        # This is self.success, except without incrementing the success counter
        return True

    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        ret = self._insert_dummy(node)
        if ret != "":
            return self.failure(ret)

        # Test setting a new secret, verifying its value in both the local
        # store and in the CIB.
        if not self._test_set(node):
            return False
        if not self._check_cib_value(node, "lrm://"):
            return False
        if not self._test_get(node, self._secret_val):
            return False

        # Test checking the secret
        if not self._test_check(node):
            return False

        # Test moving the secret into the CIB, but now we can only verify that
        # its value in the CIB is correct since it's no longer a secret
        if not self._test_unstash(node):
            return False
        if not self._check_cib_value(node, self._secret_val):
            return False

        # Test moving the secret back out of the CIB, again verifying its
        # value in both places
        if not self._test_stash(node):
            return False
        if not self._check_cib_value(node, "lrm://"):
            return False
        if not self._test_get(node, self._secret_val):
            return False

        # Delete the secret
        if not self._test_delete(node):
            return False

        return self.success()

    @property
    def errors_to_ignore(self):
        return [ r"Reloading .* \(agent\)" ]
