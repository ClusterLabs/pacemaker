"""Test managing secrets with cibsecret."""

__all__ = ["CibsecretTest"]
__copyright__ = "Copyright 2025-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

from pacemaker.exitstatus import ExitStatus
from pacemaker._cts.tests.ctstest import CTSTest
from pacemaker._cts.tests.simulstartlite import SimulStartLite
from pacemaker._cts.timer import Timer

# Disable various pylint warnings that occur in so many places throughout this
# file it's easiest to just take care of them globally.  This does introduce the
# possibility that we'll miss some other cause of the same warning, but we'll
# just have to be careful.

# pylint doesn't understand that self._env is subscriptable.
# pylint: disable=unsubscriptable-object
# pylint doesn't understand that self._rsh is callable.
# pylint: disable=not-callable


# This comes from include/config.h as private API, assuming pacemaker is built
# with cibsecrets support.  I don't want to expose this value publically, at
# least not until we default to including cibsecrets, so it's just set here
# for now.
SECRETS_DIR = "/var/lib/pacemaker/lrm/secrets"


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
        self._startall = SimulStartLite(cm)

    def _insert_dummy(self, node):
        """Create a dummy resource on the given node."""
        pats = [
            f"{node}.*" + (self._cm.templates["Pat:RscOpOK"] % ("start", self._rid))
        ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()

        self._cm.add_dummy_rsc(node, self._rid)

        with Timer(self.name, "addDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when adding dummy resource")
            return repr(watch.unmatched)

        return ""

    def _remove_dummy(self, node):
        """Remove the previously created dummy resource on the given node."""
        pats = [
            self._cm.templates["Pat:RscOpOK"] % ("stop", self._rid)
        ]

        watch = self.create_watch(pats, 60)
        watch.set_watch()
        self._cm.remove_dummy_rsc(node, self._rid)

        with Timer(self.name, "removeDummy"):
            watch.look_for_all()

        if watch.unmatched:
            self.debug("Failed to find patterns when removing dummy resource")
            return repr(watch.unmatched)

        return ""

    def _check_cib_value(self, node, expected):
        """Check that the secret has the expected value."""
        (rc, lines) = self._rsh(node, f"crm_resource -r {self._rid} -g {self._secret}",
                                verbose=1)
        s = " ".join(lines).strip()

        if rc != 0 or s != expected:
            return self.failure(f"Secret set to '{s}' in CIB, not '{expected}'")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_check(self, node):
        """Test the 'cibsecret check' subcommand."""
        (rc, _) = self._rsh(node, f"cibsecret check {self._rid} {self._secret}",
                            verbose=1)
        if rc != 0:
            return self.failure("Failed to check secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_delete(self, node):
        """Test the 'cibsecret delete' subcommand."""
        (rc, _) = self._rsh(node, f"cibsecret delete {self._rid} {self._secret}",
                            verbose=1)
        if rc != 0:
            return self.failure("Failed to delete secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_get(self, node, expected):
        """Test the 'cibsecret get' subcommand."""
        (rc, lines) = self._rsh(node, f"cibsecret get {self._rid} {self._secret}",
                                verbose=1)
        s = " ".join(lines).strip()

        if rc != 0 or s != expected:
            return self.failure(f"Secret set to '{s}' in local file, not '{expected}'")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_set(self, node):
        """Test the 'cibsecret set' subcommand."""
        (rc, _) = self._rsh(node, f"cibsecret set {self._rid} {self._secret} {self._secret_val}",
                            verbose=1)
        if rc != 0:
            return self.failure("Failed to set secret")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_stash(self, node):
        """Test the 'cibsecret stash' subcommand."""
        (rc, _) = self._rsh(node, f"cibsecret stash {self._rid} {self._secret}",
                            verbose=1)
        if rc != 0:
            return self.failure(f"Failed to stash secret {self._secret}")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_sync(self, node):
        """Test the 'cibsecret sync' subcommand."""
        (rc, _) = self._rsh(node, "cibsecret sync", verbose=1)
        if rc != 0:
            return self.failure("Failed to sync secrets")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_unstash(self, node):
        """Test the 'cibsecret unstash' subcommand."""
        (rc, _) = self._rsh(node, f"cibsecret unstash {self._rid} {self._secret}",
                            verbose=1)
        if rc != 0:
            return self.failure(f"Failed to unstash secret {self._secret}")

        # This is self.success, except without incrementing the success counter
        return True

    def _test_secrets_removed(self):
        """Verify that the secret and its checksum file has been removed."""
        f = f"{SECRETS_DIR}/{self._rid}/{self._secret}"
        if not self._rsh.exists_on_none(f, self._env["nodes"]):
            return self.failure(f"{f} not deleted from all hosts")

        f = f"{SECRETS_DIR}/{self._rid}/{self._secret}.sign"
        if not self._rsh.exists_on_none(f, self._env["nodes"]):
            return self.failure(f"{f} not deleted from all hosts")

        return True

    # @TODO: Two improvements that could be made to this test:
    #
    # (1) Add a test for the 'cibsecret sync' command.  This requires modifying
    #     the test so it brings down one node before creating secrets, then
    #     bringing the node back up, running 'cibsecret sync', and verifying the
    #     secrets are copied over.  All of this is possible with ctslab, it's
    #     just kind of a lot of code.
    #
    # (2) Add some tests for failure cases like trying to stash a value that's
    #     already secret, etc.
    def __call__(self, node):
        """Perform this test."""
        self.incr("calls")
        ret = self._startall(None)
        if not ret:
            return self.failure("Start all nodes failed")

        ret = self._insert_dummy(node)
        if ret != "":
            return self.failure(ret)

        # Test setting a new secret, verifying its value in both the CIB and
        # the local store on each node.
        if not self._test_set(node):
            return False
        if not self._check_cib_value(node, "lrm://"):
            return False

        for n in self._env["nodes"]:
            if not self._test_get(n, self._secret_val):
                return False

        # Test checking the secret on each node.
        for n in self._env["nodes"]:
            if not self._test_check(n):
                return False

        # Test moving the secret into the CIB, but now we can only verify that
        # its value in the CIB is correct since it's no longer a secret.  We
        # can also verify that it's been removed from the local store everywhere.
        if not self._test_unstash(node):
            return False
        if not self._check_cib_value(node, self._secret_val):
            return False

        self._test_secrets_removed()

        # Test moving the secret back out of the CIB, again verifying its
        # value in both places.
        if not self._test_stash(node):
            return False
        if not self._check_cib_value(node, "lrm://"):
            return False

        for n in self._env["nodes"]:
            if not self._test_get(n, self._secret_val):
                return False

        # Delete the secret
        if not self._test_delete(node):
            return False

        self._test_secrets_removed()
        self._remove_dummy(node)

        return self.success()

    @property
    def errors_to_ignore(self):
        return [r"Reloading .* \(agent\)"]

    def is_applicable(self):
        # This test requires that the node it runs on can ssh into the other
        # nodes without a password.  Testing every combination is probably
        # overkill (and will slow down `cts-lab --list-tests`), so here we're
        # just going to test that the first node can ssh into the others.
        if len(self._cm.env["nodes"]) < 2:
            return False

        node = self._cm.env["nodes"][0]
        other = self._cm.env["nodes"][1:]

        for o in other:
            (rc, _) = self._cm.rsh(node, f"{self._cm.rsh.command} {o} exit",
                                   verbose=0)
            if rc != ExitStatus.OK:
                return False

        return True
