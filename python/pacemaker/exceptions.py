"""A module providing exceptions that can be raised by the Pacemaker module."""

__all__ = ["PacemakerError"]
__copyright__ = "Copyright 2025 the Pacemaker project contributors"
__license__ = "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)"


class PacemakerError(Exception):
    """Base exception class for all Pacemaker errors."""
