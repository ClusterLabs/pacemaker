# Copyright 2009-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.

__all__ = ["ExitCodeError", "OutputFoundError", "OutputNotFoundError", "XmlValidationError"]


class TestError(Exception):
    """ Base class for exceptions in this module """
    pass


class ExitCodeError(TestError):
    """ Exception raised when command exit status is unexpected """

    def __init__(self, exit_code):
        self.exit_code = exit_code

    def __str__(self):
        return repr(self.exit_code)


class OutputNotFoundError(TestError):
    """ Exception raised when command output does not contain wanted string """

    def __init__(self, output):
        self.output = output

    def __str__(self):
        return repr(self.output)


class OutputFoundError(TestError):
    """ Exception raised when command output contains unwanted string """

    def __init__(self, output):
        self.output = output

    def __str__(self):
        return repr(self.output)


class XmlValidationError(TestError):
    """ Exception raised when xmllint fails """

    def __init__(self, output):
        self.output = output

    def __str__(self):
        return repr(self.output)
