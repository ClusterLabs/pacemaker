""" User input related utilities for CTS """

__all__ = ["should_continue"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

def should_continue(env):
    """ On failure, prompt the user to see if we should continue """

    if env["continue"]:
        return True

    try:
        answer = input("Continue? [yN]")
    except EOFError:
        answer = "n"

    return answer in ["y", "Y"]
