""" A module for managing and communicating with external processes """

__all__ = ["killall", "exit_if_proc_running"]
__copyright__ = "Copyright 2009-2023 the Pacemaker project contributors"
__license__ = "LGPLv2.1+"

import sys

import psutil

from pacemaker.exitstatus import ExitStatus

def killall(process_names, terminate=False):
    """ Kill all instances of every process in a list """

    if not process_names:
        return
    elif not isinstance(process_names, list):
        process_names = [process_names]

    procs = []
    for proc in psutil.process_iter(["name"]):
        if proc.info["name"] in process_names:
            procs.append(proc)

    if terminate:
        for proc in procs:
            proc.terminate()
        gone, alive = psutil.wait_procs(procs, timeout=3)
        procs = alive

    for proc in procs:
        proc.kill()


def is_proc_running(process_name):
    """ Check whether a process with a given name is running """

    for proc in psutil.process_iter(["name"]):
        if proc.info["name"] == process_name:
            return True
    return False


def exit_if_proc_running(process_name):
    """ Exit with error if a given process is running """

    if is_proc_running(process_name):
        print("Error: %s is already running!" % process_name)
        print("Run %s only when the cluster is stopped." % sys.argv[0])
        sys.exit(ExitStatus.ERROR)
