""" A module for managing and communicating with external processes """

__all__ = ["killall", "exit_if_proc_running", "pipe_communicate", "stdout_from_command"]
__copyright__ = "Copyright 2009-2023 the Pacemaker project contributors"
__license__ = "LGPLv2.1+"

import subprocess
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


def pipe_communicate(pipes, check_stderr=False, stdin=None):
    """ Get text output from pipes """

    if stdin is not None:
        pipe_outputs = pipes.communicate(input=stdin.encode())
    else:
        pipe_outputs = pipes.communicate()

    output = pipe_outputs[0].decode(sys.stdout.encoding)
    if check_stderr:
        output = output + pipe_outputs[1].decode(sys.stderr.encoding)

    return output


def stdout_from_command(args):
    """ Execute command and return its standard output """

    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    p.wait()
    return pipe_communicate(p).split("\n")
