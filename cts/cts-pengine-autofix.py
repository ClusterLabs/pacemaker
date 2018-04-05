#!/usr/bin/python
# Copyright 2018 Red Hat, Inc.
# Author: Jan Pokorny <jpokorny@redhat.com>
# Part of pacemaker project
# SPDX-License-Identifier: GPL-2.0-or-later

# Tested with Python 2.7+ and 3.6.
# Belongs to maintainer's toolset, you likely do not want to use this.
# Extensible, should there by any other daunting adjustment task;
# directly when the changes are orthogonal (mutually non-interfering),
# more complicated handler ordering mechanism needed otherwise.

from difflib import ndiff  #, unified_diff
from os import path
from re import compile as re_compile
from shlex import split
from subprocess import Popen, PIPE
from sys import argv, exit, version_info


if version_info[0] < 3:
    str_enc = lambda s, encoding='utf-8': s
else:
    str_enc = lambda s, encoding='utf-8': str(s, encoding=encoding)


# Inspired by http://stackoverflow.com/a/1383402
class classproperty(property):
    def __init__(self, fnc):
        property.__init__(self, classmethod(fnc))

    def __get__(self, this, owner):
        return self.fget.__get__(None, owner)()


class PopenPipedStdout(object):
    def __init__(self, *args, **kwargs):
        self._args = args
        kwargs.update(dict(stdout=PIPE))
        self._kwargs = kwargs

    def __enter__(self):
        self._p = Popen(*self._args, **self._kwargs)
        return self._p

    def __exit__(self, *args):
        if self._p.returncode is None:
            self._p.terminate()


class Fixer(object):
    """Abstract base class showing the intended protocol"""

    @classmethod
    def scan(cls, line):
        raise NotImplementedError

    @classmethod
    def fixup(cls, src, fixup_data):
        raise NotImplementedError


class DigestCmp(Fixer):
    """Fixer to fix changed hashes in the operation events"""

    re_scan = re_compile(r'[0-9a-z]{32}')

    @classmethod
    def scan(cls, line):
        if "rsc_action_digest_cmp" in line:
            found = cls.re_scan.findall(line)
            if len(found) == 2:
                return found
            return None

    @classmethod
    def fixup(cls, src, fixup_data):
        for src_hash in fixup_data:
            src = src.replace(src_hash, fixup_data[src_hash])
        return src


class FixerEngine(object):
    runner = 'cts-pengine'
    _runner_path = None
    fixers = (DigestCmp, )

    def __init__(self):
        # store/deal with args/kwargs (-> some methods no longer class ones)
        pass

    @classproperty
    def runner_path(cls):
        if cls._runner_path is None:
            root = path.dirname(__file__) or '.'
            runner_path = cls._runner_path = path.join(root, cls.runner)
            if not path.exists(runner_path):
                raise RuntimeError("script is not located where {runner} is"
                                   .format(runner=self.runner))
        return cls._runner_path

    @classmethod
    def _scan_shallow(cls):
        print(">>> collecting failing tests...")
        scan_buffer = []  # deque?
        with PopenPipedStdout(split(cls.runner_path)) as proc:
            while proc.poll() is None:
                line = str_enc(proc.stdout.readline().strip())
                if line.startswith("Test "):
                    if len(scan_buffer) > 1:  # test + failed
                        print('\n'.join(scan_buffer))
                        yield scan_buffer[0].split(':', 1)[0][len("Test "):]
                    scan_buffer[:] = [line]
                    continue
                elif line.startswith("* FAILED"):
                    scan_buffer.append(line)
                    continue
                elif line:  # we want to know all other "leftovers"
                    print("??? {0}".format(line))

            while proc.poll() is None:
                line = str_enc(proc.stdout.readline().strip())
                if line.startswith("Test "):
                    scan_buffer[:] = [line]
                    wait_for_new = False
                    continue
                elif line.startswith("* FAILED") and not wait_for_new \
                        and scan_buffer[-1].startswith("Test "):
                    print('\n'.join([scan_buffer[-1], line]))
                    yield scan_buffer[-1].split(':', 1)[0][len("Test "):]
                    wait_for_new = True
                    continue
                elif line.startswith("* FAILED"):
                    print(line)
                if not wait_for_new:
                    scan_buffer.append(line)

    @classmethod
    def _scan_deep(cls, test):
        print(">>> digging deeper for {0} test failure details...".format(test))
        deepscan = {}
        with PopenPipedStdout(split(cls.runner_path)
                              + ['--run', test]
                              + ['--testcmd-options', '-VVVV']) as proc:
            while proc.poll() is None:
                line = str_enc(proc.stdout.readline().strip())
                for fixer in cls.fixers:
                    evaled = fixer.scan(line)
                    if evaled is not None:
                        now = deepscan.setdefault(fixer, dict())
                        now = now.setdefault(*evaled)
                        assert now == evaled[1]
        return deepscan

    @classmethod
    def _get_modified(cls):
        # test name -> (fix -> <handler specific>)
        fixups = {}
        for test in cls._scan_shallow():
            deepscan = cls._scan_deep(test)
            if deepscan:
                now = fixups.setdefault(test, deepscan)
                assert now == deepscan
                origin = path.join(path.dirname(__file__), 'pengine',
                                  "{0}.xml".format(test))
                try:
                    with open(origin) as f:
                        original = f.read()
                except OSError:
                    print(">>> Cannot open {0}".format(origin))
                    continue
                modified = original
                for handler in deepscan:  # XXX random order (orthogonality)
                    print(">>> applying {0} fixer...".format(handler.__name__))
                    modified = handler.fixup(modified, deepscan[handler])
                yield origin, original, modified
            else:
                print(">>> Cannot fix {0} up in any way now".format(test))
        #from pprint import pprint
        #pprint(fixups)

    @classmethod
    def show(cls):
        for origin, original, modified in cls._get_modified():
            print('\n'.join(
                ndiff(original.splitlines(), modified.splitlines())
                #unified_diff(original.splitlines(), modified.splitlines(),
                #             origin, "{0}.new".format(origin))
            ))
        return 0

    @classmethod
    def perform(cls):
        for origin, original, modified in cls._get_modified():
            with open(origin, 'w') as f:
                f.truncate(0)
                f.writelines(modified)
        return 0


def main(argv=()):
    if any(argv.count(a) for a in ('-h', '--help')):
        print('\n'.join([
            'Usage: {prog}',
            '-h, --help: this help screen',
            '-n, --dry-run: show the generated deltas w/o application',
        ]).format(prog=argv[0]))
        return 0
    dry_run = any(argv.count(a) for a in ('-n', '--dry-run'))
    fe = FixerEngine()
    return fe.show() if dry_run else fe.perform()


if __name__ == '__main__':
    exit(main(argv))
