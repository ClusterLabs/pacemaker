# -*- coding: UTF-8 -*-
"""Tito ad-hoc module for custom git repo -> spec + archive metamorphosis"""

from __future__ import (print_function, unicode_literals, absolute_import,
                        division)

__author__ = "Jan Pokorný <jpokorny@redhat.com>"
__copyright__ = "Copyright 2016 Red Hat, Inc."
__license__ = "LGPLv2.1+ WITHOUT ANY WARRANTY"


from os.path import basename, join
from shutil import copyfile

from tito.builder.main import BuilderBase
from tito.builder.fetch import FetchBuilder
from tito.common import error_out, run_command, get_spec_version_and_release


class NativeFetchBuilder(FetchBuilder):
    """
    A specialized FetchBuilder to just setup the specfile + archive
    using package-native scripts, which currently boils down to a sequence
    that needs to be configured via fetch_prep_command option in builder
    section (e.g., "./autogen.sh && ./configure && make dist foo.spec").

    Uses code of src/tito/builder/fetch.py from the tito project as a template.
    """
    REQUIRED_ARGS = []

    def __init__(self, name=None, tag=None, build_dir=None,
                 config=None, user_config=None,
                 args=None, **kwargs):

        BuilderBase.__init__(self, name=name, build_dir=build_dir,
                             config=config,
                             user_config=user_config, args=args, **kwargs)

        if tag:
            error_out("FetchBuilder does not support building specific tags.")

        if not config.has_option('builder', 'fetch_prep_command'):
            error_out("NativeFetchBuilder requires fetch_prep_command.")

        self.build_tag = '%s-%s' % (
            self.project_name,
            get_spec_version_and_release(self.start_dir,
                                         '%s.spec' % self.project_name)
        )

    def tgz(self):
        self.ran_tgz = True
        self._create_build_dirs()

        print("Fetching sources...")
        run_command(self.config.get('builder', 'fetch_prep_command'))
        manual_sources = [run_command("ls -1t *.tar.* | head -n1")]
        self.spec_file = self.project_name + '.spec'
        for s in manual_sources:
            base_name = basename(s)
            dest_filepath = join(self.rpmbuild_sourcedir, base_name)
            copyfile(s, dest_filepath)
            self.sources.append(dest_filepath)
