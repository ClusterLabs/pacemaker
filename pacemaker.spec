%global gname haclient
%global uname hacluster
%global pcmk_docdir %{_docdir}/%{name}

%global specversion 2
#global upstream_version ee19d8e83c2a
%global upstream_prefix pacemaker

# Keep around for when/if required
#global alphatag %{upstream_version}.hg

%global pcmk_release %{?alphatag:0.}%{specversion}%{?alphatag:.%{alphatag}}%{?dist}

# Conditionals
# Invoke "rpmbuild --without <feature>" or "rpmbuild --with <feature>"
# to disable or enable specific features
%bcond_without ais
%bcond_without heartbeat
# ESMTP is not available in RHEL, only in EPEL. Allow people to build
# the RPM without ESMTP in case they choose not to use EPEL packages
%bcond_without esmtp

Name:		pacemaker
Summary:	Scalable High-Availability cluster resource manager
Version:	1.0.7
Release:	%{pcmk_release}
License:	GPLv2+ and LGPLv2+
Url:		http://www.clusterlabs.org
Group:		System Environment/Daemons
Source0:	pacemaker.tar.bz2
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
AutoReqProv:	on
Requires(pre):	cluster-glue
Requires:	resource-agents python
Conflicts:      heartbeat < 2.99

%if 0%{?fedora} || 0%{?centos} > 4 || 0%{?rhel} > 4
Requires:       perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires:  help2man libtool-ltdl-devel
%endif

%if 0%{?suse_version}
# net-snmp-devel on SLES10 does not suck in tcpd-devel automatically
BuildRequires:  help2man tcpd-devel
%endif

# Required for core functionality
BuildRequires:  automake autoconf libtool pkgconfig
BuildRequires:	glib2-devel cluster-glue-libs-devel libxml2-devel libxslt-devel 
BuildRequires:	pkgconfig python-devel gcc-c++ bzip2-devel gnutls-devel pam-devel

# Enables optional functionality
BuildRequires:	ncurses-devel net-snmp-devel openssl-devel 
BuildRequires:	lm_sensors-devel libselinux-devel
%if %{with esmtp}
BuildRequires:	libesmtp-devel
%endif

%if %{with ais}
BuildRequires:	corosynclib-devel
Requires:	corosync
%endif

%if %{with heartbeat}
BuildRequires:	heartbeat-devel heartbeat-libs
Requires:	heartbeat >= 3.0.0
%endif

%description
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

Available rpmbuild rebuild options:
  --without : heartbeat ais

%package -n pacemaker-libs
License:	GPLv2+ and LGPLv2+
Summary:	Libraries used by the Pacemaker cluster resource manager and its clients
Group:		System Environment/Daemons
Requires:	%{name} = %{version}-%{release}

%description -n pacemaker-libs
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

%package -n pacemaker-libs-devel 
License:	GPLv2+ and LGPLv2+
Summary:	Pacemaker development package
Group:		Development/Libraries
Requires:	%{name}-libs = %{version}-%{release}
Requires:	cluster-glue-libs-devel
Obsoletes:      libpacemaker3
%if %{with ais}
Requires:	corosynclib-devel
%endif
%if %{with heartbeat}
Requires:	heartbeat-devel
%endif

%description -n pacemaker-libs-devel
Headers and shared libraries for developing tools for Pacemaker.

Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

%prep
%setup -q -n %{upstream_prefix}%{?upstream_version}

%build
./autogen.sh

# RHEL <= 5 does not support --docdir
export docdir=%{pcmk_docdir}
%{configure} --localstatedir=%{_var} --enable-fatal-warnings=no
make %{_smp_mflags} docdir=%{pcmk_docdir}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} docdir=%{pcmk_docdir}

# Scripts that need should be executable
chmod a+x %{buildroot}/%{_libdir}/heartbeat/hb2openais-helper.py
chmod a+x %{buildroot}/%{_datadir}/pacemaker/tests/cts/CTSlab.py
chmod a+x %{buildroot}/%{_datadir}/pacemaker/tests/cts/OCFIPraTest.py
chmod a+x %{buildroot}/%{_datadir}/pacemaker/tests/cts/extracttests.py

# These are not actually scripts
find %{buildroot} -name '*.xml' -type f -print0 | xargs -0 chmod a-x
find %{buildroot} -name '*.xsl' -type f -print0 | xargs -0 chmod a-x
find %{buildroot} -name '*.rng' -type f -print0 | xargs -0 chmod a-x
find %{buildroot} -name '*.dtd' -type f -print0 | xargs -0 chmod a-x
 
# Dont package static libs or compiled python
find %{buildroot} -name '*.a' -type f -print0 | xargs -0 rm -f
find %{buildroot} -name '*.la' -type f -print0 | xargs -0 rm -f
find %{buildroot} -name '*.pyc' -type f -print0 | xargs -0 rm -f
find %{buildroot} -name '*.pyo' -type f -print0 | xargs -0 rm -f

# Do not package these either
rm %{buildroot}/%{_libdir}/heartbeat/crm_primitive.py
%if %{with ais}
rm %{buildroot}/%{_libdir}/service_crm.so
%endif

%clean
rm -rf %{buildroot}

%post -n pacemaker-libs -p /sbin/ldconfig

%postun -n pacemaker-libs -p /sbin/ldconfig

%files
###########################################################
%defattr(-,root,root)

%exclude %{_datadir}/pacemaker/tests
%{_datadir}/pacemaker
%{_datadir}/snmp/mibs/PCMK-MIB.txt
%{_libdir}/heartbeat/*
%{_sbindir}/cibadmin
%{_sbindir}/crm_attribute
%{_sbindir}/crm_diff
%{_sbindir}/crm_failcount
%{_sbindir}/crm_master
%{_sbindir}/crm_mon
%{_sbindir}/crm
%{_sbindir}/crm_resource
%{_sbindir}/crm_standby
%{_sbindir}/crm_verify
%{_sbindir}/crmadmin
%{_sbindir}/iso8601
%{_sbindir}/attrd_updater
%{_sbindir}/ptest
%{_sbindir}/crm_shadow
%{_sbindir}/cibpipe
%{_sbindir}/crm_node

%if %{with heartbeat}
%{_sbindir}/crm_uuid
%else
%exclude %{_sbindir}/crm_uuid
%endif

# Packaged elsewhere
%exclude %{pcmk_docdir}/AUTHORS
%exclude %{pcmk_docdir}/COPYING
%exclude %{pcmk_docdir}/COPYING.LIB

%doc %{pcmk_docdir}/crm_cli.txt
%doc %{pcmk_docdir}/crm_fencing.txt
%doc %{pcmk_docdir}/README.hb2openais
%doc %{_mandir}/man8/*.8*
%doc COPYING
%doc AUTHORS

%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/heartbeat/crm
%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/pengine
%dir %attr (750, %{uname}, %{gname}) %{_var}/run/crm
%dir /usr/lib/ocf
%dir /usr/lib/ocf/resource.d
/usr/lib/ocf/resource.d/pacemaker
%if %{with ais}
%{_libexecdir}/lcrso/pacemaker.lcrso
%endif

%files -n pacemaker-libs
%defattr(-,root,root)
%{_libdir}/libcib.so.*
%{_libdir}/libcrmcommon.so.*
%{_libdir}/libcrmcluster.so.*
%{_libdir}/libpe_status.so.*
%{_libdir}/libpe_rules.so.*
%{_libdir}/libpengine.so.*
%{_libdir}/libtransitioner.so.*
%{_libdir}/libstonithd.so.*
%doc COPYING.LIB
%doc AUTHORS

%files -n pacemaker-libs-devel
%defattr(-,root,root)
%{_includedir}/pacemaker
%{_includedir}/heartbeat/fencing
%{_libdir}/*.so
%{_datadir}/pacemaker/tests
%doc COPYING.LIB
%doc AUTHORS

%changelog
* Tue Jan 19 2010 Andrew Beekhof <andrew@beekhof.net> - 1.0.7-2
- Rebuild for corosync 1.2.0

* Mon Jan 18 2010 Andrew Beekhof <andrew@beekhof.net> - 1.0.7-1
- Update source tarball to revision: 2eed906f43e9 (stable-1.0) tip
- Statistics:
      Changesets:      193
      Diff:            220 files changed, 15933 insertions(+), 8782 deletions(-)
- Changes since 1.0.5-4
  + High: PE: Bug 2213 - Ensure groups process location constraints so that clone-node-max works for cloned groups
  + High: PE: Bug lf#2153 - non-clones should not restart when clones stop/start on other nodes
  + High: PE: Bug lf#2209 - Clone ordering should be able to prevent startup of dependant clones
  + High: PE: Bug lf#2216 - Correctly identify the state of anonymous clones when deciding when to probe
  + High: PE: Bug lf#2225 - Operations that require fencing should wait for 'stonith_complete' not 'all_stopped'.
  + High: PE: Bug lf#2225 - Prevent clone peers from stopping while another is instance is (potentially) being fenced
  + High: PE: Correctly anti-colocate with a group
  + High: PE: Correctly unpack ordering constraints for resource sets to avoid graph loops
  + High: Tools: crm: load help from crm_cli.txt
  + High: Tools: crm: resource sets (bnc#550923)
  + High: Tools: crm: support for comments (LF 2221)
  + High: Tools: crm: support for description attribute in resources/operations (bnc#548690)
  + High: Tools: hb2openais: add EVMS2 CSM processing (and other changes) (bnc#548093)
  + High: Tools: hb2openais: do not allow empty rules, clones, or groups (LF 2215)
  + High: Tools: hb2openais: refuse to convert pure EVMS volumes
  + High: cib: Ensure the loop for login message terminates
  + High: cib: Finally fix reliability of receiving large messages over remote plaintext connections
  + High: cib: Fix remote notifications
  + High: cib: For remote connections, default to CRM_DAEMON_USER since thats the only one that the cib can validate the password for using PAM
  + High: cib: Remote plaintext - Retry sending parts of the message that did not fit the first time
  + High: crmd: Ensure batch-limit is correctly enforced
  + High: crmd: Ensure we have the latest status after a transition abort
  + High (bnc#547579,547582): Tools: crm: status section editing support
  + High: shell: Add allow-migrate as allowed meta-attribute (bnc#539968)
  + Medium: Build: Do not automatically add -L/lib, it could cause 64-bit arches to break
  + Medium: PE: Bug lf#2206 - rsc_order constraints always use score at the top level
  + Medium: PE: Only complain about target-role=master for non m/s resources
  + Medium: PE: Prevent non-multistate resources from being promoted through target-role
  + Medium: PE: Provide a default action for resource-set ordering
  + Medium: PE: Silently fix requires=fencing for stonith resources so that it can be set in op_defaults
  + Medium: Tools: Bug lf#2286 - Allow the shell to accept template parameters on the command line
  + Medium: Tools: Bug lf#2307 - Provide a way to determin the nodeid of past cluster members
  + Medium: Tools: crm: add update method to template apply (LF 2289)
  + Medium: Tools: crm: direct RA interface for ocf class resource agents (LF 2270)
  + Medium: Tools: crm: direct RA interface for stonith class resource agents (LF 2270)
  + Medium: Tools: crm: do not add score which does not exist
  + Medium: Tools: crm: do not consider warnings as errors (LF 2274)
  + Medium: Tools: crm: do not remove sets which contain id-ref attribute (LF 2304)
  + Medium: Tools: crm: drop empty attributes elements
  + Medium: Tools: crm: exclude locations when testing for pathological constraints (LF 2300)
  + Medium: Tools: crm: fix exit code on single shot commands
  + Medium: Tools: crm: fix node delete (LF 2305)
  + Medium: Tools: crm: implement -F (--force) option
  + Medium: Tools: crm: rename status to cibstatus (LF 2236)
  + Medium: Tools: crm: revisit configure commit
  + Medium: Tools: crm: stay in crm if user specified level only (LF 2286)
  + Medium: Tools: crm: verify changes on exit from the configure level
  + Medium: ais: Some clients such as gfs_controld want a cluster name, allow one to be specified in corosync.conf
  + Medium: cib: Clean up logic for receiving remote messages
  + Medium: cib: Create valid notification control messages
  + Medium: cib: Indicate where the remote connection came from
  + Medium: cib: Send password prompt to stderr so that stdout can be redirected
  + Medium: cts: Fix rsh handling when stdout is not required
  + Medium: doc: Fill in the section on removing a node from an AIS-based cluster
  + Medium: doc: Update the docs to reflect the 0.6/1.0 rolling upgrade problem
  + Medium: doc: Use Publican for docbook based documentation
  + Medium: fencing: stonithd: add metadata for stonithd instance attributes (and support in the shell)
  + Medium: fencing: stonithd: ignore case when comparing host names (LF 2292)
  + Medium: tools: Make crm_mon functional with remote connections
  + Medium: xml: Add stopped as a supported role for operations
  + Medium: xml: Bug bnc#552713 - Treat node unames as text fields not IDs
  + Medium: xml: Bug lf#2215 - Create an always-true expression for empty rules when upgrading from 0.6

* Thu Oct 29 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-4
- Include the fixes from CoroSync integration testing
- Move the resource templates - they are not documentation
- Ensure documentation is placed in a standard location
- Exclude documentation that is included elsewhere in the package

- Update the tarball from upstream to version ee19d8e83c2a
  + High: cib: Correctly clean up when both plaintext and tls remote ports are requested
  + High: PE: Bug bnc#515172 - Provide better defaults for lt(e) and gt(e) comparisions
  + High: PE: Bug lf#2197 - Allow master instances placemaker to be influenced by colocation constraints
  + High: PE: Make sure promote/demote pseudo actions are created correctly
  + High: PE: Prevent target-role from promoting more than master-max instances
  + High: ais: Bug lf#2199 - Prevent expected-quorum-votes from being populated with garbage
  + High: ais: Prevent deadlock - dont try to release IPC message if the connection failed
  + High: cib: For validation errors, send back the full CIB so the client can display the errors
  + High: cib: Prevent use-after-free for remote plaintext connections
  + High: crmd: Bug lf#2201 - Prevent use-of-NULL when running heartbeat

* Wed Oct 13 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-3
- Update the tarball from upstream to version 38cd629e5c3c
  + High: Core: Bug lf#2169 - Allow dtd/schema validation to be disabled
  + High: PE: Bug lf#2106 - Not all anonymous clone children are restarted after configuration change
  + High: PE: Bug lf#2170 - stop-all-resources option had no effect
  + High: PE: Bug lf#2171 - Prevent groups from starting if they depend on a complex resource which can not
  + High: PE: Disable resource management if stonith-enabled=true and no stonith resources are defined
  + High: PE: do not include master score if it would prevent allocation
  + High: ais: Avoid excessive load by checking for dead children every 1s (instead of 100ms)
  + High: ais: Bug rh#525589 - Prevent shutdown deadlocks when running on CoroSync
  + High: ais: Gracefully handle changes to the AIS nodeid
  + High: crmd: Bug bnc#527530 - Wait for the transition to complete before leaving S_TRANSITION_ENGINE
  + High: crmd: Prevent use-after-free with LOG_DEBUG_3
  + Medium: xml: Mask the "symmetrical" attribute on rsc_colocation constraints (bnc#540672)
  + Medium (bnc#520707): Tools: crm: new templates ocfs2 and clvm
  + Medium: Build: Invert the disable ais/heartbeat logic so that --without (ais|heartbeat) is available to rpmbuild
  + Medium: PE: Bug lf#2178 - Indicate unmanaged clones
  + Medium: PE: Bug lf#2180 - Include node information for all failed ops
  + Medium: PE: Bug lf#2189 - Incorrect error message when unpacking simple ordering constraint
  + Medium: PE: Correctly log resources that would like to start but can not
  + Medium: PE: Stop ptest from logging to syslog
  + Medium: ais: Include version details in plugin name
  + Medium: crmd: Requery the resource metadata after every start operation

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1.0.5-2.1
- rebuilt with new openssl

* Wed Aug 19 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-2
- Add versioned perl dependancy as specified by
    https://fedoraproject.org/wiki/Packaging/Perl#Packages_that_link_to_libperl
- No longer remove RPATH data, it prevents us finding libperl.so and no other
  libraries were being hardcoded
- Compile in support for heartbeat
- Conditionally add heartbeat-devel and corosynclib-devel to the -devel requirements 
  depending on which stacks are supported

* Mon Aug 17 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-1
- Add dependancy on resource-agents
- Use the version of the configure macro that supplies --prefix, --libdir, etc
- Update the tarball from upstream to version 462f1569a437 (Pacemaker 1.0.5 final)
  + High: Tools: crm_resource - Advertise --move instead of --migrate
  + Medium: Extra: New node connectivity RA that uses system ping and attrd_updater
  + Medium: crmd: Note that dc-deadtime can be used to mask the brokeness of some switches

* Tue Aug 11 2009 Ville Skyttä <ville.skytta@iki.fi> - 1.0.5-0.7.c9120a53a6ae.hg
- Use bzipped upstream tarball.

* Wed Jul  29 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-0.6.c9120a53a6ae.hg
- Add back missing build auto* dependancies
- Minor cleanups to the install directive

* Tue Jul  28 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-0.5.c9120a53a6ae.hg
- Add a leading zero to the revision when alphatag is used

* Tue Jul  28 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.5-0.4.c9120a53a6ae.hg
- Incorporate the feedback from the cluster-glue review
- Realistically, the version is a 1.0.5 pre-release
- Use the global directive instead of define for variables
- Use the haclient/hacluster group/user instead of daemon
- Use the _configure macro
- Fix install dependancies

* Fri Jul  24 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.4-3
- Initial Fedora checkin
- Include an AUTHORS and license file in each package
- Change the library package name to pacemaker-libs to be more 
  Fedora compliant
- Remove execute permissions from xml related files
- Reference the new cluster-glue devel package name
- Update the tarball from upstream to version c9120a53a6ae
  + High: PE: Only prevent migration if the clone dependancy is stopping/starting on the target node
  + High: PE: Bug 2160 - Dont shuffle clones due to colocation
  + High: PE: New implementation of the resource migration (not stop/start) logic
  + Medium: Tools: crm_resource - Prevent use-of-NULL by requiring a resource name for the -A and -a options
  + Medium: PE: Prevent use-of-NULL in find_first_action()

* Tue Jul 14 2009 Andrew Beekhof <andrew@beekhof.net> - 1.0.4-2
- Reference authors from the project AUTHORS file instead of listing in description
- Change Source0 to reference the Mercurial repo
- Cleaned up the summaries and descriptions
- Incorporate the results of Fedora package self-review

* Thu Jun 04 2009 Andrew Beekhof <abeekhof@suse.de> - 1.0.4-1
- Update source tarball to revision: 1d87d3e0fc7f (stable-1.0)
- Statistics:
    Changesets:      209
    Diff:            266 files changed, 12010 insertions(+), 8276 deletions(-)
- Changes since Pacemaker-1.0.3
  + High (bnc#488291): ais: do not rely on byte endianness on ptr cast
  + High (bnc#507255): Tools: crm: delete rsc/op_defaults (these meta_attributes are killing me)
  + High (bnc#507255): Tools: crm: import properly rsc/op_defaults
  + High (LF 2114): Tools: crm: add support for operation instance attributes
  + High: ais: Bug lf#2126 - Messages replies cannot be routed to transient clients
  + High: ais: Fix compilation for the latest Corosync API (v1719)
  + High: attrd: Do not perform all updates as complete refreshes
  + High: cib: Fix huge memory leak affecting heartbeat-based clusters
  + High: Core: Allow xpath queries to match attributes
  + High: Core: Generate the help text directly from a tool options struct
  + High: Core: Handle differences in 0.6 messaging format
  + High: crmd: Bug lf#2120 - All transient node attribute updates need to go via attrd
  + High: crmd: Correctly calculate how long an FSA action took to avoid spamming the logs with errors
  + High: crmd: Fix another large memory leak affecting Heartbeat based clusters
  + High: lha: Restore compatability with older versions
  + High: PE: Bug bnc#495687 - Filesystem is not notified of successful STONITH under some conditions
  + High: PE: Make running a cluster with STONITH enabled but no STONITH resources an error and provide details on resolutions
  + High: PE: Prevent use-ofNULL when using resource ordering sets
  + High: PE: Provide inter-notification ordering guarantees
  + High: PE: Rewrite the notification code to be understanable and extendable
  + High: Tools: attrd - Prevent race condition resulting in the cluster forgetting the node wishes to shut down
  + High: Tools: crm: regression tests
  + High: Tools: crm_mon - Fix smtp notifications
  + High: Tools: crm_resource - Repair the ability to query meta attributes
  + Low Build: Bug lf#2105 - Debian package should contain pacemaker doc and crm templates
  + Medium (bnc#507255): Tools: crm: handle empty rsc/op_defaults properly
  + Medium (bnc#507255): Tools: crm: use the right obj_type when creating objects from xml nodes
  + Medium (LF 2107): Tools: crm: revisit exit codes in configure
  + Medium: cib: Do not bother validating updates that only affect the status section
  + Medium: Core: Include supported stacks in version information
  + Medium: crmd: Record in the CIB, the cluster infrastructure being used
  + Medium: cts: Do not combine crm_standby arguments - the wrapper ca not process them
  + Medium: cts: Fix the CIBAusdit class
  + Medium: Extra: Refresh showscores script from Dominik
  + Medium: PE: Build a statically linked version of ptest
  + Medium: PE: Correctly log the actions for resources that are being recovered
  + Medium: PE: Correctly log the occurance of promotion events
  + Medium: PE: Implememt node health based on a patch from Mark Hamzy
  + Medium: Tools: Add examples to help text outputs
  + Medium: Tools: crm: catch syntax errors for configure load
  + Medium: Tools: crm: implement erasing nodes in configure erase
  + Medium: Tools: crm: work with parents only when managing xml objects
  + Medium: Tools: crm_mon - Add option to run custom notification program on resource operations (Patch by Dominik Klein)
  + Medium: Tools: crm_resource - Allow --cleanup to function on complex resources and cluster-wide
  + Medium: Tools: haresource2cib.py - Patch from horms to fix conversion error
  + Medium: Tools: Include stack information in crm_mon output
  + Medium: Tools: Two new options (--stack,--constraints) to crm_resource for querying how a resource is configured

* Wed Apr 08 2009 Andrew Beekhof <abeekhof@suse.de> - 1.0.3-1
- Update source tarball to revision: b133b3f19797 (stable-1.0) tip
- Statistics:
    Changesets:      383
    Diff:            329 files changed, 15471 insertions(+), 15119 deletions(-)
- Changes since Pacemaker-1.0.2
  + Added tag SLE11-HAE-GMC for changeset 9196be9830c2
  + High: ais plugin: Fix quorum calculation (bnc#487003)
  + High: ais: Another memory fix leak in error path
  + High: ais: Bug bnc#482847, bnc#482905 - Force a clean exit of OpenAIS once Pacemaker has finished unloading
  + High: ais: Bug bnc#486858 - Fix update_member() to prevent spamming clients with membership events containing no changes
  + High: ais: Centralize all quorum calculations in the ais plugin and allow expected votes to be configured int he cib
  + High: ais: Correctly handle a return value of zero from openais_dispatch_recv()
  + High: ais: Disable logging to a file
  + High: ais: Fix memory leak in error path
  + High: ais: IPC messages are only in scope until a response is sent
  + High: All signal handlers used with CL_SIGNAL() need to be as minimal as possible
  + High: cib: Bug bnc#482885 - Simplify CIB disk-writes to prevent data loss.  Required a change to the backup filename format
  + High: cib: crmd: Revert part of 9782ab035003.  Complex shutdown routines need G_main_add_SignalHandler to avoid race coditions
  + High: crm: Avoid infinite loop during crm configure edit (bnc#480327)
  + High: crmd: Avoid a race condition by waiting for the attrd update to trigger a transition automatically
  + High: crmd: Bug bnc#480977 - Prevent extra, partial, shutdown when a node restarts too quickly
  + High: crmd: Bug bnc#480977 - Prevent extra, partial, shutdown when a node restarts too quickly (verified)
  + High: crmd: Bug bnc#489063 - Ensure the DC is always unset after we 'loose' an election
  + High: crmd: Bug BSC#479543 - Correctly find the migration source for timed out migrate_from actions
  + High: crmd: Call crm_peer_init() before we start the FSA - prevents a race condition when used with Heartbeat
  + High: crmd: Erasing the status section should not be forced to the local node
  + High: crmd: Fix memory leak in cib notication processing code
  + High: crmd: Fix memory leak in transition graph processing
  + High: crmd: Fix memory leaks found by valgrind
  + High: crmd: More memory leaks fixes found by valgrind
  + High: fencing: stonithd: is_heartbeat_cluster is a no-no if there is no heartbeat support
  + High: PE: Bug bnc#466788 - Exclude nodes that can not run resources
  + High: PE: Bug bnc#466788 - Make colocation based on node attributes work
  + High: PE: Bug BNC#478687 - Do not crash when clone-max is 0
  + High: PE: Bug bnc#488721 - Fix id-ref expansion for clones, the doc-root for clone children is not the cib root
  + High: PE: Bug bnc#490418 - Correctly determine node state for nodes wishing to be terminated
  + High: PE: Bug LF#2087 - Correctly parse the state of anonymous clones that have multiple instances on a given node
  + High: PE: Bug lf#2089 - Meta attributes are not inherited by clone children
  + High: PE: Bug lf#2091 - Correctly restart modified resources that were found active by a probe
  + High: PE: Bug lf#2094 - Fix probe ordering for cloned groups
  + High: PE: Bug LF:2075 - Fix large pingd memory leaks
  + High: PE: Correctly attach orphaned clone children to their parent
  + High: PE: Correctly handle terminate node attributes that are set to the output from time()
  + High: PE: Ensure orphaned clone members are hooked up to the parent when clone-max=0
  + High: PE: Fix memory leak in LogActions
  + High: PE: Fix the determination of whether a group is active
  + High: PE: Look up the correct promotion preference for anonymous masters
  + High: PE: Simplify handling of start failures by changing the default migration-threshold to INFINITY
  + High: PE: The ordered option for clones no longer causes extra start/stop operations
  + High: RA: Bug bnc#490641 - Shut down dlm_controld with -TERM instead of -KILL
  + High: RA: pingd: Set default ping interval to 1 instead of 0 seconds
  + High: Resources: pingd - Correctly tell the ping daemon to shut down
  + High: Tools: Bug bnc#483365 - Ensure the command from cluster_test includes a value for --log-facility
  + High: Tools: cli: fix and improve delete command
  + High: Tools: crm: add and implement templates
  + High: Tools: crm: add support for command aliases and some common commands (i.e. cd,exit)
  + High: Tools: crm: create top configuration nodes if they are missing
  + High: Tools: crm: fix parsing attributes for rules (broken by the previous changeset)
  + High: Tools: crm: new ra set of commands
  + High: Tools: crm: resource agents information management
  + High: Tools: crm: rsc/op_defaults
  + High: Tools: crm: support for no value attribute in nvpairs
  + High: Tools: crm: the new configure monitor command
  + High: Tools: crm: the new configure node command
  + High: Tools: crm_mon - Prevent use-of-NULL when summarizing an orphan
  + High: Tools: hb2openais: create clvmd clone for respawn evmsd in ha.cf
  + High: Tools: hb2openais: fix a serious recursion bug in xml node processing
  + High: Tools: hb2openais: fix ocfs2 processing
  + High: Tools: pingd - prevent double free of getaddrinfo() output in error path
  + High: Tools: The default re-ping interval for pingd should be 1s not 1ms
  + Medium (bnc#479049): Tools: crm: add validation of resource type for the configure primitive command
  + Medium (bnc#479050): Tools: crm: add help for RA parameters in tab completion
  + Medium (bnc#479050): Tools: crm: add tab completion for primitive params/meta/op
  + Medium (bnc#479050): Tools: crm: reimplement cluster properties completion
  + Medium (bnc#486968): Tools: crm: listnodes function requires no parameters (do not mix completion with other stuff)
  + Medium: ais: Remove the ugly hack for dampening AIS membership changes
  + Medium: cib: Fix memory leaks by using mainloop_add_signal
  + Medium: cib: Move more logging to the debug level (was info)
  + Medium: cib: Overhaul the processing of synchronous replies
  + Medium: Core: Add library functions for instructing the cluster to terminate nodes
  + Medium: crmd: Add new expected-quorum-votes option
  + Medium: crmd: Allow up to 5 retires when an attrd update fails
  + Medium: crmd: Automatically detect and use new values for crm_config options
  + Medium: crmd: Bug bnc#490426 - Escalated shutdowns stall when there are pending resource operations
  + Medium: crmd: Clean up and optimize the DC election algorithm
  + Medium: crmd: Fix memory leak in shutdown
  + Medium: crmd: Fix memory leaks spotted by Valgrind
  + Medium: crmd: Ingore join messages from hosts other than our DC
  + Medium: crmd: Limit the scope of resource updates to the status section
  + Medium: crmd: Prevent the crmd from being respawned if its told to shut down when it did not ask to be
  + Medium: crmd: Re-check the election status after membership events
  + Medium: crmd: Send resource updates via the local CIB during elections
  + Medium: PE: Bug bnc#491441 - crm_mon does not display operations returning 'uninstalled' correctly
  + Medium: PE: Bug lf#2101 - For location constraints, role=Slave is equivalent to role=Started
  + Medium: PE: Clean up the API - removed ->children() and renamed ->find_child() to fine_rsc()
  + Medium: PE: Compress the display of healthy anonymous clones
  + Medium: PE: Correctly log the actions for resources that are being recovered
  + Medium: PE: Determin a promotion score for complex resources
  + Medium: PE: Ensure clones always have a value for globally-unique
  + Medium: PE: Prevent orphan clones from being allocated
  + Medium: RA: controld: Return proper exit code for stop op.
  + Medium: Tools: Bug bnc#482558 - Fix logging test in cluster_test
  + Medium: Tools: Bug bnc#482828 - Fix quoting in cluster_test logging setup
  + Medium: Tools: Bug bnc#482840 - Include directory path to CTSlab.py
  + Medium: Tools: crm: add more user input checks
  + Medium: Tools: crm: do not check resource status of we are working with a shadow
  + Medium: Tools: crm: fix id-refs and allow reference to top objects (i.e. primitive)
  + Medium: Tools: crm: ignore comments in the CIB
  + Medium: Tools: crm: multiple column output would not work with small lists
  + Medium: Tools: crm: refuse to delete running resources
  + Medium: Tools: crm: rudimentary if-else for templates
  + Medium: Tools: crm: Start/stop clones via target-role.
  + Medium: Tools: crm_mon - Compress the node status for healthy and offline nodes
  + Medium: Tools: crm_shadow - Return 0/cib_ok when --create-empty succeeds
  + Medium: Tools: crm_shadow - Support -e, the short form of --create-empty
  + Medium: Tools: Make attrd quieter
  + Medium: Tools: pingd - Avoid using various clplumbing functions as they seem to leak
  + Medium: Tools: Reduce pingd logging

* Mon Feb 16 2009 Andrew Beekhof <abeekhof@suse.de> - 1.0.2-1
- Update source tarball to revision: d232d19daeb9 (stable-1.0) tip
- Statistics:
    Changesets:      441
    Diff:            639 files changed, 20871 insertions(+), 21594 deletions(-)
- Changes since Pacemaker-1.0.1
  + High (bnc#450815): Tools: crm cli: do not generate id for the operations tag
  + High: ais: Add support for the new AIS IPC layer
  + High: ais: Always set header.error to the correct default: SA_AIS_OK
  + High: ais: Bug BNC#456243 - Ensure the membership cache always contains an entry for the local node
  + High: ais: Bug BNC:456208 - Prevent deadlocks by not logging in the child process before exec()
  + High: ais: By default, disable supprt for the WIP openais IPC patch
  + High: ais: Detect and handle situations where ais and the crm disagree on the node name
  + High: ais: Ensure crm_peer_seq is updated after a membership update
  + High: ais: Make sure all IPC header fields are set to sane defaults
  + High: ais: Repair and streamline service load now that whitetank startup functions correctly
  + High: build: create and install doc files
  + High: cib: Allow clients without mainloop to connect to the cib
  + High: cib: CID:18 - Fix use-of-NULL in cib_perform_op
  + High: cib: CID:18 - Repair errors introduced in b5a18704477b - Fix use-of-NULL in cib_perform_op
  + High: cib: Ensure diffs contain the correct values of admin_epoch
  + High: cib: Fix four moderately sized memory leaks detected by Valgrind
  + High: Core: CID:10 - Prevent indexing into an array of schemas with a negative value
  + High: Core: CID:13 - Fix memory leak in log_data_element
  + High: Core: CID:15 - Fix memory leak in crm_get_peer
  + High: Core: CID:6 - Fix use-of-NULL in copy_ha_msg_input
  + High: Core: Fix crash in the membership code preventing node shutdown
  + High: Core: Fix more memory leaks foudn by valgrind
  + High: Core: Prevent unterminated strings after decompression
  + High: crmd: Bug BNC:467995 - Delay marking STONITH operations complete until STONITH tells us so
  + High: crmd: Bug LF:1962 - Do not NACK peers because they are not (yet) in our membership.  Just ignore them.
  + High: crmd: Bug LF:2010 - Ensure fencing cib updates create the node_state entry if needed to preent re-fencing during cluster startup
  + High: crmd: Correctly handle reconnections to attrd
  + High: crmd: Ensure updates for lost migrate operations indicate which node it tried to migrating to
  + High: crmd: If there are no nodes to finalize, start an election.
  + High: crmd: If there are no nodes to welcome, start an election.
  + High: crmd: Prevent node attribute loss by detecting attrd disconnections immediately
  + High: crmd: Prevent node re-probe loops by ensuring manditory actions always complete
  + High: PE: Bug 2005 - Fix startup ordering of cloned stonith groups
  + High: PE: Bug 2006 - Correctly reprobe cloned groups
  + High: PE: Bug BNC:465484 - Fix the no-quorum-policy=suicide option
  + High: PE: Bug LF:1996 - Correctly process disabled monitor operations
  + High: PE: CID:19 - Fix use-of-NULL in determine_online_status
  + High: PE: Clones now default to globally-unique=false
  + High: PE: Correctly calculate the number of available nodes for the clone to use
  + High: PE: Only shoot online nodes with no-quorum-policy=suicide
  + High: PE: Prevent on-fail settings being ignored after a resource is successfully stopped
  + High: PE: Prevent use-of-NULL for failed migrate actions in process_rsc_state()
  + High: PE: Remove an optimization for the terminate node attribute that caused the cluster to block indefinitly
  + High: PE: Repar the ability to colocate based on node attributes other than uname
  + High: PE: Start the correct monitor operation for unmanaged masters
  + High: stonith: CID:3 - Fix another case of exceptionally poor error handling by the original stonith developers
  + High: stonith: CID:5 - Checking for NULL and then dereferencing it anyway is an interesting approach to error handling
  + High: stonithd: Sending IPC to the cluster is a privileged operation
  + High: stonithd: wrong checks for shmid (0 is a valid id)
  + High: Tools: attrd - Correctly determine when an attribute has stopped changing and should be committed to the CIB
  + High: Tools: Bug 2003 - pingd does not correctly detect failures when the interface is down
  + High: Tools: Bug 2003 - pingd does not correctly handle node-down events on multi-NIC systems
  + High: Tools: Bug 2021 - pingd does not detect sequence wrapping correctly, incorrectly reports nodes offline
  + High: Tools: Bug BNC:468066 - Do not use the result of uname() when its no longer in scope
  + High: Tools: Bug BNC:473265 - crm_resource -L dumps core
  + High: Tools: Bug LF:2001 - Transient node attributes should be set via attrd
  + High: Tools: Bug LF:2036 - crm_resource cannot set/get parameters for cloned resources
  + High: Tools: Bug LF:2046 - Node attribute updates are lost because attrd can take too long to start
  + High: Tools: Cause the correct clone instance to be failed with crm_resource -F
  + High: Tools: cluster_test - Allow the user to select a stack and fix CTS invocation
  + High: Tools: crm cli: allow rename only if the resource is stopped
  + High: Tools: crm cli: catch system errors on file operations
  + High: Tools: crm cli: completion for ids in configure
  + High: Tools: crm cli: drop '-rsc' from attributes for order constraint
  + High: Tools: crm cli: exit with an appropriate exit code
  + High: Tools: crm cli: fix wrong order of action and resource in order constraint
  + High: Tools: crm cli: fox wrong exit code
  + High: Tools: crm cli: improve handling of cib attributes
  + High: Tools: crm cli: new command: configure rename
  + High: Tools: crm cli: new command: configure upgrade
  + High: Tools: crm cli: new command: node delete
  + High: Tools: crm cli: prevent key errors on missing cib attributes
  + High: Tools: crm cli: print long help for help topics
  + High: Tools: crm cli: return on syntax error when parsing score
  + High: Tools: crm cli: rsc_location can be without nvpairs
  + High: Tools: crm cli: short node preference location constraint
  + High: Tools: crm cli: sometimes, on errors, level would change on single shot use
  + High: Tools: crm cli: syntax: drop a bunch of commas (remains of help tables conversion)
  + High: Tools: crm cli: verify user input for sanity
  + High: Tools: crm: find expressions within rules (do not always skip xml nodes due to used id)
  + High: Tools: crm_master should not define a set id now that attrd is used.  Defining one can break lookups
  + High: Tools: crm_mon Use the OID assigned to the project by IANA for SNMP traps
  + Medium (bnc#445622): Tools: crm cli: improve the node show command and drop node status
  + Medium (LF 2009): stonithd: improve timeouts for remote fencing
  + Medium: ais: Allow dead peers to be removed from membership calculations
  + Medium: ais: Pass node deletion events on to clients
  + Medium: ais: Sanitize ipc usage
  + Medium: ais: Supply the node uname in addtion to the id
  + Medium: Build: Clean up configure to ensure NON_FATAL_CFLAGS is consistent with CFLAGS (ie. includes -g)
  + Medium: Build: Install cluster_test
  + Medium: Build: Use more restrictive CFLAGS and fix the resulting errors
  + Medium: cib: CID:20 - Fix potential use-after-free in cib_native_signon
  + Medium: Core: Bug BNC:474727 - Set a maximum time to wait for IPC messages
  + Medium: Core: CID:12 - Fix memory leak in decode_transition_magic error path
  + Medium: Core: CID:14 - Fix memory leak in calculate_xml_digest error path
  + Medium: Core: CID:16 - Fix memory leak in date_to_string error path
  + Medium: Core: Try to track down the cause of XML parsing errors
  + Medium: crmd: Bug BNC:472473 - Do not wait excessive amounts of time for lost actions
  + Medium: crmd: Bug BNC:472473 - Reduce the transition timeout to action_timeout+network_delay
  + Medium: crmd: Do not fast-track the processing of LRM refreshes when there are pending actions.
  + Medium: crmd: do_dc_join_filter_offer - Check the 'join' message is for the current instance before deciding to NACK peers
  + Medium: crmd: Find option values without having to do a config upgrade
  + Medium: crmd: Implement shutdown using a transient node attribute
  + Medium: crmd: Update the crmd options to use dashes instead of underscores
  + Medium: cts: Add 'cluster reattach' to the suite of automated regression tests
  + Medium: cts: cluster_test - Make some usability enhancements
  + Medium: CTS: cluster_test - suggest a valid port number
  + Medium: CTS: Fix python import order
  + Medium: cts: Implement an automated SplitBrain test
  + Medium: CTS: Remove references to deleted classes
  + Medium: Extra: Resources - Use HA_VARRUN instead of HA_RSCTMP for state files as Heartbeat removes HA_RSCTMP at startup
  + Medium: HB: Bug 1933 - Fake crmd_client_status_callback() calls because HB does not provide them for already running processes
  + Medium: PE: CID:17 - Fix memory leak in find_actions_by_task error path
  + Medium: PE: CID:7,8 - Prevent hypothetical use-of-NULL in LogActions
  + Medium: PE: Defer logging the actions performed on a resource until we have processed ordering constraints
  + Medium: PE: Remove the symmetrical attribute of colocation constraints
  + Medium: Resources: pingd - fix the meta defaults
  + Medium: Resources: Stateful - Add missing meta defaults
  + Medium: stonithd: exit if we the pid file cannot be locked
  + Medium: Tools: Allow attrd clients to specify the ID the attribute should be created with
  + Medium: Tools: attrd - Allow attribute updates to be performed from a hosts peer
  + Medium: Tools: Bug LF:1994 - Clean up crm_verify return codes
  + Medium: Tools: Change the pingd defaults to ping hosts once every second (instead of 5 times every 10 seconds)
  + Medium: Tools: cibmin - Detect resource operations with a view to providing email/snmp/cim notification
  + Medium: Tools: crm cli: add back symmetrical for order constraints
  + Medium: Tools: crm cli: generate role in location when converting from xml
  + Medium: Tools: crm cli: handle shlex exceptions
  + Medium: Tools: crm cli: keep order of help topics
  + Medium: Tools: crm cli: refine completion for ids in configure
  + Medium: Tools: crm cli: replace inf with INFINITY
  + Medium: Tools: crm cli: streamline cib load and parsing
  + Medium: Tools: crm cli: supply provider only for ocf class primitives
  + Medium: Tools: crm_mon - Add support for sending mail notifications of resource events
  + Medium: Tools: crm_mon - Include the DC version in status summary
  + Medium: Tools: crm_mon - Sanitize startup and option processing
  + Medium: Tools: crm_mon - switch to event-driven updates and add support for sending snmp traps
  + Medium: Tools: crm_shadow - Replace the --locate option with the saner --edit
  + Medium: Tools: hb2openais: do not remove Evmsd resources, but replace them with clvmd
  + Medium: Tools: hb2openais: replace crmadmin with crm_mon
  + Medium: Tools: hb2openais: replace the lsb class with ocf for o2cb
  + Medium: Tools: hb2openais: reuse code
  + Medium: Tools: LF:2029 - Display an error if crm_resource is used to reset the operation history of non-primitive resources
  + Medium: Tools: Make pingd resilient to attrd failures
  + Medium: Tools: pingd - fix the command line switches
  + Medium: Tools: Rename ccm_tool to crm_node

* Tue Nov 18 2008 Andrew Beekhof <abeekhof@suse.de> - 1.0.1-1
- Update source tarball to revision: 6fc5ce8302ab (stable-1.0) tip
- Statistics:
    Changesets:      170
    Diff:            816 files changed, 7633 insertions(+), 6286 deletions(-)
- Changes since Pacemaker-1.0.1
  + High: ais: Allow the crmd to get callbacks whenever a node state changes
  + High: ais: Create an option for starting the mgmtd daemon automatically
  + High: ais: Ensure HA_RSCTMP exists for use by resource agents
  + High: ais: Hook up the openais.conf config logging options
  + High: ais: Zero out the PID of disconnecting clients
  + High: cib: Ensure global updates cause a disk write when appropriate
  + High: Core: Add an extra snaity check to getXpathResults() to prevent segfaults
  + High: Core: Do not redefine __FUNCTION__ unnecessarily
  + High: Core: Repair the ability to have comments in the configuration
  + High: crmd: Bug:1975 - crmd should wait indefinitely for stonith operations to complete
  + High: crmd: Ensure PE processing does not occur for all error cases in do_pe_invoke_callback
  + High: crmd: Requests to the CIB should cause any prior PE calculations to be ignored
  + High: heartbeat: Wait for membership 'up' events before removing stale node status data
  + High: PE: Bug LF:1988 - Ensure recurring operations always have the correct target-rc set
  + High: PE: Bug LF:1988 - For unmanaged resources we need to skip the usual can_run_resources() checks
  + High: PE: Ensure the terminate node attribute is handled correctly
  + High: PE: Fix optional colocation
  + High: PE: Improve up the detection of 'new' nodes joining the cluster
  + High: PE: Prevent assert failures in master_color() by ensuring unmanaged masters are always reallocated to their current location
  + High: Tools: crm cli: parser: return False on syntax error and None for comments
  + High: Tools: crm cli: unify template and edit commands
  + High: Tools: crm_shadow - Show more line number information after validation failures
  + High: Tools: hb2openais: add option to upgrade the CIB to v3.0
  + High: Tools: hb2openais: add U option to getopts and update usage
  + High: Tools: hb2openais: backup improved and multiple fixes
  + High: Tools: hb2openais: fix class/provider reversal
  + High: Tools: hb2openais: fix testing
  + High: Tools: hb2openais: move the CIB update to the end
  + High: Tools: hb2openais: update logging and set logfile appropriately
  + High: Tools: LF:1969 - Attrd never sets any properties in the cib
  + High: Tools: Make attrd functional on OpenAIS
  + Medium: ais: Hook up the options for specifying the expected number of nodes and total quorum votes
  + Medium: ais: Look for pacemaker options inside the service block with 'name: pacemaker' instead of creating an addtional configuration block
  + Medium: ais: Provide better feedback when nodes change nodeids (in openais.conf)
  + Medium: cib: Always store cib contents on disk with num_updates=0
  + Medium: cib: Ensure remote access ports are cleaned up on shutdown
  + Medium: crmd: Detect deleted resource operations automatically
  + Medium: crmd: Erase a nodes resource operations and transient attributes after a successful STONITH
  + Medium: crmd: Find a more appropriate place to update quorum and refresh attrd attributes
  + Medium: crmd: Fix the handling of unexpected PE exits to ensure the current CIB is stored
  + Medium: crmd: Fix the recording of pending operations in the CIB
  + Medium: crmd: Initiate an attrd refresh _after_ the status section has been fully repopulated
  + Medium: crmd: Only the DC should update quorum in an openais cluster
  + Medium: Ensure meta attributes are used consistantly
  + Medium: PE: Allow group and clone level resource attributes
  + Medium: PE: Bug N:437719 - Ensure scores from colocated resources count when allocating groups
  + Medium: PE: Prevent lsb scripts from being used in globally unique clones
  + Medium: PE: Make a best-effort guess at a migration threshold for people with 0.6 configs
  + Medium: Resources: controld - ensure we are part of a clone with globally_unique=false
  + Medium: Tools: attrd - Automatically refresh all attributes after a CIB replace operation
  + Medium: Tools: Bug LF:1985 - crm_mon - Correctly process failed cib queries to allow reconnection after cluster restarts
  + Medium: Tools: Bug LF:1987 - crm_verify incorrectly warns of configuration upgrades for the most recent version
  + Medium: Tools: crm (bnc#441028): check for key error in attributes management
  + Medium: Tools: crm_mon - display the meaning of the operation rc code instead of the status
  + Medium: Tools: crm_mon - Fix the display of timing data
  + Medium: Tools: crm_verify - check that we are being asked to validate a complete config
  + Medium: xml: Relax the restriction on the contents of rsc_locaiton.node

* Thu Oct 16 2008 Andrew Beekhof <abeekhof@suse.de> - 1.0.0-1
- Update source tarball to revision: 388654dfef8f tip
- Statistics:
    Changesets:      261
    Diff:            3021 files changed, 244985 insertions(+), 111596 deletions(-)
- Changes since f805e1b30103
  + High: add the crm cli program
  + High: ais: Move the service id definition to a common location and make sure it is always used
  + High: build: rename hb2openais.sh to .in and replace paths with vars
  + High: cib: Implement --create for crm_shadow
  + High: cib: Remove dead files
  + High: Core: Allow the expected number of quorum votes to be configrable
  + High: Core: cl_malloc and friends were removed from Heartbeat
  + High: Core: Only call xmlCleanupParser() if we parsed anything.  Doing so unconditionally seems to cause a segfault
  + High: hb2openais.sh: improve pingd handling; several bugs fixed
  + High: hb2openais: fix clone creation; replace EVMS strings
  + High: new hb2openais.sh conversion script
  + High: PE: Bug LF:1950 - Ensure the current values for all notification variables are always set (even if empty)
  + High: PE: Bug LF:1955 - Ensure unmanaged masters are unconditionally repromoted to ensure they are monitored correctly.
  + High: PE: Bug LF:1955 - Fix another case of filtering causing unmanaged master failures
  + High: PE: Bug LF:1955 - Umanaged mode prevents master resources from being allocated correctly
  + High: PE: Bug N:420538 - Anit-colocation caused a positive node preference
  + High: PE: Correctly handle unmanaged resources to prevent them from being started elsewhere
  + High: PE: crm_resource - Fix the --migrate command
  + High: PE: MAke stonith-enabled default to true and warn if no STONITH resources are found
  + High: PE: Make sure orphaned clone children are created correctly
  + High: PE: Monitors for unmanaged resources do not need to wait for start/promote/demote actions to complete
  + High: stonithd (LF 1951): fix remote stonith operations
  + High: stonithd: fix handling of timeouts
  + High: stonithd: fix logic for stonith resource priorities
  + High: stonithd: implement the fence-timeout instance attribute
  + High: stonithd: initialize value before reading fence-timeout
  + High: stonithd: set timeouts for fencing ops to the timeout of the start op
  + High: stonithd: stonith rsc priorities (new feature)
  + High: Tools: Add hb2openais - a tool for upgrading a Heartbeat cluster to use OpenAIS instead
  + High: Tools: crm_verify - clean up the upgrade logic to prevent crash on invalid configurations
  + High: Tools: Make pingd functional on Linux
  + High: Update version numbers for 1.0 candidates
  + Medium: ais: Add support for a synchronous call to retrieve the nodes nodeid
  + Medium: ais: Use the agreed service number
  + Medium: Build: Reliably detect heartbeat libraries during configure
  + Medium: Build: Supply prototypes for libreplace functions when needed
  + Medium: Build: Teach configure how to find corosync
  + Medium: Core: Provide better feedback if Pacemaker is started by a stack it does not support
  + Medium: crmd: Avoid calling GHashTable functions with NULL
  + Medium: crmd: Delay raising I_ERROR when the PE exits until we have had a chance to save the current CIB
  + Medium: crmd: Hook up the stonith-timeout option to stonithd
  + Medium: crmd: Prevent potential use-of-NULL in global_timer_callback
  + Medium: crmd: Rationalize the logging of graph aborts
  + Medium: PE: Add a stonith_timeout option and remove new options that are better set in rsc_defaults
  + Medium: PE: Allow external entities to ask for a node to be shot by creating a terminate=true transient node attribute
  + Medium: PE: Bug LF:1950 - Notifications do not contain all documented resource state fields
  + Medium: PE: Bug N:417585 - Do not restart group children whos individual score drops below zero
  + Medium: PE: Detect clients that disconnect before receiving their reply
  + Medium: PE: Implement a true maintenance mode
  + Medium: PE: Implement on-fail=standby for NTT.  Derived from a patch by Satomi TANIGUCHI
  + Medium: PE: Print the correct message when stonith is disabled
  + Medium: PE: ptest - check the input is valid before proceeding
  + Medium: PE: Revert group stickiness to the 'old way'
  + Medium: PE: Use the correct attribute for action 'requires' (was prereq)
  + Medium: stonithd: Fix compilation without full heartbeat install
  + Medium: stonithd: exit with better code on empty host list
  + Medium: tools: Add a new regression test for CLI tools
  + Medium: tools: crm_resource - return with non-zero when a resource migration command is invalid
  + Medium: tools: crm_shadow - Allow the admin to start with an empty CIB (and no cluster connection)
  + Medium: xml: pacemaker-0.7 is now an alias for the 1.0 schema

* Mon Sep 22 2008 Andrew Beekhof <abeekhof@suse.de> - 0.7.3-1
- Update source tarball to revision: 33e677ab7764+ tip
- Statistics:
    Changesets:      133
    Diff:            89 files changed, 7492 insertions(+), 1125 deletions(-)
- Changes since f805e1b30103
  + High: Tools: add the crm cli program
  + High: Core: cl_malloc and friends were removed from Heartbeat
  + High: Core: Only call xmlCleanupParser() if we parsed anything.  Doing so unconditionally seems to cause a segfault
  + High: new hb2openais.sh conversion script
  + High: PE: Bug LF:1950 - Ensure the current values for all notification variables are always set (even if empty)
  + High: PE: Bug LF:1955 - Ensure unmanaged masters are unconditionally repromoted to ensure they are monitored correctly.
  + High: PE: Bug LF:1955 - Fix another case of filtering causing unmanaged master failures
  + High: PE: Bug LF:1955 - Umanaged mode prevents master resources from being allocated correctly
  + High: PE: Bug N:420538 - Anit-colocation caused a positive node preference
  + High: PE: Correctly handle unmanaged resources to prevent them from being started elsewhere
  + High: PE: crm_resource - Fix the --migrate command
  + High: PE: MAke stonith-enabled default to true and warn if no STONITH resources are found
  + High: PE: Make sure orphaned clone children are created correctly
  + High: PE: Monitors for unmanaged resources do not need to wait for start/promote/demote actions to complete
  + High: stonithd (LF 1951): fix remote stonith operations
  + High: Tools: crm_verify - clean up the upgrade logic to prevent crash on invalid configurations
  + Medium: ais: Add support for a synchronous call to retrieve the nodes nodeid
  + Medium: ais: Use the agreed service number
  + Medium: PE: Allow external entities to ask for a node to be shot by creating a terminate=true transient node attribute
  + Medium: PE: Bug LF:1950 - Notifications do not contain all documented resource state fields
  + Medium: PE: Bug N:417585 - Do not restart group children whos individual score drops below zero
  + Medium: PE: Implement a true maintenance mode
  + Medium: PE: Print the correct message when stonith is disabled
  + Medium: stonithd: exit with better code on empty host list
  + Medium: xml: pacemaker-0.7 is now an alias for the 1.0 schema

* Wed Aug 20 2008 Andrew Beekhof <abeekhof@suse.de> - 0.7.1-1
- Update source tarball to revision: f805e1b30103+ tip
- Statistics:
    Changesets:      184
    Diff:            513 files changed, 43408 insertions(+), 43783 deletions(-)
- Changes since 0.7.0-19
  + Fix compilation when GNUTLS isnt found
  + High: admin: Fix use-after-free in crm_mon
  + High: Build: Remove testing code that prevented heartbeat-only builds
  + High: cib: Use single quotes so that the xpath queries for nvpairs will succeed
  + High: crmd: Always connect to stonithd when the TE starts and ensure we notice if it dies
  + High: crmd: Correctly handle a dead PE process
  + High: crmd: Make sure async-failures cause the failcount to be incrimented
  + High: PE: Bug LF:1941 - Handle failed clone instance probes when clone-max < #nodes
  + High: PE: Parse resource ordering sets correctly
  + High: PE: Prevent use-of-NULL - order->rsc_rh will not always be non-NULL
  + High: PE: Unpack colocation sets correctly
  + High: Tools: crm_mon - Prevent use-of-NULL for orphaned resources
  + Medium: ais: Add support for a synchronous call to retrieve the nodes nodeid
  + Medium: ais: Allow transient clients to receive membership updates
  + Medium: ais: Avoid double-free in error path
  + Medium: ais: Include in the mebership nodes for which we have not determined their hostname
  + Medium: ais: Spawn the PE from the ais plugin instead of the crmd
  + Medium: cib: By default, new configurations use the latest schema
  + Medium: cib: Clean up the CIB if it was already disconnected
  + Medium: cib: Only incriment num_updates if something actually changed
  + Medium: cib: Prevent use-after-free in client after abnormal termination of the CIB
  + Medium: Core: Fix memory leak in xpath searches
  + Medium: Core: Get more details regarding parser errors
  + Medium: Core: Repair expand_plus_plus - do not call char2score on unexpanded values
  + Medium: Core: Switch to the libxml2 parser - its significantly faster
  + Medium: Core: Use a libxml2 library function for xml -> text conversion
  + Medium: crmd: Asynchronous failure actions have no parameters
  + Medium: crmd: Avoid calling glib functions with NULL
  + Medium: crmd: Do not allow an election to promote a node from S_STARTING
  + Medium: crmd: Do not vote if we have not completed the local startup
  + Medium: crmd: Fix te_update_diff() now that get_object_root() functions differently
  + Medium: crmd: Fix the lrmd xpath expressions to not contain quotes
  + Medium: crmd: If we get a join offer during an election, better restart the election
  + Medium: crmd: No further processing is needed when using the LRMs API call for failing resources
  + Medium: crmd: Only update have-quorum if the value changed
  + Medium: crmd: Repair the input validation logic in do_te_invoke
  + Medium: cts: CIBs can no longer contain comments
  + Medium: cts: Enable a bunch of tests that were incorrectly disabled
  + Medium: cts: The libxml2 parser wont allow v1 resources to use integers as parameter names
  + Medium: Do not use the cluster UID and GID directly.  Look them up based on the configured value of HA_CCMUSER
  + Medium: Fix compilation when heartbeat is not supported
  + Medium: PE: Allow groups to be involved in optional ordering constraints
  + Medium: PE: Allow sets of operations to be reused by multiple resources
  + Medium: PE: Bug LF:1941 - Mark extra clone instances as orphans and do not show inactive ones
  + Medium: PE: Determin the correct migration-threshold during resource expansion
  + Medium: PE: Implement no-quorum-policy=suicide (FATE #303619)
  + Medium: pengine: Clean up resources after stopping old copies of the PE
  + Medium: pengine: Teach the PE how to stop old copies of itself
  + Medium: Tools: Backport hb_report updates
  + Medium: Tools: cib_shadow - On create, spawn a new shell with CIB_shadow and PS1 set accordingly
  + Medium: Tools: Rename cib_shadow to crm_shadow

* Fri Jul 18 2008 Andrew Beekhof <abeekhof@suse.de> - 0.7.0-19
- Update source tarball to revision: 007c3a1c50f5 (unstable) tip
- Statistics:
    Changesets:      108
    Diff:            216 files changed, 4632 insertions(+), 4173 deletions(-)
- Changes added since unstable-0.7
  + High: admin: Fix use-after-free in crm_mon
  + High: ais: Change the tag for the ais plugin to "pacemaker" (used in openais.conf)
  + High: ais: Log terminated processes as an error
  + High: cib: Performance - Reorganize things to avoid calculating the XML diff twice
  + High: PE: Bug LF:1941 - Handle failed clone instance probes when clone-max < #nodes
  + High: PE: Fix memory leak in action2xml
  + High: PE: Make OCF_ERR_ARGS a node-level error rather than a cluster-level one
  + High: PE: Properly handle clones that are not installed on all nodes
  + Medium: admin: cibadmin - Show any validation errors if the upgrade failed
  + Medium: admin: cib_shadow - Implement --locate to display the underlying filename
  + Medium: admin: cib_shadow - Implement a --diff option
  + Medium: admin: cib_shadow - Implement a --switch option
  + Medium: admin: crm_resource - create more compact constraints that do not use lifetime (which is deprecated)
  + Medium: ais: Approximate born_on for OpenAIS based clusters
  + Medium: cib: Remove do_id_check, it is a poor substitute for ID validation by a schema
  + Medium: cib: Skip construction of pre-notify messages if no-one wants one
  + Medium: Core: Attempt to streamline some key functions to increase performance
  + Medium: Core: Clean up XML parser after validation
  + Medium: crmd: Detect and optimize the CRMs behavior when processing diffs of an LRM refresh
  + Medium: Fix memory leaks when resetting the name of an XML object
  + Medium: PE: Prefer the current location if it is one of a group of nodes with the same (highest) score

* Wed Jun 25 2008 Andrew Beekhof <abeekhof@suse.de> - 0.7.0-1
- Update source tarball to revision: bde0c7db74fb tip
- Statistics:
    Changesets:      439
    Diff:            676 files changed, 41310 insertions(+), 52071 deletions(-)
- Changes added since stable-0.6
  + High: A new tool for setting up and invoking CTS
  + High: Admin: All tools now use --node (-N) for specifying node unames
  + High: Admin: All tools now use --xml-file (-x) and --xml-text (-X) for specifying where to find XML blobs
  + High: cib: Cleanup the API - remove redundant input fields
  + High: cib: Implement CIB_shadow - a facility for making and testing changes before uploading them to the cluster
  + High: cib: Make registering per-op callbacks an API call and renamed (for clarity) the API call for requesting notifications
  + High: Core: Add a facility for automatically upgrading old configurations
  + High: Core: Adopt libxml2 as the XML processing library - all external clients need to be recompiled
  + High: Core: Allow sending TLS messages larger than the MTU
  + High: Core: Fix parsing of time-only ISO dates
  + High: Core: Smarter handling of XML values containing quotes
  + High: Core: XML memory corruption - catch, and handle, cases where we are overwriting an attribute value with itself
  + High: Core: The xml ID type does not allow UUIDs that start with a number
  + High: Core: Implement XPath based versions of query/delete/replace/modify
  + High: Core: Remove some HA2.0.(3,4) compatability code
  + High: crmd: Overhaul the detection of nodes that are starting vs. failed
  + High: PE: Bug LF:1459 - Allow failures to expire
  + High: PE: Have the PE do non-persistent configuration upgrades before performing calculations
  + High: PE: Replace failure-stickiness with a simple 'migration-threshold'
  + High: TE: Simplify the design by folding the tengine process into the crmd
  + Medium: Admin: Bug LF:1438 - Allow the list of all/active resource operations to be queried by crm_resource
  + Medium: Admin: Bug LF:1708 - crm_resource should print a warning if an attribute is already set as a meta attribute
  + Medium: Admin: Bug LF:1883 - crm_mon should display fail-count and operation history
  + Medium: Admin: Bug LF:1883 - crm_mon should display operation timing data
  + Medium: Admin: Bug N:371785 - crm_resource -C does not also clean up fail-count attributes
  + Medium: Admin: crm_mon - include timing data for failed actions
  + Medium: ais: Read options from the environment since objdb is not completely usable yet
  + Medium: cib: Add sections for op_defaults and rsc_defaults
  + Medium: cib: Better matching notification callbacks (for detecting duplicates and removal)
  + Medium: cib: Bug LF:1348 - Allow rules and attribute sets to be referenced for use in other objects
  + Medium: cib: BUG LF:1918 - By default, all cib calls now timeout after 30s
  + Medium: cib: Detect updates that decrease the version tuple
  + Medium: cib: Implement a client-side operation timeout - Requires LHA update
  + Medium: cib: Implement callbacks and async notifications for remote connections
  + Medium: cib: Make cib->cmds->update() an alias for modify at the API level (also implemented in cibadmin)
  + Medium: cib: Mark the CIB as disconnected if the IPC connection is terminated
  + Medium: cib: New call option 'cib_can_create' which can be passed to modify actions - allows the object to be created if it does not exist yet
  + Medium: cib: Reimplement get|set|delete attributes using XPath
  + Medium: cib: Remove some useless parts of the API
  + Medium: cib: Remove the 'attributes' scaffolding from the new format
  + Medium: cib: Implement the ability for clients to connect to remote servers
  + Medium: Core: Add support for validating xml against RelaxNG schemas
  + Medium: Core: Allow more than one item to be modified/deleted in XPath based operations
  + Medium: Core: Fix the sort_pairs function for creating sorted xml objects
  + Medium: Core: iso8601 - Implement subtract_duration and fix subtract_time
  + Medium: Core: Reduce the amount of xml copying occuring
  + Medium: Core: Support value='value+=N' XML updates (in addtion to value='value++')
  + Medium: crmd: Add support for lrm_ops->fail_rsc if its available
  + Medium: crmd: HB - watch link status for node leaving events
  + Medium: crmd: Bug LF:1924 - Improved handling of lrmd disconnects and shutdowns
  + Medium: crmd: Do not wait for actions with a start_delay over 5 minutes. Confirm them immediately
  + Medium: PE: Bug LF:1328 - Do not fencing nodes in clusters without managed resources
  + Medium: PE: Bug LF:1461 - Give transient node attributes (in <status/>) preference over persistent ones (in <nodes/>)
  + Medium: PE: Bug LF:1884, Bug LF:1885 - Implement N:M ordering and colocation constraints
  + Medium: PE: Bug LF:1886 - Create a resource and operation 'defaults' config section
  + Medium: PE: Bug LF:1892 - Allow recurring actions to be triggered at known times
  + Medium: PE: Bug LF:1926 - Probes should complete before stop actions are invoked
  + Medium: PE: Fix the standby when its set as a transient attribute
  + Medium: PE: Implement a global 'stop-all-resources' option
  + Medium: PE: Implement cibpipe, a tool for performing/simulating config changes "offline"
  + Medium: PE: We do not allow colocation with specific clone instances
  + Medium: Tools: pingd - Implement a stack-independant version of pingd
  + Medium: xml: Ship an xslt for upgrading from 0.6 to 0.7

* Thu Jun 19 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.5-1
- Update source tarball to revision: b9fe723d1ac5 tip
- Statistics:
    Changesets:      48
    Diff:            37 files changed, 1204 insertions(+), 234 deletions(-)
- Changes since Pacemaker-0.6.4
  + High: Admin: Repair the ability to delete failcounts
  + High: ais: Audit IPC handling between the AIS plugin and CRM processes
  + High: ais: Have the plugin create needed /var/lib directories
  + High: ais: Make sure the sync and async connections are assigned correctly (not swapped)
  + High: cib: Correctly detect configuration changes - num_updates does not count
  + High: PE: Apply stickiness values to the whole group, not the individual resources
  + High: PE: Bug N:385265 - Ensure groups are migrated instead of remaining partially active on the current node
  + High: PE: Bug N:396293 - Enforce manditory group restarts due to ordering constraints
  + High: PE: Correctly recover master instances found active on more than one node
  + High: PE: Fix memory leaks reported by Valgrind
  + Medium: Admin: crm_mon - Misc improvements from Satomi Taniguchi
  + Medium: Bug LF:1900 - Resource stickiness should not allow placement in asynchronous clusters
  + Medium: crmd: Ensure joins are completed promptly when a node taking part dies
  + Medium: PE: Avoid clone instance shuffling in more cases
  + Medium: PE: Bug LF:1906 - Remove an optimization in native_merge_weights() causing group scores to behave eratically
  + Medium: PE: Make use of target_rc data to correctly process resource operations
  + Medium: PE: Prevent a possible use of NULL in sort_clone_instance()
  + Medium: TE: Include target rc in the transition key - used to correctly determin operation failure

* Thu May 22 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.4-1
- Update source tarball to revision: 226d8e356924 tip
- Statistics:
    Changesets:       55
    Diff:             199 files changed, 7103 insertions(+), 12378 deletions(-)
- Changes since Pacemaker-0.6.3
  + High: crmd: Bug LF:1881 LF:1882 - Overhaul the logic for operation cancelation and deletion
  + High: crmd: Bug LF:1894 - Make sure cancelled recurring operations are cleaned out from the CIB
  + High: PE: Bug N:387749 - Colocation with clones causes unnecessary clone instance shuffling
  + High: PE: Ensure 'master' monitor actions are cancelled _before_ we demote the resource
  + High: PE: Fix assert failure leading to core dump - make sure variable is properly initialized
  + High: PE: Make sure 'slave' monitoring happens after the resource has been demoted
  + High: PE: Prevent failure stickiness underflows (where too many failures become a _positive_ preference)
  + Medium: Admin: crm_mon - Only complain if the output file could not be opened
  + Medium: Common: filter_action_parameters - enable legacy handling only for older versions
  + Medium: PE: Bug N:385265 - The failure stickiness of group children is ignored until it reaches -INFINITY
  + Medium: PE: Implement master and clone colocation by exlcuding nodes rather than setting ones score to INFINITY (similar to cs: 756afc42dc51)
  + Medium: TE: Bug LF:1875 - Correctly find actions to cancel when their node leaves the cluster

* Wed Apr 23 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.3-1
- Update source tarball to revision: fd8904c9bc67 tip
- Statistics:
    Changesets:      117
    Diff:            354 files changed, 19094 insertions(+), 11338 deletions(-)
- Changes since Pacemaker-0.6.2
  + High: Admin: Bug LF:1848 - crm_resource - Pass set name and id to delete_resource_attr() in the correct order
  + High: Build: SNMP has been moved to the management/pygui project
  + High: crmd: Bug LF1837 - Unmanaged resources prevent crmd from shutting down
  + High: crmd: Prevent use-after-free in lrm interface code (Patch based on work by Keisuke MORI)
  + High: PE: Allow the cluster to make progress by not retrying failed demote actions
  + High: PE: Anti-colocation with slave should not prevent master colocation
  + High: PE: Bug LF 1768 - Wait more often for STONITH ops to complete before starting resources
  + High: PE: Bug LF1836 - Allow is-managed-default=false to be overridden by individual resources
  + High: PE: Bug LF185 - Prevent pointless master/slave instance shuffling by ignoring the master-pref of stopped instances
  + High: PE: Bug N-191176 - Implement interleaved ordering for clone-to-clone scenarios
  + High: PE: Bug N-347004 - Ensure clone notifications are always sent when an instance is stopped/started
  + High: PE: Bug N-347004 - Include notification ordering is correct for interleaved clones
  + High: PE: Bug PM-11 - Directly link probe_complete to starting clone instances
  + High: PE: Bug PM1 - Fix setting failcounts when applied to complex resources
  + High: PE: Bug PM12, LF1648 - Extensive revision of group ordering
  + High: PE: Bug PM7 - Ensure masters are always demoted before they are stopped
  + High: PE: Create probes after allocation to allow smarter handling of anonymous clones
  + High: PE: Do not prioritize clone instances that must be moved
  + High: PE: Fix error in previous commit that allowed more than the required number of masters to be promoted
  + High: PE: Group start ordering fixes
  + High: PE: Implement promote/demote ordering for cloned groups
  + High: TE: Repair failcount updates
  + High: TE: Use the correct offset when updating failcount
  + Medium: Admin: Add a summary output that can be easily parsed by CTS for audit purposes
  + Medium: Build: Make configure fail if bz2 or libxml2 are not present
  + Medium: Build: Re-instate a better default for LCRSODIR
  + Medium: CIB: Bug LF-1861 - Filter irrelvant error status from synchronous CIB clients
  + Medium: Core: Bug 1849 - Invalid conversion of ordinal leap year to gregorian date
  + Medium: Core: Drop compataibility code for 2.0.4 and 2.0.5 clusters
  + Medium: crmd: Bug LF-1860 - Automatically cancel recurring ops before demote and promote operations (not only stops)
  + Medium: crmd: Save the current CIB contents if we detect the PE crashed
  + Medium: PE: Bug LF:1866 - Fix version check when applying compatability handling for failed start operations
  + Medium: PE: Bug LF:1866 - Restore the ability to have start failures not be fatal
  + Medium: PE: Bug PM1 - Failcount applies to all instances of non-unique clone
  + Medium: PE: Correctly set the state of partially active master/slave groups
  + Medium: PE: Do not claim to be stopping an already stopped orphan
  + Medium: PE: Ensure implies_left ordering constraints are always effective
  + Medium: PE: Indicate each resources 'promotion' score
  + Medium: PE: Prevent a possible use-of-NULL
  + Medium: PE: Reprocess the current action if it changed (so that any prior dependancies are updated)
  + Medium: TE: Bug LF-1859 - Wait for fail-count updates to complete before terminating the transition
  + Medium: TE: Bug LF:1859 - Do not abort graphs due to our own failcount updates
  + Medium: TE: Bug LF:1859 - Prevent the TE from interupting itself

* Thu Feb 14 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.2-1
- Update source tarball to revision: 28b1a8c1868b tip
- Statistics:
    Changesets:    11
    Diff:          7 files changed, 58 insertions(+), 18 deletions(-)
- Changes since Pacemaker-0.6.1
  + haresources2cib.py: set default-action-timeout to the default (20s)
  + haresources2cib.py: update ra parameters lists
  + Medium: SNMP: Allow the snmp subagent to be built (patch from MATSUDA, Daiki)
  + Medium: Tools: Make sure the autoconf variables in haresources2cib are expanded

* Tue Feb 12 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.1-1
- Update source tarball to revision: e7152d1be933 tip
- Statistics:
    Changesets:    25
    Diff:          37 files changed, 1323 insertions(+), 227 deletions(-)
- Changes since Pacemaker-0.6.0
  + High: CIB: Ensure changes to top-level attributes (like admin_epoch) cause a disk write
  + High: CIB: Ensure the archived file hits the disk before returning
  + High: CIB: Repair the ability to do 'atomic incriment' updates (value="value++")
  + High: crmd: Bug #7 - Connecting to the crmd immediately after startup causes use-of-NULL
  + Medium: CIB: Mask cib_diff_resync results from the caller - they do not need to know
  + Medium: crmd: Delay starting the IPC server until we are fully functional
  + Medium: CTS: Fix the startup patterns
  + Medium: PE: Bug 1820 - Allow the first resource in a group to be migrated
  + Medium: PE: Bug 1820 - Check the colocation dependancies of resources to be migrated

* Mon Jan 14 2008 Andrew Beekhof <abeekhof@suse.de> - 0.6.0-2
- This is the first release of the Pacemaker Cluster Resource Manager formerly part of Heartbeat.
- For those looking for the GUI, mgmtd, CIM or TSA components, they are now found in
  the new pacemaker-pygui project.  Build dependancies prevent them from being
  included in Heartbeat (since the built-in CRM is no longer supported) and,
  being non-core components, are not included with Pacemaker.
- Update source tarball to revision: c94b92d550cf
- Statistics:
    Changesets:      347
    Diff:            2272 files changed, 132508 insertions(+), 305991 deletions(-)
- Test hardware:
    + 6-node vmware cluster (sles10-sp1/256Mb/vmware stonith) on a single host (opensuse10.3/2Gb/2.66Ghz Quad Core2)
    + 7-node EMC Centera cluster (sles10/512Mb/2Ghz Xeon/ssh stonith)
- Notes: Heartbeat Stack
    + All testing was performed with STONITH enabled
    + The CRM was enabled using the "crm respawn" directive
- Notes: OpenAIS Stack
    + This release contains a preview of support for the OpenAIS cluster stack
    + The current release of the OpenAIS project is missing two important
    patches that we require.  OpenAIS packages containing these patches are
    available for most major distributions at:
    http://download.opensuse.org/repositories/server:/ha-clustering
    + The OpenAIS stack is not currently recommended for use in clusters that
    have shared data as STONITH support is not yet implimented
    + pingd is not yet available for use with the OpenAIS stack
    + 3 significant OpenAIS issues were found during testing of 4 and 6 node
    clusters.  We are activly working together with the OpenAIS project to
    get these resolved.
- Pending bugs encountered during testing:
    + OpenAIS   #1736 - Openais membership took 20s to stabilize
    + Heartbeat #1750 - ipc_bufpool_update: magic number in head does not match
    + OpenAIS   #1793 - Assertion failure in memb_state_gather_enter()
    + OpenAIS   #1796 - Cluster message corruption
- Changes since Heartbeat-2.1.2-24
  + High: Add OpenAIS support
  + High: Admin: crm_uuid - Look in the right place for Heartbeat UUID files
  + High: admin: Exit and indicate a problem if the crmd exits while crmadmin is performing a query
  + High: cib: Fix CIB_OP_UPDATE calls that modify the whole CIB
  + High: cib: Fix compilation when supporting the heartbeat stack
  + High: cib: Fix memory leaks caused by the switch to get_message_xml()
  + High: cib: HA_VALGRIND_ENABLED needs to be set _and_ set to 1|yes|true
  + High: cib: Use get_message_xml() in preference to cl_get_struct()
  + High: cib: Use the return value from call to write() in cib_send_plaintext()
  + High: Core: ccm nodes can legitimately have a node id of 0
  + High: Core: Fix peer-process tracking for the Heartbeat stack
  + High: Core: Heartbeat does not send status notifications for nodes that were already part of the cluster.  Fake them instead
  + High: CRM: Add children to HA_Messages such that the field name matches F_XML_TAGNAME
  + High: crm: Adopt a more flexible appraoch to enabling Valgrind
  + High: crm: Fix compilation when bzip2 is not installed
  + High: CRM: Future-proof get_message_xml()
  + High: crmd: Filter election responses based on time not FSA state
  + High: crmd: Handle all possible peer states in crmd_ha_status_callback()
  + High: crmd: Make sure the current date/time is set - prevents use-of-NULL when evaluating rules
  + High: crmd: Relax an assertion regrading  ccm membership instances
  + High: crmd: Use (node->processes&crm_proc_ais) to accurately update the CIB after replace operations
  + High: crmd: Heartbeat: Accurately record peer client status
  + High: PE: Bug 1777 - Allow colocation with a resource in the Stopped state
  + High: PE: Bug 1822 - Prevent use-of-NULL in PromoteRsc()
  + High: PE: Implement three recovery policies based on op_status and op_rc
  + High: PE: Parse fail-count correctly (it may be set to ININFITY)
  + High: PE: Prevent graph-loop when stonith agents need to be moved around before a STONITH op
  + High: PE: Prevent graph-loops when two operations have the same name+interval
  + High: te: Cancel active timers when destroying graphs
  + High: TE: Ensure failcount is set correctly for failed stops/starts
  + High: TE: Update failcount for oeprations that time out
  + Medium: admin: Prevent hang in crm_mon -1 when there is no cib connection - Patch from Junko IKEDA
  + Medium: cib: Require --force|-f when performing potentially dangerous commands with cibadmin
  + Medium: cib: Tweak the shutdown code
  + Medium: Common: Only count peer processes of active nodes
  + Medium: Core: Create generic cluster sign-in method
  + Medium: core: Fix compilation when Heartbeat support is disabled
  + Medium: Core: General cleanup for supporting two stacks
  + Medium: Core: iso6601 - Support parsing of time-only strings
  + Medium: core: Isolate more code that is only needed when SUPPORT_HEARTBEAT is enabled
  + Medium: crm: Improved logging of errors in the XML parser
  + Medium: crmd: Fix potential use-of-NULL in string comparison
  + Medium: crmd: Reimpliment syncronizing of CIB queries and updates when invoking the PE
  + Medium: crm_mon: Indicate when a node is both in standby mode and offline
  + Medium: PE: Bug 1822 - Do not try an promote groups if not all of it is active
  + Medium: PE: on_fail=nothing is an alias for 'ignore' not 'restart'
  + Medium: PE: Prevent a potential use-of-NULL in cron_range_satisfied()
  + snmp subagent: fix a problem on displaying an unmanaged group
  + snmp subagent: use the syslog setting
  + snmp: v2 support (thanks to Keisuke MORI)
  + snmp_subagent - made it not complain about some things if shutting down

* Mon Dec 10 2007 Andrew Beekhof <abeekhof@suse.de> - 0.6.0-1
- Initial opensuse package check-in
