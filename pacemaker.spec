#
# spec file for package Pacemaker (Version 0.7.0)
#
# Copyright (c) 2006 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild

%define with_extra_warnings   	0
%define with_debugging  	0
%define without_fatal_warnings 	1
%define with_ais_support        1
%define with_heartbeat_support  1
%define with_snmp_support	1

%define pkg_group Productivity/Clustering/HA

%if 0%{?fedora_version}
%define pkg_group System Environment/Daemons
%endif

%define gname haclient
%define uname hacluster

Name:           pacemaker
Summary:        The Pacemaker scalable High-Availability cluster resource manager
Version:        0.6.2
Release:        1
License:        GPL2/LGPL2
URL:            http://www.clusterlabs.org
Group:          %{pkg_group}
Source:         pacemaker.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Autoreqprov:    on

%if %with_ais_support
BuildRequires: openais-devel
%endif

%if %with_heartbeat_support
BuildRequires: heartbeat heartbeat-devel > 2.1.2
%endif

%if %{with_ais_support}
 %if %{with_heartbeat_support}
Conflicts: pacemaker-ais
Conflicts: pacemaker-heartbeat
 %else
Conflicts: pacemaker
Conflicts: pacemaker-heartbeat
 %endif
%else
Conflicts: pacemaker
Conflicts: pacemaker-ais
%endif

BuildRequires: heartbeat-common heartbeat-common-devel e2fsprogs-devel glib2-devel gnutls-devel libxml2-devel pam-devel python-devel swig 

%if 0%{?suse_version}

%if 0%{?suse_version} > 1000
%if %with_ais_support
Supplements:   openais
%endif

%if %with_heartbeat_support
Supplements:   heartbeat
%endif
%endif

%if 0%{?suse_version} == 930
BuildRequires: rpm-devel
%endif

%if 0%{?suse_version} == 1000
BuildRequires: lzo lzo-devel
%endif

%if 0%{?suse_version} < 1020
BuildRequires: tcpd-devel
%endif

%if 0%{?sles_version} == 9
BuildRequires: pkgconfig
%endif

%endif

%if 0%{?fedora_version} || 0%{?centos_version} || 0%{?rhel_version}
BuildRequires: 	which
%endif

%if 0%{?fedora_version} == 8
BuildRequires: 	openssl-devel
%endif


%if 0%{?mandriva_version}
BuildRequires: libbzip2-devel
%endif

%description
Pacemaker is an advanced, scalable High-Availability cluster resource manager for 
Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for managing
resources and dependencies.

It will run scripts at initialization, when machines go up or down, 
when related resources fail and can be configured to periodically check
resource health.

%if 0%{?suse_version}
%debug_package
%endif

%package devel 
Summary:        Pacemaker development package 
Group:          %{pkg_group}
Requires:       %{name} = %{version}-%{release}

%description devel
Header files and shared libraries needed for developing programs based on the 
Pacemaker High-Availability cluster resource manager.

%prep
###########################################################
%setup -n pacemaker

###########################################################

%build
# TODO: revisit -all

CFLAGS="${CFLAGS} ${RPM_OPT_FLAGS}"

# Feature-dependent CFLAGS:
%if %with_extra_warnings
# CFLAGS="${CFLAGS} -Wshadow -Wfloat-equal -Waggregate-return -Wnested-externs -Wunreachable-code -Wendif-labels -Winline"
CFLAGS="${CFLAGS} -Wfloat-equal -Wendif-labels -Winline"
%endif
%if %with_debugging
CFLAGS="${CFLAGS} -O0"
%endif

# Distribution specific settings:
%if 0%{?suse_version} > 1001
CFLAGS="${CFLAGS} -fstack-protector-all"
%endif

%if 0%{?suse_version} < 1001
export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/opt/gnome/%{_lib}/pkgconfig:/opt/gnome/share/pkgconfig"
%endif

%if 0%{?suse_version} > 1020
CFLAGS="$CFLAGS -fgnu89-inline"
%endif

%if 0%{?fedora_version} > 6
CFLAGS="$CFLAGS -fgnu89-inline"
%endif

export CFLAGS

./ConfigureMe configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} \
	--localstatedir=%{_var} --infodir=%{_infodir} 		\
	--mandir=%{_mandir} --libdir=%{_libdir} 		\
	--libexecdir=%{_libexecdir} 				\
	--with-group-name=%{gname} --with-ccmuser-name=%{uname} \
	--with-hapkgversion=%{version} 				\
	--enable-glib-malloc 					\
%if %with_snmp_support == 1
	--enable-snmp-subagent					\
%else
	--disable-snmp-subagent					\
%endif
	--with-ais-prefix=%{_prefix}      			\
%if %with_ais_support == 0
	--without-ais-support 					\
%endif
%if %with_heartbeat_support == 0
	--without-heartbeat-support 				\
%endif
%if %without_fatal_warnings
	--enable-fatal-warnings=no 			        \
%endif
	--enable-pretty

export MAKE="make %{?jobs:-j%jobs}"
make %{?jobs:-j%jobs}
###########################################################

%install
###########################################################
#make DESTDIR=$RPM_BUILD_ROOT install-strip
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

#%if %with_ais_support
#    mkdir -p $RPM_BUILD_ROOT/%{_libexecdir}/lcrso
#    cp $RPM_BUILD_ROOT/%{_libdir}/service_crm.so $RPM_BUILD_ROOT/%{_libexecdir}/lcrso/pacemaker.lcrso
#%endif

# Cleanup
[ -d $RPM_BUILD_ROOT/usr/man ] && rm -rf $RPM_BUILD_ROOT/usr/man
[ -d $RPM_BUILD_ROOT/usr/share/libtool ] && rm -rf $RPM_BUILD_ROOT/usr/share/libtool
find $RPM_BUILD_ROOT -name '*.a' -type f -print0 | xargs -0 rm -f
find $RPM_BUILD_ROOT -name '*.la' -type f -print0 | xargs -0 rm -f

###########################################################

%clean
###########################################################
if
  [ -n "${RPM_BUILD_ROOT}" -a "${RPM_BUILD_ROOT}" != "/" ]
then
  rm -rf $RPM_BUILD_ROOT
fi
rm -rf $RPM_BUILD_DIR/pacemaker
###########################################################

%pre
%preun

# Use the following if more commands need to be executed
# %post
# /sbin/ldconfig
# [...]
# http://en.opensuse.org/SUSE_Package_Conventions/RPM_Macros

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
###########################################################
%defattr(-,root,root)
%dir %{_libdir}/heartbeat

%{_prefix}/share/pacemaker
%{_prefix}/share/heartbeat
%{_libdir}/heartbeat/*

%dir %{_var}/lib/heartbeat

%{_libdir}/libcib.so.*
%{_libdir}/libcrmcommon.so.*
%{_libdir}/libcrmcluster.so.*
#%{_libdir}/heartbeat/crm_primitive.py
%{_libdir}/libpe_status.so.*
%{_libdir}/libpe_rules.so.*
%{_libdir}/libpengine.so.*
%{_libdir}/libtransitioner.so.*
%{_libdir}/libstonithd.so.*
%{_sbindir}/cibadmin
%{_sbindir}/crm_attribute
%{_sbindir}/crm_diff
%{_sbindir}/crm_failcount
%{_sbindir}/crm_master
%{_sbindir}/crm_mon
%{_sbindir}/crm_sh
%{_sbindir}/crm_resource
%{_sbindir}/crm_standby
%{_sbindir}/crm_uuid
%{_sbindir}/crm_verify
%{_sbindir}/crmadmin
%{_sbindir}/iso8601
%{_sbindir}/ccm_tool
%{_sbindir}/attrd_updater
%{_sbindir}/ptest
%doc %{_mandir}/man8/cibadmin.8*
%doc %{_mandir}/man8/crm_resource.8*
%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/heartbeat/crm
%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/heartbeat/pengine
%dir %attr (750, %{uname}, %{gname}) %{_var}/run/heartbeat/crm
%if %with_ais_support
%{_libexecdir}/lcrso/pacemaker.lcrso
%endif
%if %with_snmp_support == 1
/usr/share/snmp/mibs/LINUX-HA-MIB.mib
%endif

%files devel
%defattr(-,root,root)
#%doc %{_datadir}/doc/%{name}-%{version}
%{_includedir}/pacemaker
%{_includedir}/heartbeat/fencing
%{_libdir}/*.so

%changelog pacemaker
