#
# spec file for package pacemaker (Version 1.0.2)
#
# Copyright (c) 2009 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild

%if 0%{?suse_version}
%define _libexecdir %{_libdir}
%endif
%define with_extra_warnings   	0
%define with_debugging  	0
%define suse_build      	1
%define without_fatal_warnings 	1
%define with_ais_support        1
%define with_heartbeat_support  1
%define gname haclient
%define uname hacluster
%define doc_pkg heartbeat-doc-1.0
%if 0%{?fedora_version}
%define pkg_group System Environment/Daemons
%else
%define pkg_group Productivity/Clustering/HA
%endif

Name:           pacemaker
Summary:        The Pacemaker scalable High-Availability cluster resource manager
Version:        1.0.2
Release:        1
License:        GPL v2 or later; LGPL v2.1 or later
Url:            http://www.clusterlabs.org
Group:          Productivity/Clustering/HA
Source:         pacemaker.tar.gz
%if %suse_build
Source2:        %{doc_pkg}.tar.gz
Source100:      pacemaker.rpmlintrc
%endif
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
AutoReqProv:    on
Conflicts:      heartbeat < 2.99
Requires:       heartbeat-common
Requires:       libpacemaker3 = %{version}-%{release}
BuildRequires:  e2fsprogs-devel glib2-devel gnutls-devel libheartbeat-devel libxml2-devel libxslt-devel ncurses-devel pam-devel pkgconfig python-devel

%if %with_ais_support
BuildRequires:  libopenais-devel
Requires:       openais
%endif
%if %with_heartbeat_support
BuildRequires:  heartbeat-devel
Requires:       heartbeat
%endif

%if 0%{?suse_version}
BuildRequires:  libbz2-devel net-snmp-devel tcpd-devel

%if 0%{?suse_version} != 1010
BuildRequires:  libesmtp-devel
%endif
%if 0%{?suse_version} > 1100
BuildRequires:  docbook-xsl-stylesheets
%endif
%endif

%if 0%{?fedora_version}
BuildRequires:  which net-snmp-devel libesmtp-devel
%endif

%if 0%{?centos_version} || 0%{?rhel_version}
BuildRequires:  which
%endif

%if 0%{?mandriva_version}
BuildRequires:  libbzip2-devel
%endif

%description
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.



Authors:
--------
    Andrew Beekhof <abeekhof@suse.de>

%package -n libpacemaker3
License:        GPL v2 or later; LGPL v2.1 or later
Summary:        The Pacemaker scalable High-Availability cluster resource manager
Group:          Productivity/Clustering/HA

%description -n libpacemaker3
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.



Authors:
--------
    Andrew Beekhof <abeekhof@suse.de>

%package -n libpacemaker-devel 
License:        GPL v2 only; GPL v2 or later; LGPL v2.1 or later
Summary:        The Pacemaker scalable High-Availability cluster resource manager
Group:          Development/Libraries/C and C++
Requires:       %{name} = %{version}-%{release}
Requires:       libpacemaker3 = %{version}-%{release}
Requires:       libheartbeat-devel

%description -n libpacemaker-devel
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or OpenAIS.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.



Authors:
--------
    Andrew Beekhof <abeekhof@suse.de>

%prep
###########################################################
%if %suse_build
%setup -a 2 -n pacemaker -q
%else
%setup -n pacemaker
%endif

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
	--with-ais-prefix=%{_prefix}      			\
%if %without_fatal_warnings
	--enable-fatal-warnings=no 
%endif

export MAKE="make %{?jobs:-j%jobs}"
make %{?jobs:-j%jobs}
%if %suse_build
if [ -e /usr/share/xml/docbook/stylesheet/nwalsh/current ]; then
    make -C %{doc_pkg} man
fi
%endif
###########################################################

%install
###########################################################
make DESTDIR=$RPM_BUILD_ROOT install
%if %suse_build
if [ -e %{doc_pkg}/cibadmin.8 ]; then
    install -d $RPM_BUILD_ROOT/%{_mandir}/man8
    for file in `ls -1 %{doc_pkg}/*.8`; do
	install -p -m 644 $file $RPM_BUILD_ROOT/%{_mandir}/man8
    done
fi
%endif
chmod a+x $RPM_BUILD_ROOT/%{_libdir}/heartbeat/crm_primitive.py
chmod a+x $RPM_BUILD_ROOT/%{_libdir}/heartbeat/hb2openais-helper.py
rm $RPM_BUILD_ROOT/%{_libdir}/service_crm.so
(
    cd $RPM_BUILD_ROOT/%{_sbindir}
    rm crm_standby crm_master crm_failcount
    ln crm_attribute crm_standby
    ln crm_attribute crm_master
    ln crm_attribute crm_failcount
)
#%if %with_ais_support
#    mkdir -p $RPM_BUILD_ROOT/%{_libexecdir}/lcrso
#    cp $RPM_BUILD_ROOT/%{_libdir}/service_crm.so $RPM_BUILD_ROOT/%{_libexecdir}/lcrso/pacemaker.lcrso
#%endif
# Cleanup
[ -d $RPM_BUILD_ROOT/usr/man ] && rm -rf $RPM_BUILD_ROOT/usr/man
[ -d $RPM_BUILD_ROOT/usr/share/libtool ] && rm -rf $RPM_BUILD_ROOT/usr/share/libtool
find $RPM_BUILD_ROOT -name '*.a' -type f -print0 | xargs -0 rm -f
find $RPM_BUILD_ROOT -name '*.la' -type f -print0 | xargs -0 rm -f
find $RPM_BUILD_ROOT -name '*.pyc' -type f -print0 | xargs -0 rm -f
find $RPM_BUILD_ROOT -name '*.pyo' -type f -print0 | xargs -0 rm -f
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

%post -n libpacemaker3 -p /sbin/ldconfig

%postun -n libpacemaker3 -p /sbin/ldconfig

%files
###########################################################
%defattr(-,root,root)
%dir %{_libdir}/heartbeat
%dir %{_var}/run/heartbeat
%dir %{_var}/lib/heartbeat
%dir %{_datadir}/doc/packages/pacemaker
%{_datadir}/pacemaker
#%{_datadir}/heartbeat
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
%{_sbindir}/crm_uuid
%{_sbindir}/crm_verify
%{_sbindir}/crmadmin
%{_sbindir}/iso8601
%{_sbindir}/attrd_updater
%{_sbindir}/ptest
%{_sbindir}/crm_shadow
%{_sbindir}/cibpipe
%{_sbindir}/crm_node
%doc %{_datadir}/doc/packages/pacemaker/AUTHORS
%doc %{_datadir}/doc/packages/pacemaker/README
%doc %{_datadir}/doc/packages/pacemaker/README.hb2openais
%doc %{_datadir}/doc/packages/pacemaker/COPYING
%doc %{_datadir}/doc/packages/pacemaker/COPYING.LGPL
%doc %{_datadir}/doc/packages/pacemaker/crm_cli.txt
%if %suse_build
%doc %{_mandir}/man8/*.8*
%endif
%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/heartbeat/crm
%dir %attr (750, %{uname}, %{gname}) %{_var}/lib/heartbeat/pengine
%dir %attr (750, %{uname}, %{gname}) %{_var}/run/heartbeat/crm
%dir /usr/lib/ocf
%dir /usr/lib/ocf/resource.d
/usr/lib/ocf/resource.d/pacemaker
%if %with_ais_support
%{_libexecdir}/lcrso/pacemaker.lcrso
%endif

%files -n libpacemaker3
%defattr(-,root,root)
%{_libdir}/libcib.so.*
%{_libdir}/libcrmcommon.so.*
%{_libdir}/libcrmcluster.so.*
%{_libdir}/libpe_status.so.*
%{_libdir}/libpe_rules.so.*
%{_libdir}/libpengine.so.*
%{_libdir}/libtransitioner.so.*
%{_libdir}/libstonithd.so.*

%files -n libpacemaker-devel
%defattr(-,root,root)
#%doc %{_datadir}/doc/%{name}-%{version}
%{_includedir}/pacemaker
%{_includedir}/heartbeat/fencing
%{_libdir}/*.so

%changelog
