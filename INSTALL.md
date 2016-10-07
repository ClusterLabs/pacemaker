# How to Install Pacemaker

## Build Dependencies
* automake
* autoconf
* libtool-ltdl-devel
* libuuid-devel
* pkgconfig
* python (or python-devel if that's preferred as a build dependency)
* glib2-devel
* libxml2-devel
* libxslt-devel 
* bzip2-devel
* gnutls-devel
* pam-devel
* libqb-devel

## Cluster Stack Dependencies (Pick at least one)
* clusterlib-devel (CMAN)
* corosynclib-devel (Corosync)
* heartbeat-devel (Heartbeat)

## Optional Build Dependencies
* ncurses-devel (interactive crm_mon)
* systemd-devel (systemd support)
* dbus-devel (systemd/upstart resource support)
* cluster-glue-libs-devel (LHA style fencing agents)
* libesmtp-devel (Email alerts)
* lm_sensors-devel (SNMP alerts)
* net-snmp-devel (SNMP alerts)
* asciidoc (documentation)
* help2man (documentation)
* publican (documentation)
* inkscape (documentation)
* docbook-style-xsl (documentation)

## Optional testing dependencies
* valgrind (if running CTS valgrind tests)
* systemd-python (if using CTS on cluster nodes running systemd)
* rsync (if running CTS container tests)
* libvirt-daemon-driver-lxc (if running CTS container tests)
* libvirt-daemon-lxc (if running CTS container tests)
* libvirt-login-shell (if running CTS container tests)

## Source Control (GIT)

    git clone git://github.com/ClusterLabs/pacemaker.git

[See Github](https://github.com/ClusterLabs/pacemaker)

## Installing from source

    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install
