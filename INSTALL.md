# How to Install Pacemaker

## Build Dependencies
* automake 1.11 or later
* autoconf 2.64 or later
* libtool
* libtool-ltdl-devel
* libuuid-devel
* pkgconfig
* python (or python-devel if that's preferred as a build dependency)
* glib2-devel 2.16.0 or later
* libxml2-devel
* libxslt-devel 
* bzip2-devel
* gnutls-devel
* pam-devel
* libqb-devel

## Cluster Stack Dependencies (Pick at least one)
* Corosync: corosynclib-devel
* (no other stacks are currently supported)

## Optional Build Dependencies
* ncurses-devel (interactive crm_mon)
* systemd-devel (systemd support)
* dbus-devel (systemd/upstart resource support)
* cluster-glue-libs-devel (Linux-HA style fencing agents)
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
