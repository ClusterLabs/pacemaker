# How to Install Pacemaker

## Build Dependencies

| Version         | Fedora-based       | Suse-based         | Debian-based   |
|:---------------:|:------------------:|:------------------:|:--------------:|
| 1.11 or later   | automake           | automake           | automake       |
| 2.64 or later   | autoconf           | autoconf           | autoconf       |
|                 | libtool            | libtool            | libtool        |
|                 | libtool-ltdl-devel |                    | libltdl-dev    |
|                 | libuuid-devel      | libuuid-devel      | uuid-dev       |
|                 | pkgconfig          | pkgconfig          | pkg-config     |
| 2.16.0 or later | glib2-devel        | glib2-devel        | libglib2.0-dev |
|                 | libxml2-devel      | libxml2-devel      | libxml2-dev    |
|                 | libxslt-devel      | libxslt-devel      | libxslt-dev    |
|                 | bzip2-devel        | libbz2-devel       | libbz2-dev     |
|                 | libqb-devel        | libqb-devel        | libqb-dev      |

Also: GNU make, and Python 2.7 or Python 3.2 or later

### Cluster Stack Dependencies

*Only corosync is currently supported*

| Version         | Fedora-based       | Suse-based         | Debian-based   |
|:---------------:|:------------------:|:------------------:|:--------------:|
| 2.0.0 or later  | corosynclib        | libcorosync        | corosync       |
| 2.0.0 or later  | corosynclib-devel  | libcorosync-devel  |                |
|                 |                    |                    | libcfg-dev     |
|                 |                    |                    | libcpg-dev     |
|                 |                    |                    | libcmap-dev    |
|                 |                    |                    | libquorum-dev  |

### Optional Build Dependencies

| Feature Enabled                                 | Version        | Fedora-based            | Suse-based              | Debian-based            |
|:-----------------------------------------------:|:--------------:|:-----------------------:|:-----------------------:|:-----------------------:|
| Pacemaker Remote and encrypted remote CIB admin | 2.1.7 or later | gnutls-devel            | libgnutls-devel         | libgnutls-dev           |
| encrypted remote CIB admin                      |                | pam-devel               | pam-devel               | libpam0g-dev            |
| interactive crm_mon                             |                | ncurses-devel           | ncurses-devel           | ncurses-dev             |
| systemd support                                 |                | systemd-devel           | systemd-devel           | libsystemd-dev          |
| systemd/upstart resource support                |                | dbus-devel              | dbus-devel              | libdbus-1-dev           |
| Linux-HA style fencing agents                   |                | cluster-glue-libs-devel | libglue-devel           | cluster-glue-dev        |
| documentation                                   |                | asciidoc or asciidoctor | asciidoc or asciidoctor | asciidoc or asciidoctor |
| documentation                                   |                | help2man                | help2man                | help2man                |
| documentation                                   |                | publican                |                         | publican                |
| documentation                                   |                | inkscape                | inkscape                | inkscape                |
| documentation                                   |                | docbook-style-xsl       | docbook-xsl-stylesheets | docbook-xsl             |
| documentation                                   |                | python-sphinx or python3-sphinx | python-sphinx or python3-sphinx | python-sphinx or python3-sphinx |
| documentation (PDF)                             |                | texlive, texlive-titlesec, texlive-framed, texlive-threeparttable texlive-wrapfig texlive-multirow | texlive, texlive-latex  | texlive, texlive-latex-extra |

## Optional testing dependencies
* valgrind (if running CTS valgrind tests)
* systemd-python (if using CTS on cluster nodes running systemd)
* rsync (if running CTS container tests)
* libvirt-daemon-driver-lxc (if running CTS container tests)
* libvirt-daemon-lxc (if running CTS container tests)
* libvirt-login-shell (if running CTS container tests)
* nmap (if not specifying an IP address base)
* oprofile (if running CTS profiling tests)
* dlm (to log DLM debugging info after CTS tests)

## Simple install

    $ make && sudo make install

If GNU make is not your default make, use "gmake" instead.

## Detailed install

First, browse the build options that are available:

    $ ./autogen.sh
    $ ./configure --help

Re-run ./configure with any options you want, then proceed with the simple
method.
