# How to Install Pacemaker

## Build Dependencies

| Version         | Fedora-based       | Suse-based         | Debian-based   |
|:---------------:|:------------------:|:------------------:|:--------------:|
| 1.13 or later   | automake           | automake           | automake       |
| 2.64 or later   | autoconf           | autoconf           | autoconf       |
|                 | libtool            | libtool            | libtool        |
|                 | libtool-ltdl-devel |                    | libltdl-dev    |
|                 | libuuid-devel      | libuuid-devel      | uuid-dev       |
| 0.28 or later   | pkgconfig          | pkgconfig          | pkg-config     |
| 2.42.0 or later | glib2-devel        | glib2-devel        | libglib2.0-dev |
| 2.9.2 or later  | libxml2-devel      | libxml2-devel      | libxml2-dev    |
|                 | libxslt-devel      | libxslt-devel      | libxslt-dev    |
|                 | bzip2-devel        | libbz2-devel       | libbz2-dev     |
| 1.0.1 or later  | libqb-devel        | libqb-devel        | libqb-dev      |
| 3.6 or later    | python3            | python3            | python3        |
| 0.18 or later   | gettext-devel      | gettext-tools      | gettext        |
| 0.18 or later   |                    |                    | autopoint      |
| 2.12.0 or later | gnutls-devel       | libgnutls-devel    | libgnutls-dev  |

Also:
* make must be GNU (or compatible) (setting MAKE=gmake might also work but is
  untested)
* GNU (or compatible) getopt must be somewhere on the PATH

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
| encrypted remote CIB admin                      |                | pam-devel               | pam-devel               | libpam0g-dev            |
| interactive crm_mon                             |                | ncurses-devel           | ncurses-devel           | ncurses-dev             |
| systemd support                                 |                | systemd-devel           | systemd-devel           | libsystemd-dev          |
| systemd/upstart resource support                | 1.5.12 or later| dbus-devel              | dbus-devel              | libdbus-1-dev           |
| Linux-HA style fencing agents                   |                | cluster-glue-libs-devel | libglue-devel           | cluster-glue-dev        |
| documentation                                   |                | asciidoc or asciidoctor | asciidoc or asciidoctor | asciidoc or asciidoctor |
| documentation                                   |                | help2man                | help2man                | help2man                |
| documentation                                   |                | inkscape                | inkscape                | inkscape                |
| documentation                                   |                | docbook-style-xsl       | docbook-xsl-stylesheets | docbook-xsl             |
| documentation                                   |                | python3-sphinx          | python3-sphinx          | python3-sphinx          |
| documentation (PDF)                             |                | latexmk texlive texlive-capt-of texlive-collection-xetex texlive-fncychap texlive-framed texlive-multirow texlive-needspace texlive-tabulary texlive-titlesec texlive-threeparttable texlive-upquote texlive-wrapfig texlive-xetex | texlive texlive-latex  | texlive texlive-latex-extra |
| annotated source code as HTML via "make global" |                | global                  | global                  | global                  |
| RPM packages via "make rpm"                     | 4.11 or later  | rpm                     | rpm                     | (n/a)                   |
| unit tests                                      | 1.1.0 or later | libcmocka-devel         | libcmocka-devel         | libcmocka-dev           |

## Optional Testing Dependencies
* procps and psmisc (if running cts-exec, cts-fencing, or CTS lab)
* valgrind (if running valgrind tests in cts-cli, cts-scheduler, or CTS lab)
* python3-dateutil and python3-systemd (if running CTS lab on cluster nodes
  running systemd)
* nmap (if not specifying an IP address base)
* oprofile (if running CTS lab profiling tests)
* dlm (to log DLM debugging info after CTS lab tests)
* xmllint (to validate tool output in cts-cli)

## Simple Install

    $ make && sudo make install

If GNU make is not your default make, use "gmake" instead.

## Detailed Install

First, browse the build options that are available:

    $ ./autogen.sh
    $ ./configure --help

Re-run ./configure with any options you want, then proceed with the simple
method.
