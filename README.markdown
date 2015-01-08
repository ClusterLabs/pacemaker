# Pacemaker

## What is Pacemaker?
Pacemaker is an advanced, scalable High-Availability cluster resource
manager for Linux-HA (Heartbeat) and/or Corosync.

It supports "n-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

## For more information look at:
* [Website](http://www.clusterlabs.org)
* [Issues/Bugs](http://bugs.clusterlabs.org)
* [Mailing list](http://oss.clusterlabs.org/mailman/listinfo/pacemaker).
* [Documentation](http://www.clusterlabs.org/doc)

## User interfaces / shells

There are multiple user interfaces for Pacemaker, both command line
tools, graphical user interfaces and web frontends. The _crm shell_
used to be included in the Pacemaker source tree, but is now
maintained as a separate project.

This is not meant to be an exhaustive list:

* _crmsh_: https://crmsh.github.io/
* _pcs_: https://github.com/feist/pcs/
* _LCMC_: http://lcmc.sourceforge.net/
* _hawk_: https://github.com/ClusterLabs/hawk

## Build Dependencies
* automake
* autoconf
* libtool-ltdl-devel
* libuuid-devel
* pkgconfig
* python
* glib2-devel
* libxml2-devel
* libxslt-devel 
* python-devel
* gcc-c++
* bzip2-devel
* gnutls-devel
* pam-devel
* libqb-devel

## Cluster Stack Dependencies (Pick at least one)
* clusterlib-devel (CMAN)
* corosynclib-devel (Corosync)
* heartbeat-devel (Heartbeat)

## Optional Build Dependencies
* ncurses-devel
* openssl-devel
* libselinux-devel
* cluster-glue-libs-devel (LHA style fencing agents)
* libesmtp-devel (Email alerts)
* lm_sensors-devel (SNMP alerts)
* net-snmp-devel (SNMP alerts)
* asciidoc (documentation)
* help2man (documentation)
* publican (documentation)
* inkscape (documentation)
* docbook-style-xsl (documentation)

## Source Control (GIT)

    git clone git://github.com/ClusterLabs/pacemaker.git

[See Github](https://github.com/ClusterLabs/pacemaker)

## Installing from source

    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install

## How you can help
If you find this project useful, you may want to consider supporting its future development.
There are a number of ways to support the project.

* Test and report issues.
* Tick something off our [todo list](https://github.com/ClusterLabs/pacemaker/blob/master/TODO.markdown)
* Help others on the [mailing list](http://oss.clusterlabs.org/mailman/listinfo/pacemaker).
* Contribute documentation, examples and test cases.
* Contribute patches.
* Spread the word.
