# Pacemaker

## What is Pacemaker?

Pacemaker is an advanced, scalable high-availability cluster resource manager.

It supports "N-node" clusters with significant capabilities for
managing resources and dependencies.

It will run scripts at initialization, when machines go up or down,
when related resources fail and can be configured to periodically check
resource health.

## Who is Pacemaker?

Pacemaker is distributed by [ClusterLabs](http://www.clusterlabs.org).

Pacemaker was initially created by main architect and lead developer
Andrew Beekhof <andrew@beekhof.net>, with the aid of
project catalyst and advocate Lars Marowsky-Brée <lmb@suse.de>.

Many, many developers have contributed significantly to the project since.
The git log is the definitive record of their greatly appreciated
contributions.

The wider community of Pacemaker users is another essential aspect of the
project's existence, especially the many users who participate in the mailing
lists, blog about HA clustering, and otherwise actively make the project more
useful.

## How do I install Pacemaker?

See [INSTALL.md](https://github.com/ClusterLabs/pacemaker/blob/master/INSTALL.md).

## What higher-level interfaces to Pacemaker are available?

There are multiple user interfaces for Pacemaker, including command-line
tools, graphical user interfaces and web frontends. The crm shell
used to be included in the Pacemaker source tree, but is now
a separate project.

This is not an exhaustive list:

* crmsh: https://github.com/ClusterLabs/crmsh
* pcs: https://github.com/ClusterLabs/pcs
* LCMC: http://lcmc.sourceforge.net/
* hawk: https://github.com/ClusterLabs/hawk
* Striker: https://github.com/ClusterLabs/striker

## How can I help?

See [CONTRIBUTING.md](https://github.com/ClusterLabs/pacemaker/blob/master/CONTRIBUTING.md).

## Where can I find more information about Pacemaker?

* [ClusterLabs website](http://www.clusterlabs.org/)
* [Documentation](http://www.clusterlabs.org/doc/)
* [Issues/Bugs](http://bugs.clusterlabs.org/)
* Mailing lists for [users](http://oss.clusterlabs.org/mailman/listinfo/users) and [developers](http://oss.clusterlabs.org/mailman/listinfo/developers)
* #clusterlabs IRC channel on [freenode](http://freenode.net/)
