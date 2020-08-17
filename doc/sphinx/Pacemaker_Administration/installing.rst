Installing Cluster Software
---------------------------

.. index:: installation

Installing the Software
#######################

Most major Linux distributions have pacemaker packages in their standard
package repositories, or the software can be built from source code.
See the `Install wiki page <https://wiki.clusterlabs.org/wiki/Install>`_
for details.

Enabling Pacemaker
##################

.. index::
   pair: configuration; Corosync

Enabling Pacemaker For Corosync version 2 and greater
_____________________________________________________

High-level cluster management tools are available that can configure
corosync for you. This document focuses on the lower-level details
if you want to configure corosync yourself.

Corosync configuration is normally located in
``/etc/corosync/corosync.conf``.

.. topic:: Corosync configuration file for two nodes **myhost1** and **myhost2**

   .. code-block:: none

      totem {
        version: 2
        secauth: off
        cluster_name: mycluster
        transport: udpu
      }

      nodelist {
        node {
              ring0_addr: myhost1
              nodeid: 1
             }
        node {
              ring0_addr: myhost2
              nodeid: 2
             }
      }

      quorum {
        provider: corosync_votequorum
        two_node: 1
      }

      logging {
        to_syslog: yes
      }

.. topic:: Corosync configuration file for three nodes **myhost1**, **myhost2** and **myhost3**

   .. code-block:: none

      totem {
        version: 2
        secauth: off
        cluster_name: mycluster
        transport: udpu
      }

      nodelist {
        node {
              ring0_addr: myhost1
              nodeid: 1
        }
        node {
              ring0_addr: myhost2
              nodeid: 2
        }
        node {
              ring0_addr: myhost3
              nodeid: 3
        }
      }

      quorum {
        provider: corosync_votequorum
      }

      logging {
        to_syslog: yes
      }

In the above examples, the ``totem`` section defines what protocol version and
options (including encryption) to use, [#]_
and gives the cluster a unique name (``mycluster`` in these examples).

The ``node`` section lists the nodes in this cluster.

The ``quorum`` section defines how the cluster uses quorum. The important thing
is that two-node clusters must be handled specially, so ``two_node: 1`` must be
defined for two-node clusters (it will be ignored for clusters of any other
size).

The ``logging`` section should be self-explanatory.

.. rubric:: Footnotes

.. [#] Please consult the Corosync website (http://www.corosync.org/) and
       documentation for details on enabling encryption and peer authentication
       for the cluster.
