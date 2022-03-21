.. index::
   single: configuration
   single: CIB

Configuring Pacemaker
---------------------

Pacemaker's configuration, the CIB, is stored in XML format. Cluster
administrators have multiple options for modifying the configuration either via
the XML, or at a more abstract (and easier for humans to understand) level.

Pacemaker reacts to configuration changes as soon as they are saved.
Pacemaker's command-line tools and most higher-level tools provide the ability
to batch changes together and commit them at once, rather than make a series of
small changes, which could cause avoid unnecessary actions as Pacemaker
responds to each change individually.

Pacemaker tracks revisions to the configuration and will reject any update
older than the current revision. Thus, it is a good idea to serialize all
changes to the configuration. Avoid attempting simultaneous changes, whether on
the same node or different nodes, and whether manually or using some automated
configuration tool.

.. note::

   It is not necessary to update the configuration on all cluster nodes.
   Pacemaker immediately synchronizes changes to all active members of the
   cluster. To reduce bandwidth, the cluster only broadcasts the incremental
   updates that result from your changes and uses checksums to ensure that each
   copy is consistent.


Configuration Using Higher-level Tools
######################################

Most users will benefit from using higher-level tools provided by projects
separate from Pacemaker. Some of the most commonly used include the crm shell,
hawk, and pcs. [#]_

See those projects' documentation for details on how to configure Pacemaker
using them.


Configuration Using Pacemaker's Command-Line Tools
##################################################

Pacemaker provides lower-level, command-line tools to manage the cluster. Most
configuration tasks can be performed with these tools, without needing any XML
knowledge.

To enable STONITH for example, one could run:

.. code-block:: none

   # crm_attribute --name stonith-enabled --update 1

Or, to check whether **node1** is allowed to run resources, there is:

.. code-block:: none

   # crm_standby --query --node node1

Or, to change the failure threshold of **my-test-rsc**, one can use:

.. code-block:: none

   # crm_resource -r my-test-rsc --set-parameter migration-threshold --parameter-value 3 --meta

Examples of using these tools for specific cases will be given throughout this
document where appropriate. See the man pages for further details.

See :ref:`cibadmin` for how to edit the CIB using XML.

See :ref:`crm_shadow` for a way to make a series of changes, then commit them
all at once to the live cluster.


.. index::
   single: configuration; CIB properties
   single: CIB; properties
   single: CIB property

Working with CIB Properties
___________________________

Although these fields can be written to by the user, in
most cases the cluster will overwrite any values specified by the
user with the "correct" ones.

To change the ones that can be specified by the user, for example
``admin_epoch``, one should use:

.. code-block:: none

   # cibadmin --modify --xml-text '<cib admin_epoch="42"/>'

A complete set of CIB properties will look something like this:

.. topic:: XML attributes set for a cib element

   .. code-block:: xml

      <cib crm_feature_set="3.0.7" validate-with="pacemaker-1.2" 
         admin_epoch="42" epoch="116" num_updates="1"
         cib-last-written="Mon Jan 12 15:46:39 2015" update-origin="rhel7-1"
         update-client="crm_attribute" have-quorum="1" dc-uuid="1">


.. index::
   single: configuration; cluster options

Querying and Setting Cluster Options
____________________________________

Cluster options can be queried and modified using the ``crm_attribute`` tool.
To get the current value of ``cluster-delay``, you can run:

.. code-block:: none

   # crm_attribute --query --name cluster-delay

which is more simply written as

.. code-block:: none

   # crm_attribute -G -n cluster-delay

If a value is found, you'll see a result like this:

.. code-block:: none

   # crm_attribute -G -n cluster-delay
   scope=crm_config name=cluster-delay value=60s

If no value is found, the tool will display an error:

.. code-block:: none

   # crm_attribute -G -n clusta-deway
   scope=crm_config name=clusta-deway value=(null)
   Error performing operation: No such device or address

To use a different value (for example, 30 seconds), simply run:

.. code-block:: none

   # crm_attribute --name cluster-delay --update 30s

To go back to the cluster's default value, you can delete the value, for example:

.. code-block:: none

   # crm_attribute --name cluster-delay --delete
   Deleted crm_config option: id=cib-bootstrap-options-cluster-delay name=cluster-delay


When Options are Listed More Than Once
______________________________________

If you ever see something like the following, it means that the option you're
modifying is present more than once.

.. topic:: Deleting an option that is listed twice

   .. code-block:: none

      # crm_attribute --name batch-limit --delete

      Please choose from one of the matches below and supply the 'id' with --id
      Multiple attributes match name=batch-limit in crm_config:
      Value: 50          (set=cib-bootstrap-options, id=cib-bootstrap-options-batch-limit)
      Value: 100         (set=custom, id=custom-batch-limit)

In such cases, follow the on-screen instructions to perform the requested
action.  To determine which value is currently being used by the cluster, refer
to the "Rules" chapter of *Pacemaker Explained*.


.. index::
   single: configuration; remote

.. _remote_connection:

Connecting from a Remote Machine
################################

Provided Pacemaker is installed on a machine, it is possible to connect to the
cluster even if the machine itself is not in the same cluster. To do this, one
simply sets up a number of environment variables and runs the same commands as
when working on a cluster node.

.. table:: **Environment Variables Used to Connect to Remote Instances of the CIB**

   +----------------------+-----------+------------------------------------------------+
   | Environment Variable | Default   | Description                                    |
   +======================+===========+================================================+
   | CIB_user             | $USER     | .. index::                                     |
   |                      |           |    single: CIB_user                            |
   |                      |           |    single: environment variable; CIB_user      |
   |                      |           |                                                |
   |                      |           | The user to connect as. Needs to be            |
   |                      |           | part of the ``haclient`` group on              |
   |                      |           | the target host.                               |
   +----------------------+-----------+------------------------------------------------+
   | CIB_passwd           |           | .. index::                                     |
   |                      |           |    single: CIB_passwd                          |
   |                      |           |    single: environment variable; CIB_passwd    |
   |                      |           |                                                |
   |                      |           | The user's password. Read from the             |
   |                      |           | command line if unset.                         |
   +----------------------+-----------+------------------------------------------------+
   | CIB_server           | localhost | .. index::                                     |
   |                      |           |    single: CIB_server                          |
   |                      |           |    single: environment variable; CIB_server    |
   |                      |           |                                                |
   |                      |           | The host to contact                            |
   +----------------------+-----------+------------------------------------------------+
   | CIB_port             |           | .. index::                                     |
   |                      |           |    single: CIB_port                            |
   |                      |           |    single: environment variable; CIB_port      |
   |                      |           |                                                |
   |                      |           | The port on which to contact the server;       |
   |                      |           | required.                                      |
   +----------------------+-----------+------------------------------------------------+
   | CIB_encrypted        | TRUE      | .. index::                                     |
   |                      |           |    single: CIB_encrypted                       |
   |                      |           |    single: environment variable; CIB_encrypted |
   |                      |           |                                                |
   |                      |           | Whether to encrypt network traffic             |
   +----------------------+-----------+------------------------------------------------+

So, if **c001n01** is an active cluster node and is listening on port 1234
for connections, and **someuser** is a member of the **haclient** group,
then the following would prompt for **someuser**'s password and return
the cluster's current configuration:

.. code-block:: none

   # export CIB_port=1234; export CIB_server=c001n01; export CIB_user=someuser;
   # cibadmin -Q

For security reasons, the cluster does not listen for remote connections by
default.  If you wish to allow remote access, you need to set the
``remote-tls-port`` (encrypted) or ``remote-clear-port`` (unencrypted) CIB
properties (i.e., those kept in the ``cib`` tag, like ``num_updates`` and
``epoch``).

.. table:: **Extra top-level CIB properties for remote access**

   +----------------------+-----------+------------------------------------------------------+
   | CIB Property         | Default   | Description                                          |
   +======================+===========+======================================================+
   | remote-tls-port      |           | .. index::                                           |
   |                      |           |    single: remote-tls-port                           |
   |                      |           |    single: CIB property; remote-tls-port             |
   |                      |           |                                                      |
   |                      |           | Listen for encrypted remote connections              |
   |                      |           | on this port.                                        |
   +----------------------+-----------+------------------------------------------------------+
   | remote-clear-port    |           | .. index::                                           |
   |                      |           |    single: remote-clear-port                         |
   |                      |           |    single: CIB property; remote-clear-port           |
   |                      |           |                                                      |
   |                      |           | Listen for plaintext remote connections              |
   |                      |           | on this port.                                        |
   +----------------------+-----------+------------------------------------------------------+

.. important::

   The Pacemaker version on the administration host must be the same or greater
   than the version(s) on the cluster nodes. Otherwise, it may not have the
   schema files necessary to validate the CIB.


.. rubric:: Footnotes

.. [#] For a list, see "Configuration Tools" at
       https://clusterlabs.org/components.html
