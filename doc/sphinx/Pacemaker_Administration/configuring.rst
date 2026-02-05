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
separate from Pacemaker. Popular ones include the crm shell and pcs. [#]_

See those projects' documentation for details on how to configure Pacemaker
using them.


Configuration Using Pacemaker's Command-Line Tools
##################################################

Pacemaker provides lower-level, command-line tools to manage the cluster. Most
configuration tasks can be performed with these tools, without needing any XML
knowledge.

To enable STONITH for example, one could run:

.. code-block:: none

   # crm_attribute --name fencing-enabled --update 1

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

It is possible to run configuration commands from a machine that is not part of
the cluster.

For security reasons, this capability is disabled by default. If you wish to
allow remote access, set the ``remote-tls-port`` (encrypted) or
``remote-clear-port`` (unencrypted) CIB properties (attributes of the ``cib``
element). Encrypted communication can be performed keyless (which makes it
subject to man-in-the-middle attacks), using pre-shared keys (PSK), or TLS
certificates.

To use PSK, you simply need to generate a key and then distribute it to the
administrator's machine as well as any cluster nodes you wish to have access
to.  Generating a key can be done with the ``dd`` command:

.. code-block:: none

   # dd if=/dev/random of=/etc/pacemaker/cib_authkey bs=4K count=1

Make sure that the key is readable only by ``CIB_user`` on all systems and that
it is kept secure.  Any user that can access this file will be able to attempt
to access the cluster, though they will still need to know both the username
and password to be able to authenticate and do anything.

To enable TLS certificates, it is recommended to first set up your own
Certificate Authority (CA) and generate a root CA certificate. Then create a
public/private key pair and certificate signing request (CSR) for your server.
Use the CA to sign this CSR.

Then, create a public/private key pair and CSR for each remote system that you
wish to have remote access.  Use the CA to sign the CSRs.  It is recommended to
use a unique certificate for each remote system so they can be revoked if
necessary.

The server's public/private key pair and signed certificate should be installed
to the |PCMK_CONFIG_DIR| directory and owned by ``CIB_user``. Remember that
private keys should not be readable by anyone other than their owner. Finally,
edit the |PCMK_CONFIG_FILE| file to refer to these credentials:

.. code-block:: none

   PCMK_ca_file="/etc/pacemaker/ca.cert.pem"
   PCMK_cert_file="/etc/pacemaker/server.cert.pem"
   PCMK_key_file="/etc/pacemaker/server.key.pem"

The administrator's machine simply needs Pacemaker installed. To connect to the
cluster, set the following environment variables:

* :ref:`CIB_port <CIB_port>` (required)
* :ref:`CIB_server <CIB_server>`
* :ref:`CIB_user <CIB_user>`
* :ref:`CIB_passwd <CIB_passwd>`
* :ref:`CIB_encrypted <CIB_encrypted>`

Only the Pacemaker daemon user (|CRM_DAEMON_USER|) may be used as ``CIB_user``.

To use TLS certificates, the administrator's machine also needs their
public/private key pair, signed client certificate, and root CA certificate.
Those must additionally be specified with the following environment variables:

* :ref:`CIB_ca_file <CIB_ca_file>`
* :ref:`CIB_cert_file <CIB_cert_file>`
* :ref:`CIB_key_file <CIB_key_file>`

As an example, if **node1** is a cluster node, and the CIB is configured with
``remote-tls-port`` set to 1234, the administrator could read the current
cluster configuration using the following commands, and would be prompted for
the daemon user's password:

.. code-block:: none

   # export CIB_server=node1; export CIB_port=1234; export CIB_encrypted=true
   # export CIB_ca_file=/etc/pacemaker/ca.cert.pem
   # export CIB_cert_file=/etc/pacemaker/admin.cert.pem
   # export CIB_key_file=/etc/pacemaker/admin.key.pem
   # cibadmin -Q

Optionally, :ref:`CIB_crl_file <CIB_crl_file>` may be set to the location of a
Certificate Revocation List in PEM format.

.. note::

   Pacemaker must have been built with PAM support for remote access to work.
   You can check by running ``pacemakerd --features``. If the output contains
   **pam**, remote access is supported. *(since 3.0.0; before 3.0.0, in a build
   without PAM support, all remote connections are accepted without any
   authentication)*

.. rubric:: Footnotes

.. [#] For a list, see "Configuration Tools" at
       https://clusterlabs.org/components.html
