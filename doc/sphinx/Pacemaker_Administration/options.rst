.. index:: client options

Client Options
--------------

Pacemaker uses several environment variables set on the client side.

.. note:: Directory and file paths below may differ on your system depending on
          your Pacemaker build settings. Check your Pacemaker configuration
          file to find the correct paths.

.. list-table:: **Client-side Environment Variables**
   :class: longtable
   :widths: 20 30 50
   :header-rows: 1

   * - Environment Variable
     - Default
     - Description
   * - .. _CIB_encrypted:

       .. index::
          single: CIB_encrypted
          single: environment variable; CIB_encrypted

       CIB_encrypted
     - true
     - Whether to encrypt network traffic. Used with :ref:`CIB_port <CIB_port>`
       for connecting to a remote CIB instance; ignored if
       :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_file:

       .. index::
          single: CIB_file
          single: environment variable; CIB_file

       CIB_file
     -
     - If set, CIB connections are created against the named XML file. Clients
       read an input CIB from, and write the result CIB to, the named file.
       Ignored if :ref:`CIB_shadow <CIB_shadow>` is set.
   * - .. _CIB_passwd:

       .. index::
          single: CIB_passwd
          single: environment variable; CIB_passwd

       CIB_passwd
     -
     - :ref:`$CIB_user <CIB_user>`'s password. Read from the command line if
       unset. Used with :ref:`CIB_port <CIB_port>` for connecting to a remote
       CIB instance; ignored if :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_port:

       .. index::
          single: CIB_port
          single: environment variable; CIB_port

       CIB_port
     -
     - If set, CIB connections are created as clients to a remote CIB instance
       on :ref:`$CIB_server <CIB_server>` via this port. Ignored if
       :ref:`CIB_shadow <CIB_shadow>` or :ref:`CIB_file <CIB_file>` is set.
   * - .. _CIB_server:

       .. index::
          single: CIB_server
          single: environment variable; CIB_server

       CIB_server
     - localhost
     - The host to connect to. Used with :ref:`CIB_port <CIB_port>` for
       connecting to a remote CIB instance; ignored if
       :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_ca_file:

       .. index::
          single: CIB_ca_file
          single: environment variable; CIB_ca_file

       CIB_ca_file
     -
     - If this, :ref:`CIB_cert_file <CIB_cert_file>`, and
       :ref:`CIB_key_file <CIB_key_file>` are set, remote CIB administration
       will be encrypted using X.509 (SSL/TLS) certificates, with this root
       certificate for the certificate authority. Used with :ref:`CIB_port
       <CIB_port>` for connecting to a remote CIB instance; ignored if
       :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_cert_file:

       .. index::
          single: CIB_cert_file
          single: environment variable; CIB_cert_file

       CIB_cert_file
     -
     - If this, :ref:`CIB_ca_file <CIB_ca_file>`, and
       :ref:`CIB_key_file <CIB_key_file>` are set, remote CIB administration
       will be encrypted using X.509 (SSL/TLS) certificates, with this
       certificate for the local host. Used with :ref:`CIB_port <CIB_port>` for
       connecting to a remote CIB instance; ignored if
       :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_key_file:

       .. index::
          single: CIB_key_file
          single: environment variable; CIB_key_file

       CIB_key_file
     -
     - If this, :ref:`CIB_ca_file <CIB_ca_file>`, and
       :ref:`CIB_cert_file <CIB_cert_file>` are set, remote CIB administration
       will be encrypted using X.509 (SSL/TLS) certificates, with this
       private key for the local host. Used with :ref:`CIB_port <CIB_port>` for
       connecting to a remote CIB instance; ignored if
       :ref:`CIB_port <CIB_port>` is not set.
   * - .. _CIB_crl_file:

       .. index::
          single: CIB_crl_file
          single: environment variable; CIB_crl_file

       CIB_crl_file
     -
     - If this, :ref:`CIB_ca_file <CIB_ca_file>`,
       :ref:`CIB_cert_file <CIB_cert_file>`, and
       :ref:`CIB_key_file <CIB_key_file>` are all set, then certificates listed
       in this PEM-format Certificate Revocation List file will be rejected.
   * - .. _CIB_shadow:

       .. index::
          single: CIB_shadow
          single: environment variable; CIB_shadow

       CIB_shadow
     -
     - If set, CIB connections are created against a temporary working
       ("shadow") CIB file called ``shadow.$CIB_shadow`` in
       :ref:`$CIB_shadow_dir <CIB_shadow_dir>`. Should be set only to the name
       of a shadow CIB created by :ref:`crm_shadow <crm_shadow>`. Otherwise,
       behavior is undefined.
   * - .. _CIB_shadow_dir:

       .. index::
          single: CIB_shadow_dir
          single: environment variable; CIB_shadow_dir

       CIB_shadow_dir
     - |CRM_CONFIG_DIR| if the current user is ``root`` or |CRM_DAEMON_USER|;
       otherwise ``$HOME/.cib`` if :ref:`$HOME <HOME>` is set; otherwise
       ``$TMPDIR/.cib`` if :ref:`$TMPDIR <TMPDIR>` is set to an absolute path;
       otherwise ``/tmp/.cib``
     - If set, shadow files are created in this directory. Ignored if
       :ref:`CIB_shadow <CIB_shadow>` is not set.
   * - .. _CIB_user:

       .. index::
          single: CIB_user
          single: environment variable; CIB_user

       CIB_user
     - |CRM_DAEMON_USER| if used with :ref:`CIB_port <CIB_port>`, or the current
       effective user otherwise
     - If used with :ref:`CIB_port <CIB_port>`, connect to
       :ref:`$CIB_server <CIB_server>` as this user. Must be part of the
       |CRM_DAEMON_GROUP| group on :ref:`$CIB_server <CIB_server>`. Otherwise
       (without :ref:`CIB_port <CIB_port>`), this is used only for ACL and
       display purposes.
   * - .. _EDITOR:

       .. index::
          single: EDITOR
          single: environment variable; EDITOR

       EDITOR
     -
     - Text editor to use for editing shadow files. Required for the ``--edit``
       command of :ref:`crm_shadow <crm_shadow>`.
   * - .. _HOME:

       .. index::
          single: HOME
          single: environment variable; HOME

       HOME
     - Current user's home directory as configured in the passwd database, if an
       entry exists
     - Used to create a default :ref:`CIB_shadow_dir <CIB_shadow_dir>` for non-
       privileged users.
   * - .. _PE_fail:

       .. index::
          single: PE_fail
          single: environment variable; PE_fail

       PE_fail
     - 0
     - Advanced use only: A dummy graph action with action ID matching this
       option will be marked as failed. Primarily for developer use with
       scheduler simulations.
   * - .. _PS1:

       .. index::
          single: PS1
          single: environment variable; PS1

       PS1
     -
     - The shell's primary prompt string. Used by
       :ref:`crm_shadow <crm_shadow>`: set to indicate that the user is in an
       interactive shadow CIB session, and checked to determine whether the user
       is already in an interactive session before creating a new one.
   * - .. _SHELL:

       .. index::
          single: SHELL
          single: environment variable; SHELL

       SHELL
     -
     - Absolute path to a shell. Used by :ref:`crm_shadow <crm_shadow>` when
       launching an interactive session.
   * - .. _TMPDIR:

       .. index::
          single: TMPDIR
          single: environment variable; TMPDIR

       TMPDIR
     - /tmp
     - Directory for temporary files. If not an absolute path, the default is
       used instead.
