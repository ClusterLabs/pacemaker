.. _sample-corosync-configuration:

Sample Corosync Configuration
---------------------------------

.. topic:: Sample ``corosync.conf`` for two-node cluster created by ``pcs``.

    .. code-block:: none

        totem {
            version: 2
            cluster_name: mycluster
            transport: knet
            crypto_cipher: aes256
            crypto_hash: sha256
            cluster_uuid: e592f61f916943978bdf7c046a195980
        }

        nodelist {
            node {
                ring0_addr: pcmk-1
                name: pcmk-1
                nodeid: 1
            }

            node {
                ring0_addr: pcmk-2
                name: pcmk-2
                nodeid: 2
            }
        }

        quorum {
            provider: corosync_votequorum
            two_node: 1
        }

        logging {
            to_logfile: yes
            logfile: /var/log/cluster/corosync.log
            to_syslog: yes
            timestamp: on
        }
