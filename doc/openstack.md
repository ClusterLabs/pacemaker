# OpenStack CTS setup

If we ever get the OpenStack networking sorted out to the point where
Corosync can use it, this documents the process of getting a Pacemaker
cluster set up for testing with CTS.

## Prep

Install python-novaclient

    yum install -y python-novaclient

Export your OpenStack credentials

    export OS_REGION_NAME=...
    export OS_TENANT_NAME=...
    export OS_AUTH_URL=...
    export OS_USERNAME=... 
    export OS_PASSWORD=...

Allocate 5 floating IPs.  For the purposes of the setup instructions
(and probably your sanity), they need to be consecutive and should
ideally start with a multiple of 10. Below we will assume
10.16.16.60-64

    for n in 1 2 3 4 5; do nova floating-ip-create; done

Create some variables based on the IP addresses nova created for you:

    export IP_BASE=10.16.16.60

and a function for calculating offsets

    function nth_ipaddr() {
        echo $IP_BASE | awk -F. -v offset=$1 '{ printf "%s.%s.%s.%s\n", $1, $2, $3, $4 + offset }' 
    }

Upload a public key that we can use to log into the images we create.
I created one especially for cluster testing and left it without a password.

    nova keypair-add --pub-key ~/.ssh/cluster Cluster

Punch a hole in the firewall for SSH access and ping

    nova secgroup-add-rule default tcp 23 23 10.0.0.0/8
    nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0

Add the CTS master to /etc/hosts

    cat << EOF >> /etc/hosts
    `nth_ipaddr 0` cts-master
    EOF

Create helper scripts on a local host

    cat << END > ./master.sh
    
    echo export OS_REGION_NAME=$OS_REGION_NAME >> ~/.bashrc
    echo export OS_TENANT_NAME=$OS_TENANT_NAME >> ~/.bashrc
    echo export OS_AUTH_URL=$OS_AUTH_URL >> ~/.bashrc
    echo export OS_USERNAME=$OS_USERNAME >> ~/.bashrc
    echo export OS_PASSWORD=$OS_PASSWORD >> ~/.bashrc
    
    function nth_ipaddr() {
        echo $IP_BASE | awk -F. -v offset=\$1 '{ printf "%s.%s.%s.%s\n", \$1, \$2, \$3, \$4 + offset }' 
    }
    
    yum install -y python-novaclient git screen pdsh pdsh-mod-dshgroup
    
    git clone git://github.com/beekhof/fence_openstack.git
    ln -s /root/fence_openstack/fence_openstack /sbin

    mkdir -p  /root/.dsh/group/
    echo export cluster_name=openstack >> ~/.bashrc
    
    rm -f /root/.dsh/group/openstack
    for n in 1 2 3 4; do
    	echo "cluster-\$n" >> /root/.dsh/group/openstack
        echo \`nth_ipaddr \$n\` cluster-\$n >> /etc/hosts
    done
    
    cat << EOF >> /root/.ssh/config
        Host \`echo $IP_BASE | awk -F. '{ printf "%s.%s.%s.*", \$1, \$2, \$3 }'\`
        User       root
        IdentityFile ~/.ssh/cluster

        Host cts-master
        User       root
        IdentityFile ~/.ssh/cluster
    EOF
    
    END

Another script:

    cat << EOF > fix-guest.sh
    #!/bin/bash
    # Re-allow root to log in
    sudo sed -i s/.*ssh-/ssh-/ /root/.ssh/authorized_keys
    EOF
    
## CTS master (Fedora-17)

Create and update the master

    nova boot --poll --image "Fedora 17" --key_name Cluster --flavor m1.tiny cts-master
    nova add-floating-ip cts-master `nth_ipaddr 0`

Some images do not allow root to log in by default and insist on a 'stack' user.
Disable this "feature".

    scp fix-guest.sh stack@cts-master:
    ssh -l stack -t cts-master -- bash ./fix-guest.sh

Now we can set up the CTS master with the script we created earlier:

    scp ~/.ssh/cluster root@cts-master:.ssh/id_rsa
    scp master.sh root@cts-master:
    ssh root@cts-master -- bash ./master.sh

## Create Guest Base Image

Create a guest that we can tweak

    nova boot --poll --image "Fedora 18 Alpha" --key_name Cluster --flavor m1.tiny TempGuest
    nova add-floating-ip TempGuest `nth_ipaddr 1`
    scp fix-guest.sh stack@`nth_ipaddr 1`:

Create snapshot with our changes called Fedora-18-base

    nova image-create --poll TempGuest Fedora-18-base

Release the IP and delete the temporary guest

    nova remove-floating-ip TempGuest `nth_ipaddr 1`
    nova delete TempGuest

### Create Guests

First create the guests

    for n in 1 2 3 4; do
       nova boot --poll --image Fedora-18-base --key_name Cluster --flavor m1.tiny cluster-$n;
       nova add-floating-ip cluster-$n `nth_ipaddr $n`
    done

Then wait for everything to settle

    sleep 10

Now you can fix them 

    for n in 1 2 3 4; do
       ssh -l stack -t `nth_ipaddr $n` -- bash ./fix-guest.sh;
       scp /etc/hosts root@`nth_ipaddr $n`:/etc/;
    done

## Run CTS

### Prep

Switch to the CTS master

    ssh -l root cts-master

Clone Pacemaker for the latest version of CTS:

    git clone git://github.com/ClusterLabs/pacemaker.git
    echo 'export PATH=\$PATH:/root/pacemaker/extra::/root/pacemaker/cts' >> ~/.bashrc    

Now set up CTS to run from the local source tree 

    cts local-init

Configure a cluster (this will install all needed packages and configure corosync on the guests in the $cluster_name group)

    cluster-init -g openstack --yes --unicast fedora-17  

### Run

    cd pacemaker
    cts clean run --stonith openstack