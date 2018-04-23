# Pacemaker Cluster Test Suite (CTS)

## Purpose

Pacemaker's CTS is primarily for developers and packagers of the Pacemaker
source code, but it can be useful for users who wish to see how their cluster
will react to various situations.

CTS consists of two main parts: a set of regression tests for verifying the
functionality of particular Pacemaker components, and a cluster exerciser for
intensively testing the behavior of an entire working cluster.

The primary regression test front end is cts-regression in this directory. Run
it with the --help option to see its usage. The regression tests can be run on
any single cluster node. The cluster should be stopped on that node when
running the tests.

The rest of this document focuses on the cluster exerciser. The cluster
exerciser runs a randomized series of predefined tests on the cluster. CTS can
be run against a pre-existing cluster configuration or overwrite the existing
configuration with a test configuration.


## Requirements

* Three or more machines (one test exerciser and two or more test cluster
  machines).

* The test cluster machines should be on the same subnet and have journalling
  filesystems (ext3, ext4, xfs, etc.) for all of their filesystems other than
  /boot. You also need a number of free IP addresses on that subnet if you
  intend to test mutual IP address takeover.

* The test exerciser machine doesn't need to be on the same subnet as the test
  cluster machines.  Minimal demands are made on the exerciser machine - it
  just has to stay up during the tests.

* It helps a lot in tracking problems if all machines' clocks are closely
  synchronized. NTP does this automatically, but you can do it by hand if you
  want.

* The exerciser needs to be able to ssh over to the cluster nodes as root
  without a password challenge. Configure ssh accordingly (see the Mini-HOWTO
  at the end of this document for more details).

* The exerciser needs to be able to resolve the machine names of the
  test cluster - either by DNS or by /etc/hosts.

* CTS is not guaranteed to run on all platforms that pacemaker itself does.
  It calls commands such as service that may not be provided by all OSes.


## Preparation

Install Pacemaker (including CTS) on all machines. These scripts are
coordinated with particular versions of Pacemaker, so you need the same version
of CTS as the rest of Pacemaker, and you need the same version of
pacemaker and CTS on both the test exerciser and the test cluster machines.

You can install CTS from source, although many distributions provide
packages that include it (e.g. pacemaker-cts or pacemaker-dev).
Typically, packages will install CTS as /usr/share/pacemaker/tests/cts.

Configure cluster communications (Corosync) on the
cluster machines and verify everything works.

NOTE: Do not run the cluster on the test exerciser machine.

NOTE: Wherever machine names are mentioned in these configuration files,
they must match the machines' `uname -n` name.  This may or may not match
the machines' FQDN (fully qualified domain name) - it depends on how
you (and your OS) have named the machines.


## Run CTS

Now assuming you did all this, what you need to do is run CTSlab.py:

    python ./CTSlab.py [options] number-of-tests-to-run

You must specify which nodes are part of the cluster with --nodes, e.g.:

    --node "pcmk-1 pcmk-2 pcmk-3"

Most people will want to save the output with --outputfile, e.g.:

    --outputfile ~/cts.log

Unless you want to test your pre-existing cluster configuration, you also want:

    --clobber-cib
    --populate-resources
    --test-ip-base $IP    # e.g. --test-ip-base 192.168.9.100

and configure some sort of fencing:

    --stonith $TYPE  # e.g. "--stonith xvm" to use fence_xvm or "--stonith ssh" to use external/ssh

A complete command line might look like:

    python ./CTSlab.py --nodes "pcmk-1 pcmk-2 pcmk-3" --outputfile ~/cts.log \
        --clobber-cib --populate-resources --test-ip-base 192.168.9.100   \
        --stonith xvm 50

For more options, use the --help option.

NOTE: Perhaps more convenient way to compile a command line like above
      is to use cluster_test script that, at least in the source repository,
      sits in the same directory as this very file.

To extract the result of a particular test, run:

    crm_report -T $test


## Optional/advanced testing

### Memory testing

Pacemaker and CTS have various options for testing memory management. On the
cluster nodes, pacemaker components will use various environment variables to
control these options. How these variables are set varies by OS, but usually
they are set in the /etc/sysconfig/pacemaker or /etc/default/pacemaker file.

Valgrind is a program for detecting memory management problems (such as
use-after-free errors). If you have valgrind installed, you can enable it by
setting the following environment variables on all cluster nodes:

    PCMK_valgrind_enabled=pacemaker-attrd,cib,crmd,lrmd,pengine,stonith-ng
    VALGRIND_OPTS="--leak-check=full --trace-children=no --num-callers=25
        --log-file=/var/lib/pacemaker/valgrind-%p
        --suppressions=/usr/share/pacemaker/tests/valgrind-pcmk.suppressions
        --gen-suppressions=all"

and running CTS with these options:

    --valgrind-tests --valgrind-procs="pacemaker-attrd cib crmd lrmd pengine stonith-ng"

These options should only be set while specifically testing memory management,
because they may slow down the cluster significantly, and they will disable
writes to the CIB. If desired, you can enable valgrind on a subset of pacemaker
components rather than all of them as listed above.

Valgrind will put a text file for each process in the location specified by
valgrind's --log-file option. For explanations of the messages valgrind
generates, see http://valgrind.org/docs/manual/mc-manual.html

Separately, if you are using the GNU C library, the G_SLICE, MALLOC_PERTURB_,
and MALLOC_CHECK_ environment variables can be set to affect the library's
memory management functions.

When using valgrind, G_SLICE should be set to "always-malloc", which helps
valgrind track memory by always using the malloc() and free() routines
directly. When not using valgrind, G_SLICE can be left unset, or set to
"debug-blocks", which enables the C library to catch many memory errors
but may impact performance.

If the MALLOC_PERTURB_ environment variable is set to an 8-bit integer, the C
library will initialize all newly allocated bytes of memory to the integer
value, and will set all newly freed bytes of memory to the bitwise inverse of
the integer value. This helps catch uses of uninitialized or freed memory
blocks that might otherwise go unnoticed. Example:

    MALLOC_PERTURB_=221

If the MALLOC_CHECK_ environment variable is set, the C library will check for
certain heap corruption errors. The most useful value in testing is 3, which
will cause the library to print a message to stderr and abort execution.
Example:

    MALLOC_CHECK_=3

Valgrind should be enabled for either all nodes or none, but the C library
variables may be set differently on different nodes.


### Remote node testing

If the pacemaker_remoted daemon is installed on all cluster nodes, CTS will
enable remote node tests.

The remote node tests choose a random node, stop the cluster on it, start
pacemaker_remote on it, and add an ocf:pacemaker:remote resource to turn it
into a remote node. When the test is done, CTS will turn the node back into
a cluster node.

To avoid conflicts, CTS will rename the node, prefixing the original node name
with "remote-". For example, "pcmk-1" will become "remote-pcmk-1".

The name change may require special stonith configuration, if the fence agent
expects the node name to be the same as its hostname. A common approach is to
specify the "remote-" names in pcmk_host_list. If you use pcmk_host_list=all,
CTS will expand that to all cluster nodes and their "remote-" names.
You may additionally need a pcmk_host_map argument to map the "remote-" names
to the hostnames. Example:

    --stonith xvm --stonith-args \
    pcmk_arg_map=domain:uname,pcmk_host_list=all,pcmk_host_map=remote-pcmk-1:pcmk-1;remote-pcmk-2:pcmk-2

### Remote node testing with valgrind

When running the remote node tests, the pacemaker components on the cluster
nodes can be run under valgrind as described in the "Memory testing" section.
However, pacemaker_remote cannot be run under valgrind that way, because it is
started by the OS's regular boot system and not by pacemaker.

Details vary by system, but the goal is to set the VALGRIND_OPTS environment
variable and then start pacemaker_remoted by prefixing it with the path to
valgrind.

The init script and systemd service file provided with pacemaker_remote will
load the pacemaker environment variables from the same location used by other
pacemaker components, so VALGRIND_OPTS will be set correctly if using one of
those.

For an OS using systemd, you can override the ExecStart parameter to run
valgrind. For example:

    mkdir /etc/systemd/system/pacemaker_remote.service.d
    cat >/etc/systemd/system/pacemaker_remote.service.d/valgrind.conf <<EOF
    [Service]
    ExecStart=
    ExecStart=/usr/bin/valgrind /usr/sbin/pacemaker_remoted
    EOF

### Container testing

If the --container-tests option is given to CTS, it will enable
testing of LXC resources (currently only the RemoteLXC test,
which starts a remote node using an LXC container).

The container tests have additional package dependencies (see the toplevel
README). Also, SELinux must be enabled (in either permissive or enforcing mode),
libvirtd must be enabled and running, and root must be able to ssh without a
password between all cluster nodes (not just from the test machine). Before
running the tests, you can verify your environment with:

    /usr/share/pacemaker/tests/cts/lxc_autogen.sh -v

LXC tests will create two containers with hardcoded parameters: a NAT'ed bridge
named virbr0 using the IP network 192.168.123.0/24 will be created on the
cluster node hosting the containers; the host will be assigned
52:54:00:A8:12:35 as the MAC address and 192.168.123.1 as the IP address.
Each container will be assigned a random MAC address starting with 52:54:,
the IP address 192.168.123.11 or 192.168.123.12, the hostname lxc1 or lxc2
(which will be added to the host's /etc/hosts file), and 196MB RAM.

The test will revert all of the configuration when it is done.


## Mini-HOWTO: Allow passwordless remote SSH connections

The CTS scripts run "ssh -l root" so you don't have to do any of your testing
logged in as root on the test machine. Here is how to allow such connections
without requiring a password to be entered each time:

* On your test exerciser, create an SSH key if you do not already have one.
  Most commonly, SSH keys will be in your ~/.ssh directory, with the
  private key file not having an extension, and the public key file
  named the same with the extension ".pub" (for example, ~/.ssh/id_rsa.pub).

  If you don't already have a key, you can create one with:

      ssh-keygen -t rsa

* From your test exerciser, authorize your SSH public key for root on all test
  machines (both the exerciser and the cluster test machines):

      ssh-copy-id -i ~/.ssh/id_rsa.pub root@$MACHINE

  You will probably have to provide your password, and possibly say
  "yes" to some questions about accepting the identity of the test machines.

  The above assumes you have a RSA SSH key in the specified location;
  if you have some other type of key (DSA, ECDSA, etc.), use its file name
  in the -i option above.

* To test, try this command from the exerciser machine for each
  of your cluster machines, and for the exerciser machine itself.

      ssh -l root $MACHINE

  If this works without prompting for a password, you're in business.
  If not, look at the documentation for your version of ssh.
