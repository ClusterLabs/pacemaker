FROM {{ base_image }}
ADD /repos /etc/yum.repos.d/
#ADD /rpms /root/
#RUN yum install -y /root/*.rpm
ADD /launch_scripts /root/
ADD /bin_files /usr/sbin/

RUN mkdir -p /root/.ssh; chmod 700 /root/.ssh
ADD authorized_keys /root/.ssh/

RUN yum install -y openssh-server net-tools pacemaker pacemaker-cts resource-agents pcs corosync which fence-agents-common sysvinit-tools
RUN mkdir -p /etc/pacemaker/
RUN echo {{ pacemaker_authkey }} > /etc/pacemaker/authkey
RUN /usr/sbin/sshd

ENTRYPOINT ["/root/launch.sh"]
