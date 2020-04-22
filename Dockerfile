FROM ubuntu:18.04
MAINTAINER Adrian Dvergsdal [atmoz.net]

ARG SYSLOG_IP=192.168.1.145
ARG SYSLOG_PORT=514

RUN apt-get install rsyslog -y && \
    sed -i -e "s/^module(load=\"imklog\"/\#module(load=\"imklog\"/g" -e "s/^\#module(load=\"imtcp\")/module(load=\"imtcp\")/g" -e "s/^\#input(type=\"imtcp\"/input(type=\"imtcp\"/g"  /etc/rsyslog.conf && \
    echo "#" > /etc/rsyslog.d/remote_syslog.conf && \
    sed -i -e "\$a\*\.\*  \@\@${SYSLOG_IP}\:${SYSLOG_PORT}" /etc/rsyslog.d/remote_syslog.conf && \
    sed -i -e "\$a\*\.\*  \/var\/log\/syslog.log" /etc/rsyslog.d/50-default.conf

# Steps done in one RUN layer:
# - Install packages
# - OpenSSH needs /var/run/sshd to run
# - Remove generic host keys, entrypoint generates unique keys
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get -y install openssh-server libpam-radius-auth && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /etc/ssh/ssh_host_*key* && \
    mkdir -p /var/run/sshd && \
	mkdir /home/upload && \
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig && \
	cp /etc/pam_radius_auth.conf /etc/pam_radius_auth.conf.orig && \
	cp /etc/pam.d/login /etc/pam.d/login.orig && \
	cp /etc/pam.d/common-auth /etc/pam.d/common-auth.orig && \
	cp /etc/pam.d/sshd /etc/pam.d/sshd.orig && \
    ssh-keygen -A

ARG client_IP=192.168.1.143:1812
ARG client_secret="testing123"
ARG client_timeout="3"

#update the pam radius file for our RADIUS server details
RUN sed -i -e "s/^other.*$/${client_IP}\t${client_secret}\t${client_timeout}\n/g" /etc/pam_radius_auth.conf
RUN chmod 0600 /etc/pam_radius_auth.conf

#update /etc/pam.d/sshd for the authentication methods for SSHD daemon
RUN sed -i -e 's/\@include common-auth/auth sufficient pam_radius_auth.so\n\#\@include common-auth/g' /etc/pam.d/sshd

#update /etc/ssh/sshd_config to ensure challenge response password responses, disable DNS, ensure if user logs in with ssh, then force to internalsftp, which kicks the user.
RUN sed -i -e "s/^ChallengeResponseAuthentication.*$/ChallengeResponseAuthentication yes/g" -e "s/\#UseDNS no/UseDNS no/g" -e "s/\^#PubkeyAuthentication.*$/PubkeyAuthentication no/g" -e "\$aForceCommand internal-sftp\n" -e 's/^\#SyslogFacility/LogLevel VERBOSE\nSyslogFacility/g' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd","-D","-e"]

#docker run \
#    -v /host/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro \
#    -v /host/id_other.pub:/home/foo/.ssh/keys/id_other.pub:ro \
#    -v /host/share:/home/foo/share \
#    -p 2222:22 -d atmoz/sftp \
#    foo::1001
#docker run --name hom99_sshd --net=vlan96 --ip=192.168.1.126 -v /volumes/hom99_dmz_www/zz_upload:/home/upload -d hom99_sshd
#docker exec -it hom99_sshd useadd -m user1
	

















