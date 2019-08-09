FROM ubuntu:18.04

MAINTAINER Harry Kodden <harry.kodden@surfnet.nl>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y apt-utils

RUN apt-get install -y git
RUN apt-get install -y build-essential

RUN apt-get install -y libffi-dev
RUN apt-get install -y libssl-dev
RUN apt-get install -y libxml2-dev
RUN apt-get install -y libxmlsec1-dev

RUN apt-get install -y python-pip
RUN apt-get install -y python-dev
RUN pip install 'cryptography>=2.3'
RUN pip install 'pyasn1>=0.4.6'

RUN apt-get install -y rsyslog
RUN apt-get install -y openssh-server
RUN apt-get install -y libpam-python

RUN sed -e "s|# Standard Un\*x authentication.|auth required pam_env.so\nauth sufficient pam_python.so /pam-websso/pam_websso.py|" -i /etc/pam.d/sshd
RUN sed -e "s|# Standard Un\*x session setup and teardown.|session required pam_mkhomedir.so umask=0022 skel=/etc/skel|" -i /etc/pam.d/sshd
RUN sed -e "s|^#\?SyslogFacility.*|SyslogFacility AUTH|" -i /etc/ssh/sshd_config
RUN sed -e "s|^#\?LogLevel.*|LogLevel INFO|" -i /etc/ssh/sshd_config
RUN sed -e "s|^#\?ChallengeResponseAuthentication .*|ChallengeResponseAuthentication yes|" -i /etc/ssh/sshd_config
RUN sed -e "s|^#\?PasswordAuthentication.*|PasswordAuthentication no|" -i /etc/ssh/sshd_config
RUN sed -e "s|^#\?PermitRootLogin.*|PermitRootLogin no|" -i /etc/ssh/sshd_config
RUN ssh-keygen -A
RUN mkdir -p /run/sshd

RUN apt-get install -y python-setuptools
RUN git clone https://github.com/SURFscz/pam-websso.git
WORKDIR pam-websso
RUN python setup.py install

EXPOSE 22 80

CMD ["tail", "-f", "/dev/null"]
