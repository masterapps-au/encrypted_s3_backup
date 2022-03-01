FROM ubuntu:20.04
RUN apt-get update && \
  apt-get -y upgrade && \
  DEBIAN_FRONTEND=noninteractive apt-get -y install cron tzdata python3 python3-pip && \
  rm -rf /etc/cron.*/*
COPY encrypted_s3_backup.py requirements.txt entrypoint.sh /
RUN pip3 install -r /requirements.txt && \
  chmod u+x /encrypted_s3_backup.py /entrypoint.sh
CMD ["/entrypoint.sh"]