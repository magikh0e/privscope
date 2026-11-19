# privscope test lab: a DELIBERATELY MISCONFIGURED Debian container.
#
# Every weakness below is planted so the Linux collector + rules can be checked end to end
# against known answers (see tests/lab/expected-*.txt). Never base anything real on this
# image. The collector itself is mounted read-only at run time, not baked in:
#
#   docker build -t privscope-lab tests/lab
#   docker run --rm -u alice -v "<repo>/collector:/privscope:ro" -v "<out>:/out" privscope-lab \
#       sh /privscope/privscope-collect.sh -o /out/lab-alice.json
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/sh alice \
 && useradd -m -u 1001 -s /bin/sh bob \
 && groupadd -f docker \
 && usermod -aG docker,adm alice

# setuid program that can run commands
RUN chmod u+s /usr/bin/find

# root cron job whose script anyone can overwrite, and one whose program is missing in a
# folder anyone can create subfolders in
RUN mkdir -p /opt/app/bin /etc/cron.d \
 && printf '#!/bin/sh\ntrue\n' > /opt/app/bin/backup.sh && chmod 777 /opt/app/bin/backup.sh \
 && echo '0 2 * * * root /opt/app/bin/backup.sh' > /etc/cron.d/backup \
 && echo '@hourly root /srv/gone/run.sh' > /etc/cron.d/stale \
 && chmod 777 /srv

# systemd unit anyone can edit
RUN mkdir -p /etc/systemd/system \
 && cp /bin/true /opt/app/bin/server \
 && printf '[Service]\nExecStart=/opt/app/bin/server\n' > /etc/systemd/system/app.service \
 && chmod 666 /etc/systemd/system/app.service

# file capability that leads to root
RUN cp /bin/sleep /usr/local/bin/capsleep && setcap cap_setuid+ep /usr/local/bin/capsleep

# passwordless sudo for a program that can run commands, a wildcard rule, and LD_PRELOAD kept
RUN echo 'alice ALL=(root) NOPASSWD: /usr/bin/find, /bin/cat /var/log/*' > /etc/sudoers.d/alice \
 && echo 'Defaults env_keep += "LD_PRELOAD"' > /etc/sudoers.d/env \
 && chmod 440 /etc/sudoers.d/alice /etc/sudoers.d/env

# readable copy of the password hashes; another user's readable (dummy) SSH key
RUN mkdir -p /var/backups && cp /etc/shadow /var/backups/shadow.bak && chmod 644 /var/backups/shadow.bak \
 && mkdir -p /home/bob/.ssh && echo 'dummy, not a key' > /home/bob/.ssh/id_rsa \
 && chown -R bob:bob /home/bob && chmod 755 /home/bob /home/bob/.ssh && chmod 644 /home/bob/.ssh/id_rsa

# world-writable folder in root's PATH, writable shell startup folder, NFS root squash off,
# world-writable library folder in the loader configuration
RUN mkdir -p /opt/tools /opt/lib && chmod 777 /opt/tools /opt/lib \
 && echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/tools"' > /etc/environment \
 && chmod 777 /etc/profile.d \
 && echo '/srv *(rw,no_root_squash)' > /etc/exports \
 && echo /opt/lib > /etc/ld.so.conf.d/opt.conf
