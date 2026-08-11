FROM alpine:3.22

# adduser creates a shadow-locked account by default. sshd rejects locked
# accounts even for public-key auth, so remove that lock while every password
# authentication path (including empty passwords) remains disabled in sshd.

RUN apk add --no-cache \
      curl \
      jq \
      openssh-client \
      openssh-server \
    && addgroup -g 10001 gateway \
    && adduser -D -u 10001 -G gateway -h /home/gateway -s /bin/sh gateway \
    && passwd -d gateway \
    && mkdir -p /config /data /home/gateway/.ssh /run/clawguard-ssh /run/sshd \
    && chown gateway:gateway /home/gateway /home/gateway/.ssh \
    && chmod 0700 /home/gateway/.ssh

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/clawguard-ssh-entrypoint
COPY clawguard-force-command.sh /usr/local/bin/clawguard-force-command

RUN chmod 0600 /etc/ssh/sshd_config \
    && chmod 0755 /usr/local/sbin/clawguard-ssh-entrypoint \
                  /usr/local/bin/clawguard-force-command

EXPOSE 2222

ENTRYPOINT ["/usr/local/sbin/clawguard-ssh-entrypoint"]
