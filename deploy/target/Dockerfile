FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo ca-certificates && rm -rf /var/lib/apt/lists/* && useradd -m -s /bin/bash czt-demo && mkdir -p /run/sshd /home/czt-demo/.ssh
COPY entrypoint.sh /entrypoint.sh
COPY inputrc /home/czt-demo/.inputrc
RUN chown czt-demo:czt-demo /home/czt-demo/.inputrc && chmod 0644 /home/czt-demo/.inputrc
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
