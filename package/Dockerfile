#FROM registry.suse.com/suse/sle15:15.3
#FROM opensuse/leap:15.2
#FROM registry-jinan-lab.inspurcloud.cn/edgesphere/ecm-base-add-dashboard:v2.0.0
FROM devops.inspur.com:80/isg/cnos/repo/local_repo/cnos/edgesphere/edgesphere-base-add-dashboard:latest
#FROM registry-jinan-lab.inspurcloud.cn/scsciit-ecm/ecm-server-base:v2.6.3

#RUN  mkdir -p /usr/share/rancher/ui-dashboard/dashboard
#COPY v2.6.3.tar.gz /usr/share/rancher/ui-dashboard/dashboard/v2.6.3.tar.gz

#RUN cd /usr/share/rancher/ui-dashboard/dashboard && \
#    tar -xvf v2.6.3.tar.gz --strip-components=2 && \
#    ln -s dashboard/index.html ../index.html

COPY entrypoint.sh rancher /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh
COPY data.json /var/lib/rancher-data/driver-metadata/


ENV SSL_CERT_DIR /etc/rancher/ssl
VOLUME /var/lib/rancher
VOLUME /var/lib/kubelet
VOLUME /var/lib/cni
VOLUME /var/log

ENTRYPOINT ["entrypoint.sh"]