FROM alpine:3.3

RUN apk --update add collectd collectd-python py-pip

ADD requirements.txt /
RUN pip install -r /requirements.txt

# Add default collectd template
ADD collectd.conf.tpl /etc/collectd/collectd.conf.tpl

# Add metrics collector
ADD collectd_mesos_plugin.py /usr/share/collectd/plugins/mesos/
ADD collectd_opentsdb_plugin.py /usr/share/collectd/plugins/mesos/

# Add metrics db
ADD metrics.db /usr/share/collectd/plugins/mesos/

# Add entrypoint script
ADD bin/run.sh /run.sh
ENTRYPOINT ["/run.sh"]
