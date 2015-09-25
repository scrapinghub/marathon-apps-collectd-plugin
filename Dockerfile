FROM alpine:3.1

RUN apk --update add collectd collectd-python py-pip

ADD requirements.txt /
RUN pip install -r /requirements.txt

# Add default collectd template
ADD collectd.conf.tpl /etc/collectd/collectd.conf.tpl

# Add metrics collector
ADD collectd_marathon_plugin.py /usr/share/collectd/plugins/marathon/

# Add metrics db
ADD metrics.db /usr/share/collectd/plugins/marathon/

# Add entrypoint script
ADD bin/run.sh /run.sh
ENTRYPOINT ["/run.sh"]
