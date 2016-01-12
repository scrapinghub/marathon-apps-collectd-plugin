import os
import potsdb
import collectd


class OpenTSDBExportPlugin:

    def __init__(self):
        self.metrics = None

    def configure_callback(self, conf):
        for node in conf.children:
            key = node.key.lower()
            value = node.values[0]
            if key == 'host':
                self._opentsdb_host = value
            elif key == 'port':
                self._opentsdb_port = value
        if not self._opentsdb_host or not self._opentsdb_port:
            raise Exception("OpenTSDB export plugin is not configured")
        collectd.info("Configured OpenTSDB export plugin (%s:%s)" %
                      (self._opentsdb_host, self._opentsdb_port))

    def init_callback(self):
        self.metrics = potsdb.Client(host=self._opentsdb_host,
                                     port=self._opentsdb_port,
                                     mps=100, check_host=True)
        collectd.info("Initialized OpenTSDB export plugin.")

    def write_callback(self, vl):
        if not self.metrics:
            return
        metric_name = '{}.{}'.format(vl.type, vl.type_instance)
        tags = {'timestamp': vl.time}
        if vl.plugin_instance.startswith('kumo.'):
            project, spider, job = vl.plugin_instance.split('.')[1:]
            tags.update({'project': project,
                         'spider': spider,
                         'job': job,
                         'task': vl.plugin_instance[5:]})
        for value in vl.values:
            if isinstance(value, (float, int)):
                self.metrics.send(metric_name, value, **tags)

    def shutdown_callback(self):
        if self.metrics:
            self.metrics.wait()
        collectd.info("Shutdown-ed OpenTSDB export plugin.")


if __name__ == '__main__':
    print "OpenTSDB export plugin is called as a python script"
else:
    try:
        plugin = OpenTSDBExportPlugin()
        collectd.register_config(plugin.configure_callback)
        collectd.register_init(plugin.init_callback)
        collectd.register_write(plugin.write_callback, name='write_opentsdb')
        collectd.register_shutdown(plugin.shutdown_callback)
        print "OpenTSDB export plugin is registered."
    except Exception as ex:
        print "OpenTSDB export plugin exception: %s" % ex
