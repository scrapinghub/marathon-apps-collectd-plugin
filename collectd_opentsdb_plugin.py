import os
import potsdb
import collectd
import threading


class OpenTSDBExportPlugin:

    def __init__(self):
        self._writers = {}

    def configure_callback(self, conf):
        for node in conf.children:
            key = node.key.lower()
            value = node.values[0]
            if key == 'host':
                self._opentsdb_host = value
            elif key == 'port':
                self._opentsdb_port = value
        if (not hasattr(self, '_opentsdb_host') or
                not hasattr(self, '_opentsdb_port')):
            raise Exception("OpenTSDB export plugin is not configured")
        collectd.info("Configured OpenTSDB export plugin (%s:%s)" %
                      (self._opentsdb_host, self._opentsdb_port))

    def write_callback(self, vl):
        writer = self._get_writer()
        metric_name = '{}.{}'.format(vl.type, vl.type_instance).strip('.')
        tags = {'timestamp': vl.time}
        if vl.plugin_instance.startswith('kumo.'):
            project, spider, job = vl.plugin_instance.split('.')[1:]
            tags.update({'project': project,
                         'spider': spider,
                         'job': job,
                         'task': vl.plugin_instance[5:]})
        for value in vl.values:
            if isinstance(value, (float, int)):
                writer.send(metric_name, value, **tags)

    def shutdown_callback(self):
        for writer in self._writers.values():
            writer.wait()
        collectd.info("Shutdown-ed OpenTSDB export plugin.")

    def _get_writer(self):
        thread_id = threading.current_thread().ident
        if not thread_id in self._writers:
            self._writers[thread_id] = potsdb.Client(
                host=self._opentsdb_host,
                port=self._opentsdb_port,
                mps=100, check_host=False)
        return self._writers[thread_id]


if __name__ == '__main__':
    print "OpenTSDB export plugin is called as a python script"
else:
    try:
        plugin = OpenTSDBExportPlugin()
        collectd.register_config(plugin.configure_callback)
        collectd.register_write(plugin.write_callback, name='write_opentsdb')
        collectd.register_shutdown(plugin.shutdown_callback)
        print "OpenTSDB export plugin is registered."
    except Exception as ex:
        print "OpenTSDB export plugin exception: %s" % ex
