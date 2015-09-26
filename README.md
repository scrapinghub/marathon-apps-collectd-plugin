# marathon-collectd-plugin

A [Marathon](https://github.com/mesosphere/marathon) plugin for [collectd](http://collectd.org)
using [docker-py](https://github.com/docker/docker-py) and collectd's
[Python plugin](http://collectd.org/documentation/manpages/collectd-python.5.shtml).

Based on the work of: [Docker CollectD Plugin](https://github.com/lebauce/docker-collectd-plugin)

This uses the new stats API (https://github.com/docker/docker/pull/9984)
introduced by Docker 1.5.

The following container stats are reported for each marathon app container:

* Network bandwidth
* Memory usage
* CPU usage
* Block IO


## Environment variables

* `COLLECTD_HOST` - host to use in metric name, defaults to the value of `DOCKER_REMOTE_HOST`.
* `COLLECTD_INTERVAL` - metric update interval in seconds, defaults to `10`.
* `GRAPHITE_HOST` - host where carbon is listening for data.
* `GRAPHITE_PORT` - port where carbon is listening for data, `2003` by default.
* `GRAPHITE_PREFIX` - prefix for metrics in graphite, `collectd.` by default.
* `DOCKER_REMOTE_HOST` - docker daemon host to monitor.
* `DOCKER_REMOTE_PORT` - docker daemon port number, defaults to `2376`.
* `DOCKER_SSL_CLIENT_KEY` - SSL client key
* `DOCKER_SSL_CLIENT_CERT` - SSL client cert
* `DOCKER_SSL_CA_CERT` - SSL server CA
