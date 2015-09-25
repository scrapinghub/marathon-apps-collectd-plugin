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

