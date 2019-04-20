#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
The script will publish metrics on port 9127 at `/metrics` path.

Uses the same environment variables as the collectd script

export DOCKER_REMOTE_HOST=127.0.0.1
export DOCKER_REMOTE_PORT=2376
export DOCKER_SSL_CLIENT_CERT=/client.cer
export DOCKER_SSL_CLIENT_KEY=/client.key
export DOCKER_SSL_CA_CERT=/ca.cer

pip install docker prometheus_client flask

"""

import argparse
import logging
import sys
import os
import threading
from functools import lru_cache

import docker

from flask import Flask

import prometheus_client.core as prometheus
from prometheus_client import generate_latest, PROCESS_COLLECTOR


def async_call(function, *args, **kwargs):
    """
    Execute function in a thread
    """
    task = threading.Thread(
        target=function,
        name=function.__name__,
        args=args,
        kwargs=kwargs
    )
    task.daemon = False
    task.start()
    return task


def ns_to_sec(value):
    """
    Converts a value in nanoseconds to seconds.
    """
    return value / 1000000000.0


class BaseStatsCollector(object):

    def __init__(self):
        self._stats = {}

    def add_stat(self, stat_id, stat_type, stat_desc=None, labels=None):
        self._stats[stat_id] = stat_type(stat_id, stat_desc, labels=labels)

    def get_stat(self, stat_id):
        return self._stats[stat_id]

    def get_stats(self):
        return self._stats.values()

    def add_gauge(self, gauge_id, gauge_desc=None, labels=None):
        return self.add_stat(gauge_id, prometheus.GaugeMetricFamily,
                             gauge_desc, labels=labels)

    def add_counter(self, counter_id, counter_desc=None, labels=None):
        return self.add_stat(counter_id, prometheus.CounterMetricFamily,
                             counter_desc, labels=labels)

    def cleanup_samples(self):
        for stat in self.get_stats():
            stat.samples = []

    def collect(self):
        """Return the stats"""
        return self._stats.values()


class NetworkStatsCollector(BaseStatsCollector):

    # Which metric names are associated with each
    # of the fields in the stat json
    METRIC_NAME_TO_DOCKER_STAT = {
        "container_network_receive_bytes_total": "rx_bytes",
        "container_network_receive_errors_total": "rx_errors",
        "container_network_receive_packets_total": "rx_packets",
        "container_network_receive_packets_dropped_total": "rx_dropped",
        "container_network_transmit_bytes_total": "tx_bytes",
        "container_network_transmit_errors_total": "tx_errors",
        "container_network_transmit_packets_total": "tx_packets",
        "container_network_transmit_packets_dropped_total": "tx_dropped",
    }

    def __init__(self):
        super().__init__()
        labels = ["interface", "appid", "taskid"]
        self.add_counter("container_network_receive_bytes_total",
                         "Cumulative count of bytes received", labels)
        self.add_counter("container_network_receive_errors_total",
                         "Cumulative count of errors encountered while receiving", labels)
        self.add_counter("container_network_receive_packets_total",
                         "Cumulative count of packets received", labels)
        self.add_counter("container_network_receive_packets_dropped_total",
                         "Cumulative count of packets dropped while receiving", labels)
        self.add_counter("container_network_transmit_bytes_total",
                         "Cumulative count of bytes transmitted", labels)
        self.add_counter("container_network_transmit_errors_total",
                         "Cumulative count of errors encountered while transmitting", labels)
        self.add_counter("container_network_transmit_packets_total",
                         "Cumulative count of packets transmitted", labels)
        self.add_counter("container_network_transmit_packets_dropped_total",
                         "Cumulative count of packets dropped while transmitting", labels)

    def add_container(self, appid, taskid, stats):
        nets = stats.get("networks", [])
        for net in nets:
            for metric_name in self.METRIC_NAME_TO_DOCKER_STAT:
                stat_id = self.METRIC_NAME_TO_DOCKER_STAT[metric_name]
                self.get_stat(metric_name).add_metric([net, appid, taskid], nets[net][stat_id])


class MemoryStatsCollector(BaseStatsCollector):

    # Which metric names are associated with each
    # of the fields in the stat json
    METRIC_NAME_TO_DOCKER_STAT = {
        "container_memory_cache": "cache",
        "container_memory_rss": "rss",
        "container_memory_swap": "swap",
    }

    def __init__(self):
        super().__init__()
        labels = ["appid", "taskid"]
        self.add_gauge("container_memory_cache", "Number of bytes of page cache memory.", labels)
        self.add_gauge("container_memory_rss", "Size of RSS in bytes.", labels)
        self.add_gauge("container_memory_swap", "Container swap usage in bytes.", labels)
        self.add_gauge("container_memory_usage_bytes", "Current memory usage in bytes.", labels)
        self.add_gauge("container_memory_usage_percent", "Percentage of memory usage.", labels)

    def add_container(self, appid, taskid, stats):
        mem = stats["memory_stats"]
        for metric_name in self.METRIC_NAME_TO_DOCKER_STAT:
            stat_id = self.METRIC_NAME_TO_DOCKER_STAT[metric_name]
            self.get_stat(metric_name).add_metric([appid, taskid], mem["stats"][stat_id])
        # memory_usage needs special treatment
        self.get_stat("container_memory_usage_bytes").add_metric([appid, taskid], mem["usage"])

        mem_percent = (mem["usage"] / mem["limit"]) * 100
        self.get_stat("container_memory_usage_percent").add_metric([appid, taskid], mem_percent)


class CPUStatsCollector(BaseStatsCollector):

    def __init__(self):
        super().__init__()
        labels = ["appid", "taskid"]
        self.add_counter("container_cpu_system_seconds_total",
                         "Cumulative system cpu time consumed in seconds.", labels)
        self.add_counter("container_cpu_kernel_seconds_total",
                         "Cumulative kernel cpu time consumed in seconds.", labels)
        self.add_counter("container_cpu_user_seconds_total",
                         "Cumulative user cpu time consumed in seconds.", labels)
        self.add_counter("container_cpu_usage_seconds_total",
                         "Cumulative cpu time consumed per cpu in seconds.", ["cpu"] + labels)
        self.add_gauge("container_cpu_usage_percent",
                       "Percentage of cpu time used.", labels)

    def add_container(self, appid, taskid, stats):
        cpu_stats = stats["cpu_stats"]
        pre_cpu_stats = stats["precpu_stats"]
        cpu_usage = cpu_stats["cpu_usage"]

        # system, kernel and user usage
        self.get_stat("container_cpu_system_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_stats["system_cpu_usage"]))
        self.get_stat("container_cpu_kernel_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_usage["usage_in_kernelmode"]))
        self.get_stat("container_cpu_user_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_usage["usage_in_usermode"]))

        # Per cpu metrics
        for cpu, value in enumerate(cpu_usage["percpu_usage"]):
            cpu_label = "cpu{:02d}".format(cpu)
            self.get_stat("container_cpu_usage_seconds_total").add_metric(
                [cpu_label, appid, taskid],
                ns_to_sec(value))

        # Calculate percent usage
        # https://github.com/moby/moby/blob/8a03eb0b6cc56879eada4a928c6314f33001fc83/integration-cli/docker_api_stats_test.go#L40
        cpu_percent = 0.0
        cpu_delta = cpu_usage["total_usage"] - pre_cpu_stats["cpu_usage"]["total_usage"]
        sys_delta = cpu_stats["system_cpu_usage"] - pre_cpu_stats["system_cpu_usage"]
        if sys_delta > 0 and cpu_delta > 0:
            cpu_percent = (cpu_delta / sys_delta) * len(cpu_usage["percpu_usage"]) * 100.0
        self.get_stat("container_cpu_usage_percent").add_metric([appid, taskid], cpu_percent)


class LRUCacheStatsCollector(BaseStatsCollector):

    def __init__(self, cached_method):
        super().__init__()
        self.add_counter("exporter_details_cache_hits_total", "Cumulative cache hits.")
        self.add_counter("exporter_details_cache_misses_total", "Cumulative cache misses.")
        self.add_gauge("exporter_details_cache_max_size", "Maximum size of the cache.")
        self.add_gauge("exporter_details_cache_current_size", "Current cache utilization.")

        self._cached_method = cached_method

    def collect(self):
        # Remove old data
        self.cleanup_samples()
        # Get cache info
        info = self._cached_method.cache_info()

        self.get_stat("exporter_details_cache_hits_total").add_metric([], info.hits)
        self.get_stat("exporter_details_cache_misses_total").add_metric([], info.misses)
        self.get_stat("exporter_details_cache_max_size").add_metric([], info.maxsize)
        self.get_stat("exporter_details_cache_current_size").add_metric([], info.currsize)

        return super().collect()


class DockerStatsCollector(object):

    def __init__(self, host, port, client_cert=None, client_key=None, ca_cert=None):
        self.logger = logging.getLogger(__name__)
        self._client = None
        self._subcollectors = [
            NetworkStatsCollector(),
            MemoryStatsCollector(),
            CPUStatsCollector()
        ]
        self._lock = threading.Lock()

        # Establish the initial connection to the daemon
        self._connect(host, port, client_cert, client_key, ca_cert)

    def _connect(self, host, port, client_cert=None, client_key=None, ca_cert=None):
        """
        Connects to the docker daemon.

        Returns a client connection to the docker daemon running on `host`:`port`. If
        `client_cert` and `client_key` are given, the connection is established using
        https.
        """
        tls_config = None
        proto = "http"
        if client_cert and client_key:
            proto = "https"
            tls_config = docker.tls.TLSConfig(client_cert=(client_cert, client_key),
                                              verify=ca_cert)

        # Create connection
        docker_url = "{proto}://{host}:{port}/".format(proto=proto, host=host, port=port)
        self._client = docker.DockerClient(base_url=docker_url, version="1.21",
                                           timeout=5, tls=tls_config)
        # Check connection
        self.logger.debug("Connecting to docker daemon...")
        info = self._client.version()
        self.logger.debug("Connected to: %s (%s)", docker_url, info)

    def _fetch_stats(self, appid, taskid, container_id):
        """
        Process stats for `container_id`
        """
        stats = self._client.api.stats(container_id, decode=True, stream=False)

        # Add this container's stats to each of the sub-collectors
        self.add_container(appid, taskid, stats)

    @lru_cache(maxsize=32)
    def _details(self, container_id):
        """
        Return the details for `container_id`
        """
        self.logger.debug("Getting container info for %s", container_id)
        return self._client.api.inspect_container(container_id)

    def cache_info(self):
        """
        Returns the cache info.
        """
        return self._details.cache_info()

    def add_container(self, appid, taskid, stats):
        self.logger.info("Adding container to stats collector: %s:%s", appid, taskid)
        with self._lock:
            for collector in self._subcollectors:
                try:
                    collector.add_container(appid, taskid, stats)
                except Exception:
                    self.logger.exception("[%s] Error parsing stats: %s", str(collector), stats)

    def cleanup_samples(self):
        self.logger.info("Cleaning up samples")
        with self._lock:
            for collector in self._subcollectors:
                collector.cleanup_samples()

    def collect(self):
        """
        Collect stats from docker daemon and return metrics.
        """
        threads = []

        # Erase previous samples
        self.cleanup_samples()

        # Get the running containers at this moment
        for container in self._client.api.containers(all=False):
            # Get the details of the container (cached for speed)
            cid = container["Id"]
            details = self._details(cid)
            self.logger.debug("Processing container: %s", cid)

            # Get appid and taskid from environment configuration
            appid = taskid = None
            for env_var in details.get("Config", {}).get("Env", []):
                key, value = env_var.split("=", 1)
                if key == "MESOS_TASK_ID":
                    appid, taskid = value.split(".", 1)
                    # Use short taskid
                    taskid = taskid[:8]

            # If we don't have both values we can't continue
            if appid and taskid:
                threads.append(async_call(self._fetch_stats, appid, taskid, cid))
            else:
                self.logger.info("Can't calculate 'appid' or 'taskid', ignoring container: %s", cid)

        # Wait for all _fetch_stats to finish
        for thread in threads:
            thread.join(5)
        self.logger.debug("All metrics collected")

        # Return all the metrics
        for metrics in self._subcollectors:
            for metric in metrics.collect():
                yield metric


def main():
    """
    Start metrics exporter
    """
    argp = argparse.ArgumentParser()
    argp.add_argument("--listen-host", action="store",
                      default="127.0.0.1", help="Host address on which to expose metrics.")
    argp.add_argument("--listen-port", action="store", default=9127,
                      type=int, help="Port on which to expose metrics.")
    argp.add_argument("--telemetry-path", action="store", default="/metrics",
                      help="Path under which to expose metrics.")
    argp.add_argument('--verbose', action='store_true',
                      help='Enable verbose logging')
    args = argp.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level,
                        format="[%(asctime)s: %(levelname)s/%(name)s] "
                               "[%(threadName)s] %(message)s")

    # Register docker stats collector
    collector = DockerStatsCollector(host=os.environ.get("DOCKER_REMOTE_HOST", "127.0.0.1"),
                                     port=os.environ.get("DOCKER_REMOTE_PORT", "2376"),
                                     client_cert=os.environ.get("DOCKER_SSL_CLIENT_CERT"),
                                     client_key=os.environ.get("DOCKER_SSL_CLIENT_KEY"),
                                     ca_cert=os.environ.get("DOCKER_SSL_CA_CERT"))
    prometheus.REGISTRY.register(collector)

    # Register cache stats collector
    prometheus.REGISTRY.register(LRUCacheStatsCollector(collector))

    # Remove process collector (added by default)
    prometheus.REGISTRY.unregister(PROCESS_COLLECTOR)

    app = Flask(__name__)

    @app.route("/")
    def root():
        return ("<html>" +
                "<head><title>Task Exporter</title></head>"
                "<body>"
                "<h1>Task Exporter</h1>"
                "<p><a href=\"" + args.telemetry_path + "\">Metrics</a></p>"
                "</body>"
                "</html>\n")

    @app.route(args.telemetry_path)
    def metrics():
        return generate_latest()

    app.run(host=args.listen_host, port=args.listen_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
