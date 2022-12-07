#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The script will publish metrics on port 9127 at `/metrics` path.
It connects to the local docker daemon using the unix socket:
    unix://var/run/docker.sock

It's possible to modify the connection details using the `DOCKER_HOST`,
`DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` environment variables as the
official docker client.

    * DOCKER_HOST: With the url to the docker daemon.
    * DOCKER_TLS_VERIFY: Flag that defines whether TLS verification should be
                         performed. Any non empty value is treated as `True`.
    * DOCKER_CERT_PATH: Path to SSL certificates to use when TLS is activated.
                        If set, the value should point to a folder where there
                        is a client certificate `cert.pem`, a client private key
                        `key.pem` and a CA certificate `ca.pem`.

"""

import argparse
import logging
import sys
import threading
import time

import docker

from datetime import datetime
from flask import Flask

import prometheus_client.core as prometheus
from prometheus_client import generate_latest, PROCESS_COLLECTOR


def ns_to_sec(value):
    """
    Converts a value in nanoseconds to seconds.
    """
    return value / 1000000000.0


def iso_datetime_to_datetime(value):
    """
    Converts ISO date time to unix timestamp
    """

    if '.' in value:
        dt, _ = value.split('.')
    else:
        dt = value.replace('Z', '')

    return datetime.fromisoformat(dt)


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

    def add_container(self, appid, taskid, stats, details):
        nets = stats.get("networks", {})
        for net in nets:
            labels = [net, appid, taskid]

            self.get_stat("container_network_receive_bytes_total").add_metric(
                labels, nets[net].get("rx_bytes", 0))
            self.get_stat("container_network_receive_errors_total").add_metric(
                labels, nets[net].get("rx_errors", 0))
            self.get_stat("container_network_receive_packets_total").add_metric(
                labels, nets[net].get("rx_packets", 0))
            self.get_stat("container_network_receive_packets_dropped_total").add_metric(
                labels, nets[net].get("rx_dropped", 0))
            self.get_stat("container_network_transmit_bytes_total").add_metric(
                labels, nets[net].get("tx_bytes", 0))
            self.get_stat("container_network_transmit_errors_total").add_metric(
                labels, nets[net].get("tx_errors", 0))
            self.get_stat("container_network_transmit_packets_total").add_metric(
                labels, nets[net].get("tx_packets", 0))
            self.get_stat("container_network_transmit_packets_dropped_total").add_metric(
                labels, nets[net].get("tx_dropped", 0))


class MemoryStatsCollector(BaseStatsCollector):

    def __init__(self):
        super().__init__()
        labels = ["appid", "taskid"]
        self.add_gauge("container_memory_cache", "Number of bytes of page cache memory.", labels)
        self.add_gauge("container_memory_rss", "Size of RSS in bytes.", labels)
        self.add_gauge("container_memory_swap", "Container swap usage in bytes.", labels)
        self.add_gauge("container_memory_usage_bytes", "Current memory usage in bytes.", labels)
        self.add_gauge("container_memory_limit_bytes", "Current memory limit in bytes.", labels)
        self.add_gauge("container_memory_usage_percent", "Percentage of memory usage.", labels)
        self.add_gauge("container_memory_usage_percent_total", "Percentage of memory usage total.", labels)

    def add_container(self, appid, taskid, stats, details):

        mem = stats.get("memory_stats", {})
        if not mem:
            return

        labels = [appid, taskid]

        self.get_stat("container_memory_usage_bytes").add_metric(labels, mem.get("usage", 0))

        mem_stats = mem.get("stats", {})

        if mem.get("limit", 0) > 0:
            self.get_stat("container_memory_limit_bytes").add_metric(labels, mem["limit"])
            # Calculate percent when limit is available
            mem_percent_total = (mem.get("usage", 0) / mem["limit"]) * 100

            if mem_stats:
                stats_cache = mem_stats.get("cache", 0)
                mem_percent = ((mem.get("usage", 0) - stats_cache) / mem["limit"]) * 100
            else:
                mem_percent = mem_percent_total

            self.get_stat("container_memory_usage_percent").add_metric(labels, mem_percent)
            self.get_stat("container_memory_usage_percent_total").add_metric(labels, mem_percent_total)

        if not mem_stats:
            return

        self.get_stat("container_memory_cache").add_metric(labels, mem_stats.get("cache", 0))
        self.get_stat("container_memory_rss").add_metric(labels, mem_stats.get("rss", 0))
        self.get_stat("container_memory_swap").add_metric(labels, mem_stats.get("swap", 0))


class StateStatsCollector(BaseStatsCollector):

    def __init__(self):
        super().__init__()
        labels = ["appid", "taskid"]
        self.add_counter("container_state_uptime", "Container uptime", labels)

    def add_container(self, appid, taskid, stats, details):

        state = details.get("State", {})
        if not state:
            return

        labels = [appid, taskid]

        if state.get("StartedAt", 0) != 0 and state.get("Running", None) is True:
            started_at = iso_datetime_to_datetime(state.get("StartedAt"))
            if datetime.now() > started_at:
                uptime = (datetime.now() - started_at).total_seconds()
            else:
                uptime = 0
        else:
            uptime = 0

        self.get_stat("container_state_uptime").add_metric(labels, uptime)


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
        self.add_gauge("container_spec_cpu_shares",
                       "Assigned CPU shares.", labels)

    def add_container(self, appid, taskid, stats, details):
        details = details or {}
        cpu_stats = stats.get("cpu_stats", {})
        if not cpu_stats:
            return

        cpu_usage = cpu_stats.get("cpu_usage", {})
        if not cpu_usage:
            return

        self.get_stat("container_cpu_system_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_stats.get("system_cpu_usage", 0)))
        self.get_stat("container_cpu_kernel_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_usage.get("usage_in_kernelmode", 0)))
        self.get_stat("container_cpu_user_seconds_total").add_metric(
            [appid, taskid],
            ns_to_sec(cpu_usage.get("usage_in_usermode", 0)))
        self.get_stat("container_spec_cpu_shares").add_metric(
            [appid, taskid],
            details.get("HostConfig", {}).get("CpuShares", 0))

        # Per cpu metrics
        for cpu, value in enumerate(cpu_usage.get("percpu_usage", [])):
            cpu_label = "cpu{:02d}".format(cpu)
            self.get_stat("container_cpu_usage_seconds_total").add_metric(
                [cpu_label, appid, taskid],
                ns_to_sec(value))

        pre_cpu_stats = stats.get("precpu_stats", {})
        if not pre_cpu_stats:
            return

        # Calculate percent usage
        # https://github.com/moby/moby/blob/8a03eb0b6cc56879eada4a928c6314f33001fc83/integration-cli/docker_api_stats_test.go#L40
        cpu_percent = 0.0

        cpu_delta = cpu_usage.get("total_usage", 0) - pre_cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        sys_delta = cpu_stats.get("system_cpu_usage", 0) - pre_cpu_stats.get("system_cpu_usage", 0)
        if sys_delta > 0 and cpu_delta > 0:
            cpu_percent = (cpu_delta / sys_delta) * len(cpu_usage.get("percpu_usage", [])) * 100.0

        self.get_stat("container_cpu_usage_percent").add_metric([appid, taskid], cpu_percent)


class ContainerStatsStream(threading.Thread):

    def __init__(self, docker_client, container_id):
        """
        ContainerStatsStream connects to the docker stats api stream
        and updates `self.latest` with the latest value of the stats.
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.client = docker_client
        self.id = container_id
        self.__stop__ = False
        self.latest = None
        self.appid = None
        self.taskid = None
        self.details = None

    def stop(self):
        """
        Stops collecting stats
        """
        self.__stop__ = True

    def run(self):
        """
        Connects to the docker stats api stream to fetch the stats of the
        container.
        """
        # Get appid and taskid from environment configuration
        self.logger.debug("Processing container: %s", self.id)
        self.details = self.client.api.inspect_container(self.id)

        self.appid = self.taskid = None
        for env_var in self.details.get("Config", {}).get("Env", []):
            key, value = env_var.split("=", 1)
            if key == "MESOS_TASK_ID":
                self.appid, self.taskid = value.split(".", 1)
                # Use short taskid
                self.taskid = self.taskid[:8]

        if self.appid and self.taskid:
            try:
                stream = self.client.api.stats(self.id, decode=True, stream=True)
                for stat in stream:
                    if self.__stop__:
                        break
                    # Save stat
                    self.latest = stat
            except Exception:
                self.logger.warning("Unable to retrieve container stats from "
                                    "docker, appid: %s, container: %s", self.appid, self.id)
        self.latest = None


class DockerStatsCollector(threading.Thread):

    def __init__(self):
        """
        DockerStatsCollector collects the stats from the running docker
        containers, it updates the list of running and stopped containers
        every second.
        """
        super().__init__(name='DockerStatsCollector')

        self.logger = logging.getLogger(__name__)
        self._client = None
        self._subcollectors = [
            NetworkStatsCollector(),
            MemoryStatsCollector(),
            CPUStatsCollector(),
            StateStatsCollector(),
        ]
        self._lock = threading.Lock()
        self.__stop__ = False
        self.streams = dict()

    def stop(self):
        """
        Stops the stats collector
        """
        self.__stop__ = True

    def run(self):
        """
        Collect stats of running containers.
        """
        self._client = docker.from_env(timeout=5)
        # Check connection
        self.logger.debug("Connecting to docker daemon...")
        info = self._client.version()
        self.logger.debug("Connected to: %s (%s)", self._client.api.base_url, info)

        if self.streams:
            raise Exception("Can't start running when there are running streams")

        while not self.__stop__:
            # Collect containers and their stats
            try:
                for container in self._client.api.containers(all=False):
                    # Ignore containers that we've already seen
                    cid = container["Id"]
                    if cid in self.streams:
                        continue
                    # Add container to the list of watched streams
                    self.streams[cid] = ContainerStatsStream(self._client, cid)
                    self.streams[cid].start()
            except Exception:
                self.logger.warning("Can't retrieve list of containers")
            time.sleep(1)

        self.logger.debug("Finishing collecting containers")

        # Stop all streams
        for cid in self.streams:
            self.streams[cid].stop()

        # Wait for streams to finish
        for cid in self.streams:
            self.streams[cid].join(5)

        self.logger.debug("All threads finished")

    def add_container(self, appid, taskid, stats, details):
        """
        Add the container stats belonging to appid and taskid.
        """
        self.logger.info("Adding container to stats collector: %s:%s", appid, taskid)
        with self._lock:
            for collector in self._subcollectors:
                try:
                    collector.add_container(appid, taskid, stats, details)
                except Exception:
                    self.logger.exception("[%s] Error parsing stats: %s", str(collector), stats)

    def cleanup_samples(self):
        """
        Remove samples to start from scratch.
        """
        self.logger.info("Cleaning up samples")
        with self._lock:
            for collector in self._subcollectors:
                collector.cleanup_samples()

    def collect(self):
        """
        Collect stats from docker daemon and return metrics.
        """
        to_remove = []

        # Erase previous samples
        self.cleanup_samples()

        # Get the metrics from the streams
        try:
            for cid in self.streams:
                collector = self.streams[cid]
                if collector.latest:
                    self.add_container(collector.appid, collector.taskid, collector.latest, collector.details)
                else:
                    to_remove.append(cid)
        except:
            logging.warning("New container was found during iteration over streams")

        # Return all the metrics
        for metrics in self._subcollectors:
            for metric in metrics.collect():
                yield metric

        # Stop dead containers
        for cid in to_remove:
            self.streams[cid].stop()
            self.streams.pop(cid)


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
    collector = DockerStatsCollector()
    collector.start()
    prometheus.REGISTRY.register(collector)

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

    # Wait for collector
    collector.stop()
    collector.join(5)

    return 0


if __name__ == "__main__":
    sys.exit(main())
