Hostname "{{ COLLECTD_HOST | default(DOCKER_REMOTE_HOST) }}"

FQDNLookup false
Interval {{ COLLECTD_INTERVAL | default(10) }}
Timeout 2
ReadThreads 5

LoadPlugin "logfile"
<Plugin "logfile">
  LogLevel "info"
  File "/var/log/collectd_plugin.log"
  Timestamp true
</Plugin>

LoadPlugin "csv"
<Plugin "csv">
  DataDir "/var/log/collectd.csv"
  StoreRates true
</Plugin>

LoadPlugin write_graphite
<Plugin "write_graphite">
    <Carbon>
        Host "{{ GRAPHITE_HOST }}"
        Port "{{ GRAPHITE_PORT | default("2003") }}"
        Protocol "tcp"
        Prefix "{{ GRAPHITE_PREFIX | default("collectd.") }}"
        EscapeCharacter "."
        StoreRates true
        AlwaysAppendDS false
        SeparateInstances true
    </Carbon>
</Plugin>

TypesDB "/usr/share/collectd/plugins/mesos/metrics.db"
<LoadPlugin "python">
    Globals true
</LoadPlugin>

<Plugin "python">
    ModulePath "/usr/share/collectd/plugins/mesos"

    Import "collectd_mesos_plugin"
    <Module "collectd_mesos_plugin">
        Host "{{ DOCKER_REMOTE_HOST }}"
        Port {{ DOCKER_REMOTE_PORT | default(2376) }}
        CertKey "{{ DOCKER_SSL_CLIENT_KEY | default(False) }}"
        CertCert "{{ DOCKER_SSL_CLIENT_CERT | default(False) }}"
        CertCA "{{ DOCKER_SSL_CA_CERT | default(False) }}"
    </Module>
</Plugin>

LoadPlugin "match_regex"
<Chain "PostCache">
    <Rule>
        <Match regex>
            Plugin "collectd.*.mesos-tasks.kumo.*"
        </Match>
        <Target write>
            Plugin "csv"
        </Target>
        Target stop
    </Rule>
    Target "write"
</Chain>
