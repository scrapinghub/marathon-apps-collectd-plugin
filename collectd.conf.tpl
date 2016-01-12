Hostname "{{ COLLECTD_HOST | default(DOCKER_REMOTE_HOST) }}"

FQDNLookup false
Interval {{ COLLECTD_INTERVAL | default(10) }}
Timeout 2
ReadThreads 5

LoadPlugin write_graphite
<Plugin "write_graphite">
    <Node "carbon">
        Host "{{ GRAPHITE_HOST }}"
        Port "{{ GRAPHITE_PORT | default("2003") }}"
        Protocol "tcp"
        Prefix "{{ GRAPHITE_PREFIX | default("collectd.") }}"
        EscapeCharacter "."
        StoreRates true
        AlwaysAppendDS false
        SeparateInstances true
    </Node>
</Plugin>

TypesDB "/usr/share/collectd/plugins/mesos/metrics.db"

<LoadPlugin "python">
    Globals true
</LoadPlugin>
<Plugin "python">
    ModulePath "/usr/share/collectd/plugins/mesos"
    LogTraces true
    Import "collectd_mesos_plugin"
    Import "collectd_opentsdb_plugin"
    <Module "collectd_mesos_plugin">
        Host "{{ DOCKER_REMOTE_HOST }}"
        Port {{ DOCKER_REMOTE_PORT | default(2376) }}
        CertKey "{{ DOCKER_SSL_CLIENT_KEY | default(False) }}"
        CertCert "{{ DOCKER_SSL_CLIENT_CERT | default(False) }}"
        CertCA "{{ DOCKER_SSL_CA_CERT | default(False) }}"
    </Module>
    <Module "collectd_opentsdb_plugin">
        Host "{{ OPENTSDB_HOST | default("172.17.42.1") }}"
        Port "{{ OPENTSDB_PORT | default("4242") }}"
    </Module>
</Plugin>


LoadPlugin "match_regex"
PostCacheChain "PostCache"
<Chain "PostCache">
    <Rule>
        <Match regex>
            Plugin "mesos-tasks"
            PluginInstance "^(kumo\.)"
        </Match>
        <Target "write">
            Plugin "python.write_opentsdb"
        </Target>
        Target stop
    </Rule>
    <Target "write">
        Plugin "write_graphite/carbon"
    </Target>
</Chain>
