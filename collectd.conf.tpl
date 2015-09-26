Hostname "{{ COLLECTD_HOST | default(DOCKER_HOST) }}"

FQDNLookup false
Interval {{ COLLECTD_INTERVAL | default(10) }}
Timeout 2
ReadThreads 5

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

TypesDB "/usr/share/collectd/plugins/marathon/metrics.db"
<LoadPlugin "python">
    Globals true
</LoadPlugin>

<Plugin "python">
    ModulePath "/usr/share/collectd/plugins/marathon"

    Import "collectd_marathon_plugin"
    <Module "collectd_marathon_plugin">
        Host "{{ DOCKER_HOST }}"
        Port {{ DOCKER_PORT | default(2376) }}
        CertKey "{{ DOCKER_SSL_CLIENT_KEY | default(False) }}"
        CertCert "{{ DOCKER_SSL_CLIENT_CERT | default(False) }}"
        CertCA "{{ DOCKER_SSL_CA_CERT | default(False) }}"
    </Module>
</Plugin>

