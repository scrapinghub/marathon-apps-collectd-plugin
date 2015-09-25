#!/bin/sh
set -e

template=${COLLECTD_CONF_TPL:-/etc/collectd/collectd.conf.tpl}

if [ ! -e "/.initialized" ]; then
    touch "/.initialized"
    envtpl $template
fi

collectd -f
