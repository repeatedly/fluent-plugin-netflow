# Netflow plugin for Fluentd

Accept Netflow logs.

Netflow parser is based on [Logstash's netflow codes](https://github.com/elasticsearch/logstash/blob/master/lib/logstash/codecs/netflow.rb).

## Installation

Use RubyGems:

    fluent-gem install fluent-plugin-netflow

## Configuration

    <source>
      type netflow
      tag netflow.event

      # optional parameters
      bind 127.0.0.1
      port 5140

      # optional parser parameters
      cache_ttl 6000
      versions [5, 9]
    </match>

## TODO

- Support TCP protocol? TCP is needed?
- Use Fluentd feature instead of own handlers
- Need another maintainer who uses Netflow in production!
