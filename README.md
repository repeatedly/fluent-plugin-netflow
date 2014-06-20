# Netflow plugin for Fluentd

Accept Netflow logs.

## Installation

Use RubyGems:

    gem install fluent-plugin-netflow

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

* Release as rubygem
