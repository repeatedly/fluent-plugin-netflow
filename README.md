# Netflow plugin for Fluentd

Fluentd plugin to receive/parse Netflow protocol v5/v9.

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
    </source>

## Rough performance

Benchmark for v5 protocol on Macbook Air (Early 2014, 1.7 GHz Intel Core i7):
* 0 packets dropped in 32,000 records/second (for 3,000,000 packets)
* 45,000 records/second in maximum (for flooding netflow packets)

Tested with the packet generator below:

* https://github.com/mshindo/NetFlow-Generator
* `./flowgen -n3000000 -i50 -w1 -p5140 localhost`

And configuration:

    <source>
      @type  netflow
      tag netflow.event
      bind 0.0.0.0
      port 5140
      switched_times_from_uptime yes
    </source>
    <match netflow.event>
      @type flowcounter
      unit minute
      count_keys count # missing column for counting events only
      tag flowcount
    </match>
    <match flowcount>
      @type stdout
    </match>

## TODO

* Netflow v9 protocol parser optimization
* Support TCP protocol? TCP is needed?
* Use Fluentd feature instead of own handlers
