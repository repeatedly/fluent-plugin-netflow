# Netflow plugin for Fluentd

[![Build Status](https://travis-ci.org/repeatedly/fluent-plugin-netflow.svg)](https://travis-ci.org/repeatedly/fluent-plugin-netflow)


## Overview

[Fluentd](http://fluentd.org/) input plugin that acts as Netflow v5/v9 collector.


## Installation

Use RubyGems:

    fluent-gem install fluent-plugin-netflow


## Configuration

    <source>
      type netflow
      tag netflow.event

      # optional parameters
      bind 192.168.0.1
      port 2055
      cache_ttl 6000
      versions [5, 9]
    </source>

**bind**

IP address on which the plugin will accept Netflow.  
(Default: '0.0.0.0')

**port**

UDP port number on which tpe plugin will accept Netflow.  
(Default: 5140)

**cache_ttl**

Template cache TTL for Netflow v9 in seconds. Templates not refreshed from the Netflow v9 exporter within the TTL are expired at the plugin.  
(Default: 4000)

**versions**

Netflow versions which are acceptable.  
(Default:[5, 9])

**switched_times_from_uptime**

When set to true, the plugin stores system uptime for ```first_switched``` and ```last_switched``` instead of ISO8601-formatted absolute time.  
(Defaults: false)


## Performance Evaluation

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


## Tips

### Use netflow parser in other plugins

```ruby
require 'fluent/plugin/parser_netflow'

parser = TextParser::NetflowParser.new
parser.configure(conf)

# Netflow v5
parser.call(payload) do |time, record|
  # do something
end

# Netflow v9
parser.call(payload, source_ip_address) do |time, record|
  # do something
end
```

**NOTE:**
If the plugin receives Netflow v9 from multiple sources, provide ```source_ip_address``` argument to parse correctly.

### More speed ?

:bullettrain_side: Try ```switched_times_from_uptime true``` option !


## TODO

* Netflow v9 protocol parser optimization
* Use Fluentd feature instead of own handlers
