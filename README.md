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
      definitions /path/to/custom_fields.yaml
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

**definitions**

YAML file containing Netflow field definitions to overfide pre-defined templates. Example is like below

    ---
    4:          # field value
    - :uint8    # field length
    - :protocol # field type


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

### Field definition for Netflow v9

Both option and scope fields for Netflow v9 are defined in [YAML](https://www.ietf.org/rfc/rfc3954.txt) where two parameters are described for each field value like:

```yaml
option:
  ...
  4:           # field value
  - :uint8     # field length
  - :protocol  # field type
```

See [RFC3954 document](https://www.ietf.org/rfc/rfc3954.txt) for more details.

When int value specified for field length, the template parser in this plugin will prefer a field length in received template flowset over YAML. The int value in YAML will be used as a default value only when the length in received flowset is invalid.

```yaml
option:
  1:
  - 4          # means :unit32, which is just a default
  - :in_bytes
```

When ```:skip``` is described for a field, the template parser will learn the length from received template flowset and skip the field when data flowsets are processed.

```yaml
option:
  ...
  43:
  - :skip
```

**NOTE:**
The definitions don't exactly reflect RFC3954 in order to cover some illegal implementations which export Netflow v9 in bad field length.

```yaml
   31:
   - 3  # Some system exports in 4 bytes despite of RFC
   - :ipv6_flow_label
   ...
   48:
   - 1  # Some system exports in 2 bytes despite of RFC
   - :flow_sampler_id
```

### PaloAlto Netflow

PaloAlto Netflow has different field definitionas:
See this definitions for PaloAlto Netflow: https://github.com/repeatedly/fluent-plugin-netflow/issues/27#issuecomment-269197495

### More speed ?

:bullettrain_side: Try ```switched_times_from_uptime true``` option !


## TODO

* Netflow v9 protocol parser optimization
* Use Fluentd feature instead of own handlers
