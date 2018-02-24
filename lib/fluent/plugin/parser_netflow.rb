require "ipaddr"
require 'yaml'

require 'fluent/plugin/parser'

require_relative 'netflow_records'
require_relative 'vash'

module Fluent
  module Plugin
    # port from logstash's netflow parser
    class NetflowParser < Parser
      Fluent::Plugin.register_parser('netflow', self)

      config_param :switched_times_from_uptime, :bool, default: false
      config_param :cache_ttl, :integer, default: 4000
      config_param :versions, :array, default: [5, 9]
      config_param :definitions, :string, default: nil
      config_param :target, :string, default:"netflow"
      IPFIX_FIELDS = ['version']  

      # Cisco NetFlow Export Datagram Format
      # http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
      # Cisco NetFlow Version 9 Flow-Record Format
      # http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

      def configure(conf)
        @file_cache_mutex = Mutex.new
        @threadsafe = true
        @decode_mutex_netflow = Mutex.new
        @decode_mutex_ipfix = Mutex.new
        super

        @templates = Vash.new()
        @samplers_v9 = Vash.new()
        @ipfix_templates = Vash.new()
        # Path to default Netflow v9 field definitions
        filename = File.expand_path('../netflow_fields.yaml', __FILE__)

        begin
          # netflow_fields
          @template_fields = YAML.load_file(filename)
        rescue => e
          raise Fluent::ConfigError, "Bad syntax in definitions file #{filename}, error_class = #{e.class.name}, error = #{e.message}"
        end
        filename = File.expand_path('../ipfix.yaml', __FILE__)
        @ipfix_fields = load_definitions(filename, @ipfix_definitions)
        # Allow the user to augment/override/rename the supported Netflow fields
        if @definitions
          raise Fluent::ConfigError, "definitions file #{@definitions} doesn't exist" unless File.exist?(@definitions)
          begin
            @template_fields['option'].merge!(YAML.load_file(@definitions))
          rescue => e
            raise Fluent::ConfigError, "Bad syntax in definitions file #{@definitions}, error_class = #{e.class.name}, error = #{e.message}"
          end
        end
      end

      def load_definitions(defaults, extra)
        begin
          fields = YAML.load_file(defaults)
        rescue Exception => e
          raise "#{self.class.name}: Bad syntax in definitions file #{defaults}"
        end

        # Allow the user to augment/override/rename the default fields
        if extra
          raise "#{self.class.name}: definitions file #{extra} does not exist" unless File.exists?(extra)
          begin
            fields.merge!(YAML.load_file(extra))
          rescue Exception => e
            raise "#{self.class.name}: Bad syntax in definitions file #{extra}"
          end
        end
        fields
      end

      def call(payload, host=nil, &block)
        version,_ = payload[0,2].unpack('n')
        case version
        when 5
          forV5(payload, block)
        when 9
          # TODO: implement forV9
          pdu = Netflow9PDU.read(payload)
          handle_v9(host, pdu, block)
        when 10 
          flowset = IpfixPDU.read(payload)
          $log.warn "Yet to implement support for Netflow v#{version}"
          $log.warn "Printing flowset: #{flowset}"
          flowset.records.each do |record|
            decode_ipfix(flowset, record).each { |event, time|
            yield(time, event) 
            # block.call(time, event)
          }
          end
        else
          $log.warn "Unsupported Netflow version v#{version}: #{version.class}"
        end
      end

      private

      def ipv4_addr_to_string(uint32)
        "#{(uint32 & 0xff000000) >> 24}.#{(uint32 & 0x00ff0000) >> 16}.#{(uint32 & 0x0000ff00) >> 8}.#{uint32 & 0x000000ff}"
      end

      def msec_from_boot_to_time(msec, uptime, current_unix_time, current_nsec)
        millis = uptime - msec
        seconds = current_unix_time - (millis / 1000)
        micros = (current_nsec / 1000) - ((millis % 1000) * 1000)
        if micros < 0
          seconds -= 1
          micros += 1000000
        end
        Time.at(seconds, micros)
      end

      def format_for_switched(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ".freeze)
      end

      def format_for_flowSeconds(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%S".freeze)
      end

      def format_for_flowMilliSeconds(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ".freeze)
      end

      def format_for_flowMicroSeconds(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%S.%6NZ".freeze)
      end

      def format_for_flowNanoSeconds(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%S.%9NZ".freeze)
      end

      NETFLOW_V5_HEADER_FORMAT = 'nnNNNNnn'
      NETFLOW_V5_HEADER_BYTES  = 24
      NETFLOW_V5_RECORD_FORMAT = 'NNNnnNNNNnnnnnnnxx'
      NETFLOW_V5_RECORD_BYTES  = 48

      # V5 header
      # uint16 :version        # n
      # uint16 :flow_records   # n
      # uint32 :uptime         # N
      # uint32 :unix_sec       # N
      # uint32 :unix_nsec      # N
      # uint32 :flow_seq_num   # N
      # uint8  :engine_type    # n -> 0xff00
      # uint8  :engine_id      #   -> 0x00ff
      # bit2   :sampling_algorithm # n -> 0b1100000000000000
      # bit14  :sampling_interval  #   -> 0b0011111111111111

      # V5 records
      # array  :records, initial_length: :flow_records do
      #   ip4_addr :ipv4_src_addr # uint32 N
      #   ip4_addr :ipv4_dst_addr # uint32 N
      #   ip4_addr :ipv4_next_hop # uint32 N
      #   uint16   :input_snmp    # n
      #   uint16   :output_snmp   # n
      #   uint32   :in_pkts       # N
      #   uint32   :in_bytes      # N
      #   uint32   :first_switched # N
      #   uint32   :last_switched  # N
      #   uint16   :l4_src_port    # n
      #   uint16   :l4_dst_port    # n
      #   skip     length: 1  # n -> (ignored)
      #   uint8    :tcp_flags #   -> 0x00ff
      #   uint8    :protocol  # n -> 0xff00
      #   uint8    :src_tos   #   -> 0x00ff
      #   uint16   :src_as   # n
      #   uint16   :dst_as   # n
      #   uint8    :src_mask # n -> 0xff00
      #   uint8    :dst_mask #   -> 0x00ff
      #   skip     length: 2 # xx
      # end
      def forV5(payload, block)
        version, flow_records, uptime, unix_sec, unix_nsec, flow_seq_num, engine, sampling = payload.unpack(NETFLOW_V5_HEADER_FORMAT)
        engine_type = (engine & 0xff00) >> 8
        engine_id = engine & 0x00ff
        sampling_algorithm = (sampling & 0b1100000000000000) >> 14
        sampling_interval = sampling & 0b0011111111111111

        time = Fluent::EventTime.new(unix_sec.to_i, unix_nsec.to_i)

        records_bytes = payload.bytesize - NETFLOW_V5_HEADER_BYTES

        if records_bytes / NETFLOW_V5_RECORD_BYTES != flow_records
          $log.warn "bytesize mismatch, records_bytes:#{records_bytes}, records:#{flow_records}"
          return
        end

        format_full = NETFLOW_V5_RECORD_FORMAT * flow_records
        objects = payload[NETFLOW_V5_HEADER_BYTES, records_bytes].unpack(format_full)

        while objects.size > 0
          src_addr, dst_addr, next_hop, input_snmp, output_snmp,
          in_pkts, in_bytes, first_switched, last_switched, l4_src_port, l4_dst_port,
          tcp_flags_16, protocol_src_tos, src_as, dst_as, src_dst_mask = objects.shift(16)
          record = {
            "version" => version,
            "uptime"  => uptime,
            "flow_records" => flow_records,
            "flow_seq_num" => flow_seq_num,
            "engine_type"  => engine_type,
            "engine_id"    => engine_id,
            "sampling_algorithm" => sampling_algorithm,
            "sampling_interval"  => sampling_interval,

            "ipv4_src_addr" => ipv4_addr_to_string(src_addr),
            "ipv4_dst_addr" => ipv4_addr_to_string(dst_addr),
            "ipv4_next_hop" => ipv4_addr_to_string(next_hop),
            "input_snmp"  => input_snmp,
            "output_snmp" => output_snmp,
            "in_pkts"  => in_pkts,
            "in_bytes" => in_bytes,
            "first_switched" => first_switched,
            "last_switched"  => last_switched,
            "l4_src_port" => l4_src_port,
            "l4_dst_port" => l4_dst_port,
            "tcp_flags" => tcp_flags_16 & 0x00ff,
            "protocol" => (protocol_src_tos & 0xff00) >> 8,
            "src_tos"  => (protocol_src_tos & 0x00ff),
            "src_as"   => src_as,
            "dst_as"   => dst_as,
            "src_mask" => (src_dst_mask & 0xff00) >> 8,
            "dst_mask" => (src_dst_mask & 0x00ff)
          }
          unless @switched_times_from_uptime
            record["first_switched"] = format_for_switched(msec_from_boot_to_time(record["first_switched"], uptime, unix_sec, unix_nsec))
            record["last_switched"]  = format_for_switched(msec_from_boot_to_time(record["last_switched"] , uptime, unix_sec, unix_nsec))
          end

          block.call(time, record)
        end
      end

      def handle_v9(host, pdu, block)
        pdu.records.each do |flowset|
          case flowset.flowset_id
          when 0
            handle_v9_flowset_template(host, pdu, flowset)
          when 1
            handle_v9_flowset_options_template(host, pdu, flowset)
          when 256..65535
            handle_v9_flowset_data(host, pdu, flowset, block)
          else
            $log.warn 'Unsupported flowset', flowset_id: flowset.flowset_id
          end
        end
      end

      def handle_v9_flowset_template(host, pdu, flowset)
        flowset.flowset_data.templates.each do |template|
          catch (:field) do
            template_fields = []
            template.template_fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length)
              throw :field unless entry

              template_fields << entry
            end
            # We get this far, we have a list of fields
            key = "#{host}|#{pdu.source_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: template_fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      end

      NETFLOW_V9_FIELD_CATEGORIES = ['scope', 'option']

      def handle_v9_flowset_options_template(host, pdu, flowset)
        flowset.flowset_data.templates.each do |template|
          catch (:field) do
            template_fields = []

            NETFLOW_V9_FIELD_CATEGORIES.each do |category|
              template["#{category}_fields"].each do |field|
                entry = netflow_field_for(field.field_type, field.field_length, category)
                throw :field unless entry

                template_fields << entry
              end
            end

            # We get this far, we have a list of fields
            key = "#{host}|#{pdu.source_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: template_fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      end

      FIELDS_FOR_COPY_V9 = ['version', 'flow_seq_num']

      def handle_v9_flowset_data(host, pdu, flowset, block)
        template_key = "#{host}|#{pdu.source_id}|#{flowset.flowset_id}"
        template = @templates[template_key]
        if ! template
          $log.warn 'No matching template for',
                    host: host, source_id: pdu.source_id, flowset_id: flowset.flowset_id
          return
        end

        length = flowset.flowset_length - 4

        # Template shouldn't be longer than the flowset and there should
        # be at most 3 padding bytes
        if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
          $log.warn "Template length doesn't fit cleanly into flowset",
                    template_id: flowset.flowset_id, template_length: template.num_bytes, flowset_length: length
          return
        end

        array = BinData::Array.new(type: template, initial_length: length / template.num_bytes)

        template_fields = array.read(flowset.flowset_data)
        template_fields.each do |r|
          if is_sampler?(r)
            sampler_key = "#{host}|#{pdu.source_id}|#{r.flow_sampler_id}"
            register_sampler_v9 sampler_key, r
            next
          end

          time = Fluent::EventTime.new(pdu.unix_sec.to_i)
          event = {}

          # Fewer fields in the v9 header
          FIELDS_FOR_COPY_V9.each do |f|
            event[f] = pdu[f]
          end

          event['flowset_id'] = flowset.flowset_id

          r.each_pair do |k, v|
            case k
            when :first_switched
              unless @switched_times_from_uptime
                event[k.to_s] = format_for_switched(msec_from_boot_to_time(v.snapshot, pdu.uptime, time, 0))
              end
            when :last_switched
              unless @switched_times_from_uptime
                event[k.to_s] = format_for_switched(msec_from_boot_to_time(v.snapshot, pdu.uptime, time, 0))
              end
            when :flowStartSeconds
              event[k.to_s] = format_for_flowSeconds(Time.at(v.snapshot, 0))
            when :flowEndSeconds
              event[k.to_s] = format_for_flowSeconds(Time.at(v.snapshot, 0))
            when :flowStartMilliseconds
              divisor = 1_000
              microseconds = (v.snapshot % 1_000) * 1_000
              event[k.to_s] = format_for_flowMilliSeconds(Time.at(v.snapshot / divisor, microseconds))
            when :flowEndMilliseconds
              divisor = 1_000
              microseconds = (v.snapshot % 1_000) * 1_000
              event[k.to_s] = format_for_flowMilliSeconds(Time.at(v.snapshot / divisor, microseconds))
            when :flowStartMicroseconds
              divisor = 1_000_000
              microseconds = (v.snapshot % 1_000_000)
              event[k.to_s] = format_for_flowMicroSeconds(Time.at(v.snapshot / divisor, microseconds))
            when :flowEndMicroseconds
              divisor = 1_000_000
              microseconds = (v.snapshot % 1_000_000)
              event[k.to_s] = format_for_flowMicroSeconds(Time.at(v.snapshot / divisor, microseconds))
            when :flowStartNanoseconds
              divisor = 1_000_000_000
              microseconds = (v.snapshot % 1_000_000_000) / 1_000
              nanoseconds = v.snapshot % 1_000_000_000
              time_with_nano = Time.at(v.snapshot / divisor, microseconds)
              time_with_nano.nsec = nanoseconds
              event[k.to_s]  = format_for_flowNanoSeconds(time_with_nano)
            when :flowEndNanoseconds
              divisor = 1_000_000_000
              microseconds = (v.snapshot % 1_000_000_000) / 1_000
              nanoseconds = v.snapshot % 1_000_000_000
              time_with_nano = Time.at(v.snapshot / divisor, microseconds)
              time_with_nano.nsec = nanoseconds
              event[k.to_s]  = format_for_flowNanoSeconds(time_with_nano)
            else
              event[k.to_s] = v.snapshot
            end
          end

          if sampler_id = r['flow_sampler_id']
            sampler_key = "#{host}|#{pdu.source_id}|#{sampler_id}"
            if sampler = @samplers_v9[sampler_key]
              event['sampling_algorithm'] ||= sampler['flow_sampler_mode']
              event['sampling_interval'] ||= sampler['flow_sampler_random_interval']
            end
          end

          block.call(time, event)
        end
      end

      def uint_field(length, default)
        # If length is 4, return :uint32, etc. and use default if length is 0
        ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
      end

      def netflow_field_for(type, length, category = 'option'.freeze)
        unless field = @template_fields[category][type]
          $log.warn "Skip unsupported field", type: type, length: length
          return [:skip, nil, {length: length}]
        end

        unless field.is_a?(Array)
          $log.warn "Skip non-Array definition", field: field
          return [:skip, nil, {length: length}]
        end

        # Small bit of fixup for numeric value, :skip or :string field length, which are dynamic
        case field[0]
        when Integer
          [uint_field(length, field[0]), field[1]]
        when :skip
          field + [nil, {length: length}]
        when :string
          field + [{length: length, trim_padding: true}]
        else
          field
        end
      end     
      # covers Netflow v9 and v10 (a.k.a IPFIX)
      def is_sampler?(record)
        record['flow_sampler_id'] && record['flow_sampler_mode'] && record['flow_sampler_random_interval']
      end

      def register_sampler_v9(key, sampler)
        @samplers_v9[key, @cache_ttl] = sampler
        @samplers_v9.cleanup!
      end

      def decode_ipfix(flowset, record)
        events = []
        $log.warn "Printing flowset_id: #{record.flowset_id}"
        case record.flowset_id
        when 2..3
          $log.warn "Decoding template set or option template set #{record.flowset_id}"
          record.flowset_data.templates.each do |template|
            catch (:field) do
              fields = []
              # Template flowset (2) or Options template flowset (3) ?
              template_fields = (record.flowset_id == 2) ? template.record_fields : (template.scope_fields.to_ary + template.option_fields.to_ary)
              template_fields.each do |field|
                field_type = field.field_type
                field_length = field.field_length
                enterprise_id = field.enterprise ? field.enterprise_id : 0

                entry = ipfix_field_for(field_type, enterprise_id, field.field_length)
                throw :field unless entry
                fields += entry
              end
              # FIXME Source IP address required in key
              key = "#{flowset.observation_domain_id}|#{template.template_id}"
              $log.warn "Key is : #{key}"
              # Prevent ipfix_templates array from being concurrently modified
              @decode_mutex_ipfix.synchronize do
                @ipfix_templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
                # Purge any expired templates
                @ipfix_templates.cleanup!
                if @cache_save_path
                  @ipfix_templates_cache[key] = fields
                  save_templates_cache(@ipfix_templates_cache, "#{@cache_save_path}/ipfix_templates.cache")
                end
              end
            end
          end
        when 256..65535
          # Data flowset
          key = "#{flowset.observation_domain_id}|#{record.flowset_id}"
          $log.warn "Decoding dataset with Domain id: #{flowset.observation_domain_id} and flow set id: #{record.flowset_id} "
          if @ipfix_templates[key] != nil
            template = @ipfix_templates[key]
          else
            $log.warn "Can't (yet) decode flowset id #{record.flowset_id} from observation domain id #{flowset.observation_domain_id}, because no template to decode it with has been received. This message will usually go away after 1 minute."
            return events
          end

          array = BinData::Array.new(:type => template, :read_until => :eof)
          records = array.read(record.flowset_data)

          records.each do |r|
            time = Fluent::EventTime.new(flowset.unix_sec.to_i)
            event = {
              "time" => Fluent::EventTime.new(flowset.unix_sec.to_i),
              @target => {}
            }

            IPFIX_FIELDS.each do |f|
              event[@target][f] = flowset[f].snapshot
            end

            if @include_flowset_id
              event[@target][FLOWSET_ID] = record.flowset_id.snapshot
            end

            r.each_pair do |k, v|
              case k.to_s
              when /^flow(?:Start|End)Seconds$/
                event[@target][k.to_s] = format_for_flowSeconds(Time.at(v.snapshot, 0))
              when /^flow(?:Start|End)(Milli|Micro|Nano)seconds$/
                case $1
                when 'Milli'
                  divisor = 1_000
                  microseconds = (v.snapshot % 1_000) * 1_000
                  event[@target][k.to_s] = format_for_flowMilliSeconds(Time.at(v.snapshot / divisor, microseconds))
                when 'Micro'
                  divisor = 1_000_000
                  microseconds = (v.snapshot % 1_000_000)
                  event[@target][k.to_s] = format_for_flowMicroSeconds(Time.at(v.snapshot / divisor, microseconds))
                when 'Nano'
                  divisor = 1_000_000_000
                  microseconds = (v.snapshot % 1_000_000_000) / 1_000
                  nanoseconds = v.snapshot % 1_000_000_000
                  time_with_nano = Time.at(v.snapshot / divisor, microseconds)
                  time_with_nano.nsec = nanoseconds
                  event[@target][k.to_s]  = format_for_flowNanoSeconds(time_with_nano)
                end
              else
                event[@target][k.to_s] = v.snapshot
              end
            end
            $log.warn "Adding event to the list: #{event}"
            events << [event,time]
          end
        else
          $log.warn "Unsupported flowset id #{record.flowset_id}"
        end

        events
      rescue BinData::ValidityError => e
        $log.warn "Invalid IPFIX packet received (#{e})"
      end # end decode_ipfix

      def ipfix_field_for(type, enterprise, length)
        if @ipfix_fields.include?(enterprise)
          if @ipfix_fields[enterprise].include?(type)
            field = @ipfix_fields[enterprise][type].clone
          else
           $log.warn("Unsupported enterprise field", :type => type, :enterprise => enterprise, :length => length)
          end
        else
          $log.warn("Unsupported enterprise", :enterprise => enterprise)
        end

        return nil unless field

        if field.is_a?(Array)
          case field[0]
          when :skip
            field = skip_field(field, type, length.to_i)
          when :string
            field = string_field(field, type, length.to_i)
          when :octetarray
            field[0] = :OctetArray
            field += [{:initial_length => length.to_i}]
          when :uint64
            field[0] = uint_field(length, 8)
          when :uint32
            field[0] = uint_field(length, 4)
          when :uint16
            field[0] = uint_field(length, 2)
          end

          $log.debug("Definition complete", :field => field)
          [field]
        else
          $log.warn("Definition should be an array", :field => field)
        end
      end # end def ipfix_field_for

      def skip_field(field, type, length)
        if length == 65535
          field[0] = :VarSkip
        else
          field += [nil, {:length => length.to_i}]
        end
        field
      end # def skip_field

      def string_field(field, type, length)
        if length == 65535
          field[0] = :VarString
        else
          field[0] = :string
          field += [{ :length => length.to_i, :trim_padding => true }]
        end
        field
      end # def string_field

    end
  end
end
