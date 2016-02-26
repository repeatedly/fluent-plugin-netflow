require "bindata"
require "ipaddr"
require 'yaml'

require 'fluent/parser'

module Fluent
  class TextParser
    # port from logstash's netflow parser
    class NetflowParser < Parser
      Plugin.register_parser('netflow', self)

      config_param :cache_ttl, :integer, default: 4000
      config_param :versions, :array, default: [5, 9]
      config_param :definitions, :string, default: nil

      def configure(conf)
        super

        @templates = Vash.new()
        # Path to default Netflow v9 field definitions
        filename = File.expand_path('../netflow_option_fields.yaml', __FILE__)

        begin
          @fields = YAML.load_file(filename)
        rescue => e
          raise "Bad syntax in definitions file #{filename}", error_class: e.class, error: e.message
        end

        # Allow the user to augment/override/rename the supported Netflow fields
        if @definitions
          raise "definitions file #{@definitions} does not exists" unless File.exist?(@definitions)
          begin
            @fields.merge!(YAML.load_file(@definitions))
          rescue => e
            raise "Bad syntax in definitions file #{@definitions}", error_class: e.class, error: e.message
          end
        end
        # Path to default Netflow v9 scope field definitions
        filename = File.expand_path('../netflow_scope_fields.yaml', __FILE__)

        begin
          @scope_fields = YAML.load_file(filename)
        rescue => e
          raise "Bad syntax in scope definitions file #{filename}", error_class: e.class, error: e.message
        end
      end

      def call(payload, &block)
        header = Header.read(payload)
        unless @versions.include?(header.version)
          $log.warn "Ignoring Netflow version v#{header.version}"
          return
        end

        if header.version == 5
          flowset = Netflow5PDU.read(payload)
          handle_v5(flowset, block)
        elsif header.version == 9
          flowset = Netflow9PDU.read(payload)
          handle_v9(flowset, block)
        else
          $log.warn "Unsupported Netflow version v#{header.version}"
        end
      end

      private

      FIELDS_FOR_COPY_V5 = [
        'version', 'flow_seq_num', 'engine_type', 'engine_id', 'sampling_algorithm', 'sampling_interval', 'flow_records',
      ]

      def handle_v5(flowset, block)
        flowset.records.each do |record|
          event = {}

          # FIXME Probably not doing this right WRT JRuby?
          #
          # The flowset header gives us the UTC epoch seconds along with
          # residual nanoseconds so we can set @timestamp to that easily
          time = flowset.unix_sec

          # Copy some of the pertinent fields in the header to the event
          FIELDS_FOR_COPY_V5.each do |f|
            event[f] = flowset[f]
          end

          # Create fields in the event from each field in the flow record
          record.each_pair do |k,v|
            case k.to_s
            when /_switched$/
              # The flow record sets the first and last times to the device
              # uptime in milliseconds. Given the actual uptime is provided
              # in the flowset header along with the epoch seconds we can
              # convert these into absolute times
              millis = flowset.uptime - v
              seconds = flowset.unix_sec - (millis / 1000)
              micros = (flowset.unix_nsec / 1000) - (millis % 1000)
              if micros < 0
                seconds -= 1
                micros += 1000000
              end

              # FIXME Again, probably doing this wrong WRT JRuby?
              event[k.to_s] = Time.at(seconds, micros).utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ")
            else
              event[k.to_s] = v
            end
          end

          block.call(time, event)
        end
      end

      def handle_v9(flowset, block)
        flowset.records.each do |record|
          case record.flowset_id
          when 0
            handle_v9_flowset_template(flowset, record)
          when 1
            handle_v9_flowset_options_template(flowset, record)
          when 256..65535
            # Data flowset
            #key = "#{flowset.source_id}|#{event["source"]}|#{record.flowset_id}"
            key = "#{flowset.source_id}|#{record.flowset_id}"
            template = @templates[key]
            if ! template
              #$log.warn("No matching template for flow id #{record.flowset_id} from #{event["source"]}")
              $log.warn("No matching template for flow id #{record.flowset_id}")
              next
            end

            length = record.flowset_length - 4

            # Template shouldn't be longer than the record and there should
            # be at most 3 padding bytes
            if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
              $log.warn "Template length doesn't fit cleanly into flowset",
              template_id: record.flowset_id, template_length: template.num_bytes, record_length: length
              next
            end

            array = BinData::Array.new(type: template, initial_length: length / template.num_bytes)

            records = array.read(record.flowset_data)
            records.each do |r|
              time = flowset.unix_sec
              event = {}

              # Fewer fields in the v9 header
              ['version', 'flow_seq_num'].each do |f|
                event[f] = flowset[f]
              end

              event['flowset_id'] = record.flowset_id

              r.each_pair do |k,v|
                case k.to_s
                when /_switched$/
                  millis = flowset.uptime - v
                  seconds = flowset.unix_sec - (millis / 1000)
                  # v9 did away with the nanosecs field
                  micros = 1000000 - (millis % 1000)
                  event[k.to_s] = Time.at(seconds, micros).utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ")
                else
                  event[k.to_s] = v
                end
              end

              block.call(time, event)
            end
          else
            $log.warn "Unsupported flowset id #{record.flowset_id}"
          end
        end
      end

      def handle_v9_flowset_template(flowset, record)
        record.flowset_data.templates.each do |template|
          catch (:field) do
            fields = []
            template.fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length, @fields)
              if !entry
                throw :field
              end
              fields += entry
            end
            # We get this far, we have a list of fields
            key = "#{flowset.source_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      end

      def handle_v9_flowset_options_template(flowset, record)
        record.flowset_data.templates.each do |template|
          catch (:field) do
            fields = []
            template.scope_fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length, @scope_fields)
              if ! entry
                throw :field
              end
              fields += entry
            end
            template.option_fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length, @fields)
              if ! entry
                throw :field
              end
              fields += entry
            end
            # We get this far, we have a list of fields
            key = "#{flowset.source_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, :fields => fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      end

      def uint_field(length, default)
        # If length is 4, return :uint32, etc. and use default if length is 0
        ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
      end

      def netflow_field_for(type, length, field_definitions)
        if field_definitions.include?(type)
          field = field_definitions[type]
          if field.is_a?(Array)

            if field[0].is_a?(Integer)
              field[0] = uint_field(length, field[0])
            end

            # Small bit of fixup for skip or string field types where the length
            # is dynamic
            case field[0]
            when :skip
              field += [nil, {length: length}]
            when :string
              field += [{length: length, trim_padding: true}]
            end

            [field]
          else
            $log.warn "Definition should be an array", field: field
            nil
          end
        else
          $log.warn "Unsupported field", type: type, length: length)
          nil
        end
      end

      class IP4Addr < BinData::Primitive
        endian :big
        uint32 :storage

        def set(val)
          ip = IPAddr.new(val)
          if ! ip.ipv4?
            raise ArgumentError, "invalid IPv4 address '#{val}'"
          end
          self.storage = ip.to_i
        end

        def get
          IPAddr.new_ntoh([self.storage].pack('N')).to_s
        end
      end

      class IP6Addr < BinData::Primitive
        endian  :big
        uint128 :storage

        def set(val)
          ip = IPAddr.new(val)
          if ! ip.ipv6?
            raise ArgumentError, "invalid IPv6 address `#{val}'"
          end
          self.storage = ip.to_i
        end

        def get
          IPAddr.new_ntoh((0..7).map { |i|
              (self.storage >> (112 - 16 * i)) & 0xffff
            }.pack('n8')).to_s
        end
      end

      class MacAddr < BinData::Primitive
        array :bytes, type: :uint8, initial_length: 6

        def set(val)
          ints = val.split(/:/).collect { |int| int.to_i(16) }
          self.bytes = ints
        end

        def get
          self.bytes.collect { |byte| byte.value.to_s(16).rjust(2,'0') }.join(":")
        end
      end

      class MplsLabel < BinData::Primitive
        bit20 :label
        bit3  :exp
        bit1  :bottom
        def set(val)
          self.label = val >> 4
          self.exp = (val & 0b1111) >> 1
          self.bottom = val & 0b1
        end
        def get
          self.label
        end
      end

      class Header < BinData::Record
        endian :big
        uint16 :version
      end

      class Netflow5PDU < BinData::Record
        endian :big
        uint16 :version
        uint16 :flow_records
        uint32 :uptime
        uint32 :unix_sec
        uint32 :unix_nsec
        uint32 :flow_seq_num
        uint8  :engine_type
        uint8  :engine_id
        bit2   :sampling_algorithm
        bit14  :sampling_interval
        array  :records, initial_length: :flow_records do
          ip4_addr :ipv4_src_addr
          ip4_addr :ipv4_dst_addr
          ip4_addr :ipv4_next_hop
          uint16   :input_snmp
          uint16   :output_snmp
          uint32   :in_pkts
          uint32   :in_bytes
          uint32   :first_switched
          uint32   :last_switched
          uint16   :l4_src_port
          uint16   :l4_dst_port
          skip     length: 1
          uint8    :tcp_flags # Split up the TCP flags maybe?
          uint8    :protocol
          uint8    :src_tos
          uint16   :src_as
          uint16   :dst_as
          uint8    :src_mask
          uint8    :dst_mask
          skip     length: 2
        end
      end

      class TemplateFlowset < BinData::Record
        endian :big
        array  :templates, read_until: lambda { array.num_bytes == flowset_length - 4 } do
          uint16 :template_id
          uint16 :field_count
          array  :fields, :initial_length => :field_count do
            uint16 :field_type
            uint16 :field_length
          end
        end
      end

      class OptionFlowset < BinData::Record
        endian :big
        array  :templates, read_until: lambda { flowset_length - 4 - array.num_bytes <= 2 } do
          uint16 :template_id
          uint16 :scope_length
          uint16 :option_length
          array  :scope_fields, initial_length: lambda { scope_length / 4 } do
            uint16 :field_type
            uint16 :field_length
          end
          array  :option_fields, initial_length: lambda { option_length / 4 } do
            uint16 :field_type
            uint16 :field_length
          end
        end
        skip   length: lambda { templates.length.odd? ? 2 : 0 }
      end

      class Netflow9PDU < BinData::Record
        endian :big
        uint16 :version
        uint16 :flow_records
        uint32 :uptime
        uint32 :unix_sec
        uint32 :flow_seq_num
        uint32 :source_id
        array  :records, read_until: :eof do
          uint16 :flowset_id
          uint16 :flowset_length
          choice :flowset_data, selection: :flowset_id do
            template_flowset 0
            option_flowset   1
            string           :default, read_length: lambda { flowset_length - 4 }
          end
        end
      end

      # https://gist.github.com/joshaven/184837
      class Vash < Hash
        def initialize(constructor = {})
          @register ||= {}
          if constructor.is_a?(Hash)
            super()
            merge(constructor)
          else
            super(constructor)
          end
        end

        alias_method :regular_writer, :[]= unless method_defined?(:regular_writer)
        alias_method :regular_reader, :[] unless method_defined?(:regular_reader)

        def [](key)
          sterilize(key)
          clear(key) if expired?(key)
          regular_reader(key)
        end

        def []=(key, *args)
          if args.length == 2
            value, ttl = args[1], args[0]
          elsif args.length == 1
            value, ttl = args[0], 60
          else
            raise ArgumentError, "Wrong number of arguments, expected 2 or 3, received: #{args.length+1}\n"+
              "Example Usage:  volatile_hash[:key]=value OR volatile_hash[:key, ttl]=value"
          end
          sterilize(key)
          ttl(key, ttl)
          regular_writer(key, value)
        end

        def merge(hsh)
          hsh.map {|key,value| self[sterile(key)] = hsh[key]}
          self
        end

        def cleanup!
          now = Time.now.to_i
          @register.map {|k,v| clear(k) if v < now}
        end

        def clear(key)
          sterilize(key)
          @register.delete key
          self.delete key
        end

        private

        def expired?(key)
          Time.now.to_i > @register[key].to_i
        end

        def ttl(key, secs=60)
          @register[key] = Time.now.to_i + secs.to_i
        end

        def sterile(key)
          String === key ? key.chomp('!').chomp('=') : key.to_s.chomp('!').chomp('=').to_sym
        end

        def sterilize(key)
          key = sterile(key)
        end
      end
    end
  end
end
