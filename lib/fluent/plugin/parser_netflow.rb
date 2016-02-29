require "ipaddr"
require 'yaml'

require 'fluent/parser'

require_relative 'netflow_records'
require_relative 'vash'

module Fluent
  class TextParser
    # port from logstash's netflow parser
    class NetflowParser < Parser
      Plugin.register_parser('netflow', self)

      config_param :cache_ttl, :integer, default: 4000
      config_param :versions, :array, default: [5, 9]
      config_param :definitions, :string, default: nil

      # Cisco NetFlow Export Datagram Format
      # http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
      # Cisco NetFlow Version 9 Flow-Record Format
      # http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

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
            handle_v9_flowset_data(flowset, record, block)
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
            @templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      end

      FIELDS_FOR_COPY_V9 = ['version', 'flow_seq_num']

      def handle_v9_flowset_data(flowset, record, block)
        key = "#{flowset.source_id}|#{record.flowset_id}"
        template = @templates[key]
        if ! template
          $log.warn("No matching template for flow id #{record.flowset_id}")
          return
        end

        length = record.flowset_length - 4

        # Template shouldn't be longer than the record and there should
        # be at most 3 padding bytes
        if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
          $log.warn "Template length doesn't fit cleanly into flowset",
                    template_id: record.flowset_id, template_length: template.num_bytes, record_length: length
          return
        end

        array = BinData::Array.new(type: template, initial_length: length / template.num_bytes)

        records = array.read(record.flowset_data)
        records.each do |r|
          time = flowset.unix_sec
          event = {}

          # Fewer fields in the v9 header
          FIELDS_FOR_COPY_V9.each do |f|
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
          $log.warn "Unsupported field", type: type, length: length
          nil
        end
      end
    end
  end
end
