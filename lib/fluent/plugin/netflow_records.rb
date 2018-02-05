require "bindata"

module Fluent
  module Plugin
    class NetflowParser < Parser
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


      class VarSkip < BinData::Primitive
        endian :big
        uint8 :length_1
        uint16 :length_2, :onlyif => lambda { length_1 == 255 }
        skip :length => lambda { (length_1 == 255) ? length_2 : length_1 }

        def get
          ""
        end
      end

      class VarString < BinData::Primitive
        endian :big
        uint8 :length_1
        uint16 :length_2, :onlyif => lambda { length_1 == 255 }
        string :data, :trim_padding => true, :length => lambda { (length_1 == 255) ? length_2 : length_1 }

        def set(val)
          self.data = val
        end

        def get
          self.data
        end

        def snapshot
          super.encode("ASCII-8BIT", "UTF-8", invalid: :replace, undef: :replace)
        end
      end

      class ACLIdASA < BinData::Primitive
        string :bytes, :length => 12

        def set(val)
          unless val.nil?
            self.bytes = val.split("-").collect { |aclid| aclid.scan(/../).collect { |hex| hex.to_i(16)} }.flatten
          end
        end

        def get
          # This is currently the fastest implementation
          # For benchmarks see spec/codecs/benchmarks/ACLIdASA.rb
          b = self.bytes.unpack('H*')[0]
          b[0..7] + "-" + b[8..15] + "-" + b[16..23] 
        end
      end

      class MPLSLabelStackOctets < BinData::Record
        endian :big
        bit20  :label
        bit3   :experimental
        bit1   :bottom_of_stack
        uint8  :ttl
      end

      class Forwarding_Status < BinData::Record
        endian :big
        bit2   :status
        bit6   :reason
      end

      class Application_Id16 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint24 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<24
            self.selector_id = val.to_i-((val.to_i>>24)<<24)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class Application_Id24 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint16 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<16
            self.selector_id = val.to_i-((val.to_i>>16)<<16)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class Application_Id32 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint24 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<24
            self.selector_id = val.to_i-((val.to_i>>24)<<24)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class Application_Id40 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint32 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<32
            self.selector_id = val.to_i-((val.to_i>>32)<<32)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class Application_Id64 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint56 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<56
            self.selector_id = val.to_i-((val.to_i>>56)<<56)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class Application_Id72 < BinData::Primitive
        endian :big
        uint8  :classification_id
        uint64 :selector_id

        def set(val)
          unless val.nil?
            self.classification_id=val.to_i<<64
            self.selector_id = val.to_i-((val.to_i>>64)<<64)
          end
        end

        def get
          self.classification_id.to_s + ":" + self.selector_id.to_s
        end
      end

      class OctetArray < BinData::Primitive
        # arg_processor :octetarray
        mandatory_parameter :initial_length
        array :bytes, :type => :uint8, :initial_length => :initial_length

        def set(val)
          unless val.nil?
            self.bytes = val.scan(/../).collect { |hex| hex.to_i(16)}
          end
        end

        def get
          self.bytes.collect { |byte| byte.value.to_s(16).rjust(2,'0') }.join
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
          array  :template_fields, initial_length: :field_count do
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

      class IpfixTemplateFlowset < BinData::Record
        endian :big
        array  :templates, :read_until => lambda { flowset_length - 4 - array.num_bytes <= 2 } do
          uint16 :template_id
          uint16 :field_count
          array  :record_fields, :initial_length => :field_count do
            bit1   :enterprise
            bit15  :field_type
            uint16 :field_length
            uint32 :enterprise_id, :onlyif => lambda { enterprise != 0 }
          end
        end
        # skip :length => lambda { flowset_length - 4 - set.num_bytes } ?
      end

      class IpfixOptionFlowset < BinData::Record
        endian :big
        array  :templates, :read_until => lambda { flowset_length - 4 - array.num_bytes <= 2 } do
          uint16 :template_id
          uint16 :field_count
          uint16 :scope_count, :assert => lambda { scope_count > 0 }
          array  :scope_fields, :initial_length => lambda { scope_count } do
            bit1   :enterprise
            bit15  :field_type
            uint16 :field_length
            uint32 :enterprise_id, :onlyif => lambda { enterprise != 0 }
          end
          array  :option_fields, :initial_length => lambda { field_count - scope_count } do
            bit1   :enterprise
            bit15  :field_type
            uint16 :field_length
            uint32 :enterprise_id, :onlyif => lambda { enterprise != 0 }
          end
        end
      end

      class IpfixPDU < BinData::Record
        endian :big
        uint16 :version
        uint16 :pdu_length
        uint32 :unix_sec
        uint32 :flow_seq_num
        uint32 :observation_domain_id
        array  :records, :read_until => lambda { array.num_bytes == pdu_length - 16 } do
          uint16 :flowset_id, :assert => lambda { [2, 3, *(256..65535)].include?(flowset_id) }
          uint16 :flowset_length, :assert => lambda { flowset_length > 4 }
          choice :flowset_data, :selection => :flowset_id do
            ipfix_template_flowset 2
            ipfix_option_flowset   3
            string                 :default, :read_length => lambda { flowset_length - 4 }
          end
        end
      end
    end
  end
end
