module RubySMB
  module Dcerpc
    module Winreg

      # This class represents a BaseRegQueryValue Response Packet as defined in
      # [3.1.5.17 BaseRegQueryValue (Opnum 17)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/8bc10aa3-2f91-44e8-aa33-b3263c49ab9d)
      class QueryValueResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_lp_dword :lp_type
        ndr_lp_byte  :lp_data
        string       :pad, length: -> { pad_length }
        ndr_lp_dword :lpcb_data
        ndr_lp_dword :lpcb_len
        uint32       :error_status

        def initialize_instance
          super
          @opnum = REG_QUERY_VALUE
        end

        # Determines the correct length for the padding in front of
        # #lpcb_data. It should always force a 4-byte alignment.
        def pad_length
          offset = (lp_data.abs_offset + lp_data.to_binary_s.length) % 4
          (4 - offset) % 4
        end

        # Returns the data portion of the registry value formatted according to its type:
        # [3.1.1.5 Values](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/3d64dbea-f016-4373-8cac-e43bf343837d)
        def data
          bytes = lp_data.bytes.to_a.pack('C*')
          case lp_type
          when 1,2
            bytes.force_encoding('utf-16le').strip
          when 3
            bytes
          when 4
            bytes.unpack('V').first
          when 5
            bytes.unpack('N').first
          when 7
            str = bytes.force_encoding('utf-16le')
            str.split("\0".encode('utf-16le'))
          when 11
            bytes.unpack('Q<').first
          else
            ""
          end
        end

      end
    end
  end
end
