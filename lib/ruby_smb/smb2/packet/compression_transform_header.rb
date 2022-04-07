module RubySMB
  module SMB2
    module Packet
      # An SMB2 SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER Packet as defined in
      # [2.2.42.2.1 SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8898e8e7-f1b2-47f5-a525-2ce5bad6db64)
      class Smb2CompressionChainedPayloadHeader < BinData::Record
        endian :little

        uint16           :compression_algorithm,            label: 'Compression Algorithm'
        uint16           :flags,                            label: 'Flags'
        uint32           :payload_length,                   label: 'Compressed Payload Length'
        uint32           :original_payload_size,            label: 'Original Payload Size', onlyif: :has_original_payload_size?

        private

        def has_original_payload_size?
          # #original_payload_size is only present when the algorithm is one of these values
          [
            SMB2::CompressionCapabilities::LZNT1,
            SMB2::CompressionCapabilities::LZ77,
            SMB2::CompressionCapabilities::LZ77_Huffman
          ].include?(compression_algorithm)
        end
      end

      # An SMB2 SMB2_COMPRESSION_PATTERN_PAYLOAD_V1 Packet as defined in
      # [2.2.42.2.2 SMB2_COMPRESSION_PATTERN_PAYLOAD_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f6859837-395a-4d0a-8971-1fc3919e2d09)
      class Smb2CompressionPatternPayloadV1 < BinData::Record
        endian :little
        hide   :reserved1, :reserved2

        uint8            :pattern,                          label: 'Pattern'
        uint8            :reserved1
        uint16           :reserved2
        uint32           :repetitions,                      label: 'Repetitions'
      end

      # An SMB2 SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED Packet as defined in
      # [2.2.42.1 SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/793db6bb-25b4-4469-be49-a8d7045ba3a6)
      class CompressionTransformHeaderUnchained < BinData::Record
        endian :little

        bit32            :protocol,                         label: 'Protocol ID Field', initial_value: 0xFC534D42
        uint32           :original_compressed_segment_size, label: 'Original Compressed Segment Size'
        uint16           :compression_algorithm,            label: 'Compression Algorithm'
        uint16           :flags,                            label: 'Flags'
        uint32           :offset,                           label: 'Offset / Length'
        string           :compressed_data,                  label: 'Compressed Data', read_length: :offset

        def self.from_hex(val)
          self.read(val.scan(/../).map { |x| x.hex.chr }.join)
        end
      end

      # An SMB2 SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED Packet as defined in
      # [2.2.42.2 SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/aa880fe8-ebed-4409-a474-ec6e0ca0dbcb)
      class CompressionTransformHeaderChained < BinData::Record
        endian :little

        bit32            :protocol,                         label: 'Protocol ID Field', initial_value: 0xFC534D42
        uint32           :original_compressed_segment_size, label: 'Original Compressed Segment Size'
        array            :payload_chain, read_until: -> { element.header.flags == 0 } do
          smb2_compression_chained_payload_header :header
          string                                  :compressed_data, read_length: -> { header.payload_length - (header.original_payload_size? ? header.original_payload_size.num_bytes : 0) }
        end

        def self.from_hex(val)
          self.read(val.scan(/../).map { |x| x.hex.chr }.join)
        end
      end

      # An SMB2 COMPRESSION_TRANSFORM_HEADER Packet as defined in
      # [2.2.42 SMB2 COMPRESSION_TRANSFORM_HEADER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0)
      # NOTE: On 2021-04-06 the official documentation split the definition of COMPRESSION_TRANSFORM_HEADER into the following two variants:
      #   * SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED
      #   * SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED
      #   This uses the unchained variant for backwards compatibility. Which one to be used depends on the #flags field.
      class CompressionTransformHeader < CompressionTransformHeaderUnchained
      end
    end
  end
end

