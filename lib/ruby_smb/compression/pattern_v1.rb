module RubySMB
  module Compression
    module PatternV1
      def self.compress(buf)
        raise EncodingError, 'incompatible buffer' unless Set.new(buf.bytes).length == 1

        [buf.bytes.first, buf.length].pack('CxxxV')
      end

      def self.decompress(buf)
        raise EncodingError, 'invalid buffer length' unless buf.length == 8

        pattern, repetitions = buf.unpack('CxxxV')
        pattern.chr * repetitions
      end
    end
  end
end
