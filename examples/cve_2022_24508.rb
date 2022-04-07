#!/usr/bin/ruby

# This example script is used for testing the writing to a file.
# It will attempt to connect to a specific share and then write to a specified file.
# Example usage: ruby write_file.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE test.txt "data to write"
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and write "data to write" the file test.txt

require 'bundler/setup'
require 'ruby_smb'

require 'securerandom'

address      = ARGV[0]
username     = ARGV[1]
password     = ARGV[2]
share        = 'SMBBasic' #ARGV[3]
file         = "BVT_SMB2Compression_Chained_PatternV1_#{SecureRandom.uuid}"#ARGV[4]
data         = "A" * 256 #ARGV[5]
smb_versions = ARGV[6]&.split(',') || ['1','2','3']

path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: smb_versions.include?('1'), smb2: smb_versions.include?('2'), smb3: smb_versions.include?('3'), username: username, password: password, always_encrypt: false)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

file = tree.open_file(
  filename: file,
  attributes: RubySMB::Fscc::FileAttributes.new,
  write: true,
  delete: true,
  disposition: RubySMB::Dispositions::FILE_OPEN_IF
)

write_request = file.write_packet(data: "\xaa" * 256)
# since we're shorting the client#send_recv method, we need to add the applicable logic here
write_request = client.increment_smb_message_id(write_request)
write_request.smb2_header.session_id = client.session_id
# make sure we're signing if we need to based on the same logic from #send_recv
write_request = client.smb3_sign(write_request)

raw_chunks = [
  write_request.to_binary_s[0...write_request.offset_of(write_request.buffer)],
  write_request.to_binary_s[write_request.offset_of(write_request.buffer)...]
]

# there's definitely an opportunity here to make this easier to work with.
compressed_write_request = RubySMB::SMB2::Packet::CompressionTransformHeaderChained.new(
  original_compressed_segment_size: write_request.num_bytes,
  payload_chain: [
    {
      header: {
        compression_algorithm: RubySMB::SMB2::CompressionCapabilities::LZNT1,
        flags: 1,
        payload_length: RubySMB::Compression::LZNT1.compress(raw_chunks[0]).length + 4,
        original_payload_size: raw_chunks[0].length
      },
      compressed_data: RubySMB::Compression::LZNT1.compress(raw_chunks[0])
    },
    {
    header: {
        compression_algorithm: RubySMB::SMB2::CompressionCapabilities::Pattern_V1,
        flags: 0,
        payload_length: RubySMB::Compression::PatternV1.compress(raw_chunks[1]).length,
        original_payload_size: raw_chunks[1].length
      },
      compressed_data: RubySMB::Compression::PatternV1.compress(raw_chunks[1])
    },
  ]
)

client.send_packet(compressed_write_request, encrypt: tree.tree_connect_encrypt_data)
result = client.recv_packet(encrypt: tree.tree_connect_encrypt_data)
puts result.to_s
file.close
