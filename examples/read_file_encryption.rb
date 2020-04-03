#!/usr/bin/ruby

# This example script is used for testing the reading of a file.
# It will attempt to connect to a specific share and then read a specified file.
# Example usage: ruby read_file.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE short.txt
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and read the file short.txt

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
share    = ARGV[3]
file     = ARGV[4]
path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: false, smb2: false, smb3: true, username: username, password: password, encryption: true, compression: false)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

def bin_to_hex(s)
  s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
end
puts "SMB 3.1.1 Key Generation:"
puts "  - Session Key:    #{bin_to_hex(client.session_key)}"
puts "  - KDF Context:    #{bin_to_hex(client.preauth_integrity_hash_value)}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

file = tree.open_file(filename: file)

data = file.read
puts data
file.close
