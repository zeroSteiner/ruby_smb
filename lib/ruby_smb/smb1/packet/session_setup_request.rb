module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_SESSION_SETUP_ANDX Request Packet as defined in
      # [2.2.4.6.1](https://msdn.microsoft.com/en-us/library/cc246328.aspx)
      class SessionSetupRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {SessionSetupRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block   :andx_block
          uint16        :max_buffer_size,       label: 'Max Buffer Size'
          uint16        :max_mpx_count,         label: 'Max Mpx Count'
          uint16        :vc_number,             label: 'VC Number'
          uint32        :session_key,           label: 'Session Key'
          uint16        :security_blob_length,  label: 'Security Blob Length'
          uint32        :reserved
          capabilities  :capabilities
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          string     :security_blob,  label: 'Security Blob (GSS-API)'
          stringz16  :native_os,      label: 'Native OS'
          stringz16  :native_lan_man, label: 'Native LAN Manager'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
        end

      end
    end
  end
end
