package Net::FastCGI::Protocol::XS;

use strict;
use warnings;
use Net::FastCGI::XS;

BEGIN {
    our $VERSION   = '0.01';
    our @EXPORT_OK = qw[ build_begin_request
                         build_begin_request_body
                         build_begin_request_record
                         build_end_request
                         build_end_request_body
                         build_end_request_record
                         build_header
                         build_params
                         build_record
                         build_stream
                         build_unknown_type_body
                         build_unknown_type_record
                         check_params
                         parse_begin_request_body
                         parse_end_request_body
                         parse_header
                         parse_params
                         parse_record
                         parse_record_body
                         parse_unknown_type_body
                         is_known_type
                         is_management_type
                         is_discrete_type
                         is_stream_type
                         get_record_length
                         get_role_name
                         get_type_name
                         get_protocol_status_name ];

    my @TODO       = qw[ build_begin_request
                         build_end_request
                         check_params ];


    require Net::FastCGI::Protocol::PP;
            Net::FastCGI::Protocol::PP->import(@TODO);

    require Exporter;
    *import = \&Exporter::import;
}

1;

