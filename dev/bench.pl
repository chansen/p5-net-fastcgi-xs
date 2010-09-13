#!/usr/bin/perl -w

use strict;
use warnings;

use Benchmark                  qw[];
use Net::FastCGI::XS           qw[];
use Net::FastCGI::Protocol::PP qw[];

my $environ = {
    GATEWAY_INTERFACE    => "CGI/1.1",
    HTTPS                => "OFF",
    HTTP_ACCEPT          => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    HTTP_ACCEPT_CHARSET  => "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
    HTTP_ACCEPT_ENCODING => "gzip,deflate",
    HTTP_ACCEPT_LANGUAGE => "sv-se,sv;q=0.8,en-us;q=0.5,en;q=0.3",
    HTTP_HOST            => "localhost:80",
    HTTP_KEEP_ALIVE      => 300,
    HTTP_USER_AGENT      => "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; sv-SE; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6",
    PATH_INFO            => "/",
    REMOTE_ADDR          => "127.0.0.1",
    REMOTE_HOST          => "localhost",
    REMOTE_PORT          => 41049,
    REQUEST_METHOD       => "GET",
    REQUEST_URI          => "/",
    SCRIPT_NAME          => "/",
    SERVER_NAME          => "localhost",
    SERVER_PORT          => 80,
    SERVER_PROTOCOL      => "HTTP/1.1",
    SERVER_SOFTWARE      => "Foo-Bar/0.0",
};

print "\n\nbuild_params()\n\n";

{
    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::build_params($environ);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::build_params($environ);
        },
    });
}

print "\n\nparse_params()\n\n";

{
    my $octets = Net::FastCGI::Protocol::PP::build_params($environ);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::parse_params($octets);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::parse_params($octets);
        }
    });
}

print "\n\nbuild_record()\n\n";

{
    my @values = (1, 2, "X" x 1024**8);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::build_record(@values);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::build_record(@values);
        }
    });
}

print "\n\nparse_record() scalar context\n\n";

{
    my $octets = Net::FastCGI::Protocol::PP::build_record(5, 2, "X" x 1024**8);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::parse_record($octets);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::parse_record($octets);
        }
    });
}

print "\n\nparse_record() list context\n\n";

{
    my $octets = Net::FastCGI::Protocol::PP::build_record(5, 2, "X" x 1024**8);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my ($t, $i, $c) = Net::FastCGI::Protocol::XS::parse_record($octets);
        },
        'PP' => sub { 
            my ($t, $i, $c) = Net::FastCGI::Protocol::PP::parse_record($octets);
        }
    });
}

print "\n\nbuild_stream()\n\n";

{
    my @values = (1, 2, "X" x 32760**8, 1);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::build_stream(@values);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::build_stream(@values);
        }
    });
}

print "\n\nparse_header() scalar context\n\n";

{
    my $octets = Net::FastCGI::Protocol::XS::build_header((1) x 4);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::parse_header($octets);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::parse_header($octets);
        }
    });
}

print "\n\nparse_header() list context\n\n";

{
    my $octets = Net::FastCGI::Protocol::XS::build_header((1) x 4);

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my ($t, $i, $c, $p) = Net::FastCGI::Protocol::XS::parse_header($octets);
        },
        'PP' => sub { 
            my ($t, $i, $c, $p) = Net::FastCGI::Protocol::PP::parse_header($octets);
        }
    });
}

print "\n\nbuild_header()\n\n";

{
    my @values = (1) x 4;

    Benchmark::cmpthese( -10, {
        'XS' => sub { 
            my $r = Net::FastCGI::Protocol::XS::build_header(@values);
        },
        'PP' => sub { 
            my $r = Net::FastCGI::Protocol::PP::build_header(@values);
        }
    });
}


