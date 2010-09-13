package Net::FastCGI::XS;

use strict;
use warnings;

BEGIN {
    our $VERSION = '0.01';
    require XSLoader; XSLoader::load(__PACKAGE__, $VERSION);
}

1;
