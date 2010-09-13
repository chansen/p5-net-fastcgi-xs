use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'         => 'Net::FastCGI::XS',
    'VERSION_FROM' => 'lib/Net/FastCGI/XS.pm',
    'PREREQ_PM'    => {}
);

