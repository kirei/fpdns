# $Id: Makefile.PL,v 1.4 2005/03/04 14:17:46 jakob Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME' => 'Net::DNS::Fingerprint',
    'VERSION_FROM' => 'Fingerprint.pm',
    'PREREQ_PM' => { Net::DNS => 0.42 },
    'EXE_FILES' => [ "apps/fpdns" ],
    'NO_META' => 1,
    'SIGN' => 1,
    clean => { FILES => "*~" },
);
