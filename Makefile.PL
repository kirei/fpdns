use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'         => 'Net::DNS::Fingerprint',
    'VERSION_FROM' => 'lib/Net/DNS/Fingerprint.pm',
    'MIN_PERL_VERSION' => '5.10.0',
    'PREREQ_PM'    => { Net::DNS => 0.42 },
    'EXE_FILES'    => ["apps/fpdns"],
    'NO_META'      => 1,
    'SIGN'         => 0,
    clean          => { FILES => "*~" },
);
