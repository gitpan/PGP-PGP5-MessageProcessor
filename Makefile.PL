use ExtUtils::MakeMaker;

WriteMakefile
  ( 'NAME'     => 'PGP::PGP5::MessageProcessor',
    'VERSION_FROM'  => 'MessageProcessor.pm',
    'dist' => {
	       'COMPRESS'   => 'gzip', 
	       'SUFFIX'     => 'gz',
	      },
  );
