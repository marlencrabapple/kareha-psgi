requires 'perl', 'v5.40';

requires 'Object::Pad';

requires 'TOML::Tiny';
requires 'Crypt::Argon2';
requires 'List::AllUtils';
requires 'Syntax::Keyword::Try';
requires 'System::CPU', '1.03';

requires 'Plack', '1.0052',
  dist => 'CRABAPP/Plack-1.0052-TRIAL.tar.gz';

requires 'Frame', '0.1.3',
  dist => 'CRABAPP/Frame-0.1.3-TRIAL.tar.gz';

requires 'JSON::MaybeXS', '1.004003';

requires 'CGI::Compile', '0.25';
requires 'CGI::Emulate::PSGI', '0.23';

requires 'DBI', '1.643';
requires 'DBD::SQLite', '1.70';

requires 'Path::Tiny', '0.122';
requires 'Data::Printer';

on 'develop' => sub {
  requires 'Perl::Tidy', '20220613';
  requires 'Perl::Critic', '1.140';
  requires 'Perl::Critic::Community';
};

on 'test' => sub {
  requires 'Test::More', '0.98';
};

on 'build' => sub {
  requires 'Minilla'
};
