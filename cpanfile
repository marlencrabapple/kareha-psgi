requires 'CGI'; # this will be removed from the core modules in v5.22 so it
                # will probably need downloading from cpan at some point

requires 'CGI::Compile';
requires 'CGI::Emulate::PSGI';

requires 'JSON'; # this will probably be used a lot more in future releases
                 # plus i think its a core module now so i don't feel too guilty
                 
requires 'Plack';
requires 'Plack::Builder';
requires 'Plack::App::File';
requires 'Plack::App::WrapCGI';
