use strict;

use Plack::App::WrapCGI;
use Plack::App::File;
use Plack::Builder;

# Load Kareha
my $kareha_app = Plack::App::WrapCGI->new(script => "./kareha.pl")->to_app;

# These only work properly in CGI mode for whatever reason.
my $captcha_app = Plack::App::WrapCGI->new(script => "./captcha.pl", execute => 1)->to_app;
my $admin_app = Plack::App::WrapCGI->new(script => "./admin.pl", execute => 1)->to_app;

# Please don't use this outside of testing.
my $fileserve_app = Plack::App::File->new(root => "./");

my $app = builder {
  mount "/admin.pl" => $admin_app;
  mount "/captcha.pl" => $captcha_app;
  mount "/kareha.pl" => $kareha_app;
  mount "/" => $fileserve_app
}
