#!/usr/bin/env perl

use utf8;
use v5.40;

use lib '.';

use CGI::Compile;
use Plack::Builder;
use Plack::App::File;
use CGI::Emulate::PSGI;
use Plack::Middleware::Auth::Basic;
use Crypt::Argon2 qw(argon2id_pass argon2_verify);

our $kareha = CGI::Emulate::PSGI->handler(CGI::Compile->compile(
		"./kareha.pl", "kareha"));

our $captcha = CGI::Emulate::PSGI->handler(CGI::Compile->compile(
		"./captcha.pl", "captcha"))
                  if $ENV{WAKA_CAPTCHA};

our $admin = CGI::Emulate::PSGI->handler(CGI::Compile->compile(
		"./admin.pl", "admin"));

builder {
  enable "Auth::Basic", authenticator => sub ($user, $pass, $env) {
    die "No username defined in \$ENV{WAKA_USER}" unless $ENV{WAKA_USER};
    die "No password hash defined in \$ENV{WAKA_PWHASH}"
      unless $ENV{WAKA_PWHASH};

    $user eq $ENV{WAKA_USER}
      && argon2_verify($ENV{WAKA_PWHASH}, $pass)
  } unless $ENV{WAKA_NOLOGIN};

  enable "Plack::Middleware::Static",
    path => qr{^/(css|arch|res|thumb|src|img|kareha.js|(?:kareha|favicon)?.ico|(kareha|[0-9]+).html)},
    root => './';

  enable "Plack::Middleware::Static",
    path => '/static',
    root => 's/';
  
  mount "/", Plack::App::File->new(file => 'index.html')->to_app;

  mount "/kareha.pl", $kareha;
  mount "/admin.pl", $admin;
  mount "/captcha.pl", $captcha if $captcha
}

