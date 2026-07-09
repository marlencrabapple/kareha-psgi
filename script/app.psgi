#!/usr/bin/env perl

package kareha::psgi::app;

use utf8;
use v5.40;

use lib 'lib';

use CGI::Compile;
use CGI::Emulate::PSGI;
use Const::Fast;
use CGI::Compile;
use Plack::Builder;
use Plack::App::File;
use IO::Handle::Common;

# use Plack::Middleware::Auth::Basic;
use Crypt::Argon2 qw(argon2id_pass argon2_verify);

use kareha::psgi;

const our $pathre => qr"^
   /(css|arch|res|thumb|src|img|kareha.js
   |(?:kareha|favicon)?.ico
   |(kareha|[0-9]+).html)
 "xx;

builder {
    enable "Auth::Basic", authenticator => sub ( $user, $pass, $env = \%ENV ) {
        fatal "WAKA_USER is unset, cannot lookup user."
          unless $ENV{WAKA_USER};

        fatal "WAKA_PWHASH is unset, cannot check check password."
          unless $ENV{WAKA_PWHASH};

        $user eq $ENV{WAKA_USER}
          && argon2_verify( $ENV{WAKA_PWHASH}, $pass );
      }
      unless $ENV{WAKA_NOLOGIN};

    if ( any { $_ } @ENV{qw(PLACK_DEVELOPMENT PLACK_DEBUG DEBUG)} ) {
        enable "Plack::Middleware::Devel::StackTrace",
          enable "Plack::Middleware::Debug";
    }

    if ( $ENV{SERVE_HTTP} ) {
        enable "Plack::Middleware::Static", path => $pathre root => './';

        enable "Plack::Middleware::Static",
          path => '/static',
          root => 's/';

        mount "/",
          Plack::App::File->new( file => '$app->config->{index_html}' )->to_app;
    }

    mount "/kareha.pl", kareha::psgi->new->to_psgi
}
