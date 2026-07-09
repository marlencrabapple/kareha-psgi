#!/usr/bin/env perl
use Object::Pad qw(:experimental(:all));

package kareha::psgi::env;

use lib 'lib';

role kareha::psgi::env : does(kareha::config);

use utf8;
use v5.40;

use TOML::Tiny qw(from_toml to_toml);

package main;

class main : does(kareha::psgi::env);

use utf8;
use v5.40;

use TOML::Tiny qw(from_toml to_toml);

field $clidest : reader : param //= {};
field $infile { $clidest->{config_file} };

field $app
  : reader
  : param { kareha->psgi->new(%$clidest) };

method cli : common ( $argv = \@ARGV ) {
    my %cliopt =
      ( configfile => $infile, debug => 0, verbose => 0, outfmt => 'toml' );

    GetOptionsFromArray( $argv, \%cliopt,
        'configfile|config_file|configin|infile=s@',
        'verbose+', 'debug=i' );

    my $self = $class->new( app => kareha->psgi->new(%cliopt) );
    $self    #,$app;

}

method print_config {
    dmsg $self->config, $self->config_file;
    say $toml->encode( $self->config_files );
}

my $env = main->new( config_file => $configfile );
$env->print
