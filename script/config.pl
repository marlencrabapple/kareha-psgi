#!/usr/bin/env perl
use Object::Pad qw(:experimental(:all));

package kareha::psgi::env;
role kareha::psgi::env;

use lib 'lib';

use utf8;
use v5.40;

use Carp;
use Const::Fast;
use TOML::Tiny qw(from_toml to_toml);
use Path::Tiny;
use Data::Printer;

const our $S_NOADMIN => 'No ADMIN_PASS defined in the configuration';	# Returns error when the config is incomplete
const our $S_NOSECRET => 'No SECRET defined in the configuration';	# Returns error when the config is incomplete

const our $config_default_path => path('config.default.toml');

our $_config_default;

try {
  $_config_default = from_toml($config_default_path->slurp_utf8)
}
catch ($e) {
  croak $e if $ENV{PRODUCTION};
  carp $e
}

const our $config_defaults => $_config_default;

field $source :param(open);
field $_config :inheritable :reader(config);

ADJUSTPARAMS ($params) {
  $source = path($source) unless ref $source eq 'Path::Tiny';
  const our $config => { %$config_defaults
                       , from_toml($source->slurp_utf8)->%* };
  $_config = $config;
}

p $config_defaults;
1;

package main;
class main :does(kareha::psgi::env);

use utf8;
use v5.40;

use JSON::MaybeXS;
use Data::Printer;

method print {
    p $self->config;
    say encode_json($self->config);
}

my $env = main->new( open => 'config.toml');
$env->print
