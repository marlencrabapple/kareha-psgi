use Object::Pad qw(:experimental(:all));;

package kareha::config;
role kareha::config;

use utf8;
use v5.40;

use Carp;
use Const::Fast;
use TOML::Tiny qw(from_toml to_toml);
use Path::Tiny;
use Data::Printer;

const our $S_NOADMIN => 'No \'admin_pass\' defined in the configuration';
const our $S_NOSECRET => 'No \'secret\' defined in the configuration';

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
field $config;

ADJUSTPARAMS ($params) {
  $source = path($source) unless ref $source eq 'Path::Tiny';
  const our $_config => { %$config_defaults
                       , from_toml($source->slurp_utf8)->%* };
  $config = $_config;
}
