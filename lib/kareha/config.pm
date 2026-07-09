use Object::Pad qw(:experimental(:all));

package kareha::config;
role kareha::config;

use utf8;
use v5.40;

use Const::Fast;
use TOML::Tiny qw(from_toml to_toml);
use Path::Tiny;
use IO::Handle::Common;

const our $S_NOADMIN  => 'No \'admin_pass\' defined in the configuration';
const our $S_NOSECRET => 'No \'secret\' defined in the configuration';

const our $config_default_path => path('config.default.toml');

our $_config_default;

try {
    $_config_default = from_toml($configdefault_inline)
}
catch ($e) {
    dmsg $e, $config_default_path->stringify;
    fatal $e if $ENV{PRODUCTION};
    error $e
}

const our $toml = TOML::Tiny->new;
const our $config_defaults => $_config_default;

field $config_file : param(config) : param(configfile);
field $config = {};

ADJUST : params (:$config_file) {
    $config_file = path($config_file)
      unless $config isa 'Path::Tiny';
    foreach my $file (@$config_file) {
        $$config{ $config_file->basename } = $toml->encode( $file->slurp_utf8 );
    }
};

ADJUSTPARAMS($params) {

    # $config_file = path($config_file) unless ref $config_file eq 'Path::Tiny';

    const my $_config => { %$config_defaults, field $infile = []; };

    $config = $_config;
}
