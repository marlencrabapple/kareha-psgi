use Object::Pad;

package wakautils 8.12;
role wakautils :does(kareha::config);

use utf8;
use v5.40;

use feature 'bareword_filehandles';

use Carp;
use Const::Fast::Exporter;
use HTTP::Tinyish;
use MIME::Base64;
use Path::Tiny;
use FFmpeg::Inline;
use Time::Local;
use Socket;
use JSON::MaybeXS;
use File::Basename;
use Data::Printer;
use Digest::MD5;
use Encode qw(encode decode);

use kareha::config;

const our $MAX_UNICODE => 1114111;

#
# HTML utilities
#

const our $protocol_re => qr{(?:http://|https://|ftp://|mailto:|news:|irc:)};
const our $url_re => qr{(${protocol_re}[^\s<>()"]*?(?:\([^\s<>()"]*?\)[^\s<>()"]*?)*)((?:\s|<|>|"|\.||\]|!|\?|,|&#44;|&quot;)*(?:[\s<>()"]|$))};

method protocol_regexp :common { return $protocol_re }

method url_regexp :common { return $url_re }

method abbreviate_html ($html,$max_lines=$self->config->{max_lines_shown},$approx_len=$self->config->{approx_line_length})
{
	my ($lines,$chars,@stack);

	return undef unless($max_lines);

    const my $abbrev_html_re = qr!(?:([^<]+)|<(/?)(\w+).*?(/?)>)!;
	const my $abbrev_html_re2 = qr!^(?:\s*</\w+>)*\s*$!s;

	while ($html =~ /$abbrev_html_re/g) {
		my ($text,$closing,$tag,$implicit)=($1,$2,(lc($3 // '') eq '' ? undef : $3),$4);

		if($text) { $chars+=length $text; }
		else
		{
			push @stack,$tag if(!$closing and !$implicit);
			pop @stack if($closing);

			if(($closing or $implicit) and ($tag eq "p" or $tag eq "blockquote" or $tag eq "pre"
			or $tag eq "li" or $tag eq "ol" or $tag eq "ul" or $tag eq "br"))
			{
				$lines+=int($chars/$approx_len)+1;
				$lines++ if($tag eq "p" or $tag eq "blockquote");
				$chars=0;
			}

			if($lines && $lines>=$max_lines)
			{
 				# check if there's anything left other than end-tags
 				return undef if (substr $html,pos $html) =~ $abbrev_html_re2;

				my $abbrev=substr $html,0,pos $html;
				while(my $tag=pop @stack) { $abbrev.="</$tag>" }

				return $abbrev;
			}
		}
	}

	return undef;
}

method sanitize_html($html,%tags)
{
	my (@stack,$clean);
	const my $entity_re => qr/&(?!\#[0-9]+;|\#x[0-9a-fA-F]+;|amp;|lt;|gt;)/;

	const my $htmlsan_re1 = qr/(?:([^<]+)|<([^<>]*)>|(<))/;
	const my $htmlsan_re2 = qr!^\s*(/?)\s*([a-z0-9_:\-\.]+)(?:\s+(.*?)|)\s*(/?)\s*$!;

	while($html =~ /$htmlsan_re1/sg) {
		my ($text, $tag, $lt) = ($1, $2, $3);

		if($lt) {
			$clean.="&lt;";
		}
		elsif($text) {
			$text=~s/$entity_re/&amp;/g;
			$text=~s/>/&gt;/g;
			$clean.=$text;
		}
		else {
			if($tag =~ /$htmlsan_re2/si) {
				my ($closing,$name,$args,$implicit)=($1,lc($2),$3,$4);

				if($tags{$name}) {
					if($closing) {
						if(grep { $_ eq $name } @stack) {
							my $entry;

							do {
								$entry=pop @stack;
								$clean.="</$entry>";
							} until $entry eq $name;
						}
					}
					else {
						my %args;

						$args =~ s/\s/ /sg;

					    const my $htmlsan_re3 = qr/([a-z0-9_:\-\.]+)(?:\s*=\s*(?:'([^']*?)'|"([^"]*?)"|['"]?([^'" ]*))|)/;

						while($args =~ /$htmlsan_re3/gi) {
							my ($arg,$value)=(lc($1),defined($2)?$2:defined($3)?$3:$4);
							$value=$arg unless defined($value);

							my $type=$tags{$name}{args}{$arg};

							if($type) {
								my $passes=1;

								if($type=~/url/i) { $passes=0 unless $value=~/(?:^${protocol_re}|^[^:]+$)/ }
								if($type=~/number/i) { $passes=0 unless $value=~/^[0-9]+$/  }

								if($passes) {
									$value=~s/$entity_re/&amp;/g;
									$args{$arg}=$value;
								}
							}
						}

						$args{$_} = $tags{$name}{forced}{$_} for (keys %{$tags{$name}{forced}}); # override forced arguments

						my $cleanargs=join " ",map {
							my $value=$args{$_};
							$value=~s/'/%27/g;
							"$_='$value'";
						} keys %args;

						$implicit="/" if($tags{$name}{empty});

						push @stack,$name unless $implicit;

						$clean.="<$name";
						$clean.=" $cleanargs" if $cleanargs;
						#$clean.=" $implicit" if $implicit;
						$clean.=">";
						$clean.="</$name>" if $implicit;
					}
				}
			}
		}
	}

	my $entry;
	while ($entry = pop @stack) { $clean .= "</$entry>" }

	$clean;
}

method describe_allowed :common (%tags)
{
	return join ", ",map { $_.($tags{$_}{args}?" (".(join ", ",sort keys %{$tags{$_}{args}}).")":"") } sort keys %tags;
}

method do_wakabamark($text, $handler= undef, $simplify = undef) {
	my $res;

	my @lines=split /(?:\r\n|\n|\r)/,$text;

	while (defined($_=$lines[0])) {
		if (/^\s*$/) { shift @lines; } # skip empty lines
		elsif (/^(1\.|[\*\+\-]) /) # lists
		{
			my ($tag,$re,$skip,$html);

			if ($1 eq "1.") { $tag="ol"; $re=qr/[0-9]+\./; $skip=1; }
			else { $tag="ul"; $re=qr/\Q$1\E/; $skip=0; }

			while($lines[0]=~/^($re)(?: |\t)(.*)/)
			{
				my $spaces=(length $1)+1;
				my $item="$2\n";
				shift @lines;

				while ($lines[0]=~/^(?: {1,$spaces}|\t)(.*)/) { $item .= "$1\n"; shift @lines }
				$html .= "<li>".do_wakabamark($item,$handler,1)."</li>";

				if($skip) { while(@lines and $lines[0]=~/^\s*$/) { shift @lines; } } # skip empty lines
			}
			$res.="<$tag>$html</$tag>";
		}
		elsif(/^(?:    |\t)/) # code sections
		{
			my @code;
			while($lines[0]=~/^(?:    |\t)(.*)/) { push @code,$1; shift @lines; }
			$res.="<pre><code>".(join "<br />",@code)."</code></pre>";
		}
		elsif(/^&gt;/) # quoted sections
		{
			my @quote;
			while($lines[0]=~/^(&gt;.*)/) { push @quote,$1; shift @lines; }
			$res.="<blockquote>".do_spans($handler,@quote)."</blockquote>";

			#while($lines[0]=~/^&gt;(.*)/) { push @quote,$1; shift @lines; }
			#$res.="<blockquote>".do_blocks($handler,@quote)."</blockquote>";
		}
		else # normal paragraph
		{
			my @text;
			while($lines[0]!~/^(?:\s*$|1\. |[\*\+\-] |&gt;|    |\t)/) { push @text,shift @lines; }
			if(!defined($lines[0]) and $simplify) { $res.=do_spans($handler,@text) }
			else { $res.="<p>".do_spans($handler,@text)."</p>" }
		}
		$simplify=0;
	}

	return $res;
}

method do_spans :common ($handler) {
	return join "<br>",map
	{
		my $line=$_;
		my @hidden;

		# hide <code> sections
		$line=~s{ (?<![\x80-\x9f\xe0-\xfc]) (`+) ([^<>]+?) (?<![\x80-\x9f\xe0-\xfc]) \1}{push @hidden,"<code>$2</code>"; "<!--$#hidden-->"}sgex;

		# make URLs into links and hide them
		$line=~s{$url_re}{push @hidden,"<a href=\"$1\" rel=\"nofollow\">$1\</a>"; "<!--$#hidden-->$2"}sge;

		# do <strong>
		$line=~s{ (?<![0-9a-zA-Z\*_\x80-\x9f\xe0-\xfc]) (\*\*|__) (?![<>\s\*_]) ([^<>]+?) (?<![<>\s\*_\x80-\x9f\xe0-\xfc]) \1 (?![0-9a-zA-Z\*_]) }{<strong>$2</strong>}gx;

		# do <em>
		$line=~s{ (?<![0-9a-zA-Z\*_\x80-\x9f\xe0-\xfc]) (\*|_) (?![<>\s\*_]) ([^<>]+?) (?<![<>\s\*_\x80-\x9f\xe0-\xfc]) \1 (?![0-9a-zA-Z\*_]) }{<em>$2</em>}gx;

		# do ^H
		if($]>5.007)
		{
			my $regexp;
			$regexp=qr/(?:&#?[0-9a-zA-Z]+;|[^&<>])(?<!\^H)(??{$regexp})?\^H/;
			$line=~s{($regexp)}{"<del>".(substr $1,0,(length $1)/3)."</del>"}gex;
		}

		$line=$handler->($line) if($handler);

		# fix up hidden sections
		$line=~s{<!--([0-9]+)-->}{$hidden[$1]}ge;

		$line;
	} @_;
}

method compile_template :common ($str,$nostrip="")
{
	my $code;

	unless($nostrip)
	{
		$str=~s/^\s+//;
		$str=~s/\s+$//;
		$str=~s/\n\s*/ /sg;
	}

	while($str=~m!(.*?)(<(/?)(var|const|if|loop)(?:|\s+(.*?[^\\]))>|$)!sg)
	{
		my ($html,$tag,$closing,$name,$args)=($1,$2,$3,$4,$5);

		$html=~s/(['\\])/\\$1/g;
		$code.="\$res.='$html';" if(length $html);
		$args=~s/\\>/>/g if $args;

		if($tag)
		{
			if($closing)
			{
				if($name eq 'if') { $code.='}' }
				elsif($name eq 'loop') { $code.='$$_=$__ov{$_} for(keys %__ov);}}' }
			}
			else
			{
				if($name eq 'var') { $code.='$res.=eval{'.$args.'};' }
				elsif($name eq 'const') { my $const=eval $args; $const=~s/(['\\])/\\$1/g; $code.='$res.=\''.$const.'\';' }
				elsif($name eq 'if') { $code.='if(eval{'.$args.'}){' }
				elsif($name eq 'loop')
				{ $code.='my $__a=eval{'.$args.'};if($__a){for(@$__a){my %__v=%{$_};my %__ov;for(keys %__v){$__ov{$_}=$$_;$$_=$__v{$_};}' }
			}
		}
	}

	my $sub=eval
		'no strict; method { '.
		'my $port=$ENV{SERVER_PORT}==80?"":":$ENV{SERVER_PORT}";'.
		'my $self=$ENV{SCRIPT_NAME};'.
		'my $absolute_self="http://$ENV{SERVER_NAME}$port$ENV{SCRIPT_NAME}";'.
		'my ($path)=$ENV{SCRIPT_NAME}=~m!^(.*/)[^/]+$!;'.
		'my $absolute_path="http://$ENV{SERVER_NAME}$port$path";'.
		'my %__v=@_;my %__ov;for(keys %__v){$__ov{$_}=$$_;$$_=$__v{$_};}'.
		'my $res;'.
		$code.
		'$$_=$__ov{$_} for(keys %__ov);'.
		'return $res; }';

	die "Template format error" unless $sub;

	return $sub;
}

method template_for :common ($var,$start,$end)
{
	return [map +{$var=>$_},($start..$end)];
}

method include :common ($filename)
{
    my $file = path($filename)->slurp_utf8;

	$file=~s/^\s+//;
	$file=~s/\s+$//;
	$file=~s/\n\s*/ /sg;

	return $file;
}


method forbidden_unicode ($dec,$hex)
{
	return 1 if length($dec)>7 or length($hex)>7; # too long numbers
	my $ord=($dec or hex $hex);

	return 1 if $ord > $self->config->{max_unicode}; # outside unicode range
	return 1 if $ord<32; # control chars
	return 1 if $ord>=0x7f and $ord<=0x84; # control chars
	return 1 if $ord>=0xd800 and $ord<=0xdfff; # surrogate code points
	return 1 if $ord>=0x202a and $ord<=0x202e; # text direction
	return 1 if $ord>=0xfdd0 and $ord<=0xfdef; # non-characters
	return 1 if $ord % 0x10000 >= 0xfffe; # non-characters
	return 0;
}

method clean_string :common ($str,$cleanentities=undef)
{

	if($cleanentities) { $str=~s/&/&amp;/g } # clean up &
	else
	{
		$str=~s/&(#([0-9]+);|#x([0-9a-fA-F]+);|)/
			if($1 eq "") { '&amp;' } # change simple ampersands
			elsif(forbidden_unicode($2,$3))  { "" } # strip forbidden unicode chars
			else { "&$1" } # and leave the rest as-is.
		/ge  # clean up &, excluding numerical entities
	}

	$str=~s/\</&lt;/g; # clean up brackets for HTML tags
	$str=~s/\>/&gt;/g;
	$str=~s/"/&quot;/g; # clean up quotes for HTML ode
	$str=~s/'/&#39;/g;
	$str=~s/,/&#44;/g; # clean up commas for some reason I forgot

	$str=~s/[\x00-\x08\x0b\x0c\x0e-\x1f]//g; # remove control chars

	return $str;
}

method decode_string ($str,$charset = $self->config->{charset}, $noentities = undef)
{

	state $use_unicode=1;

	$str=decode($charset,$str) if $use_unicode;

	$str=~s{(&#([0-9]*)([;&])|&#([x&])([0-9a-f]*)([;&]))}{
		my $ord=($2 or hex $5);
		if($3 eq '&' or $4 eq '&' or $5 eq '&') { $1 } # nested entities, leave as-is.
		elsif(forbidden_unicode($2,$5))  { "" } # strip forbidden unicode chars
		elsif($ord==35 or $ord==38) { $1 } # don't convert & or #
		elsif($use_unicode) { chr $ord } # if we have unicode support, convert all entities
		elsif($ord<128) { chr $ord } # otherwise just convert ASCII-range entities
		else { $1 } # and leave the rest as-is.
	}gei unless $noentities;

	$str=~s/[\x00-\x08\x0b\x0c\x0e-\x1f]//g; # remove control chars

	$str
}

method escamp :common ($str) {
	$str=~s/&/&amp;/g;
	$str
}

method urlenc :common ($str) {
	$str=~s/([^\w ])/"%".sprintf("%02x",ord $1)/sge;
	$str=~s/ /+/sg;
	$str
}

method clean_path :common ($str) {
	$str=~s!([^\w/._\-])!"%".sprintf("%02x",ord $1)!sge;
	$str
}


#
# Javascript utilities
#

method clean_to_js :common ($str) {
	$str=~s/&amp;/\\x26/g;
	$str=~s/&lt;/\\x3c/g;
	$str=~s/&gt;/\\x3e/g;
	$str=~s/&quot;/\\x22/g; #"
	$str=~s/(&#39;|')/\\x27/g;
	$str=~s/&#44;/,/g;
	$str=~s/&#[0-9]+;/sprintf "\\u%04x",$1/ge;
	$str=~s/&#x[0-9a-f]+;/sprintf "\\u%04x",hex($1)/gie;
	$str=~s/(\r\n|\r|\n)/\\n/g;

	return "'$str'";
}

method js_string :common ($str) {
	$str=~s/\\/\\\\/g;
	$str=~s/'/\\'/g;
	$str=~s/([\x00-\x1f\x80-\xff<>&])/sprintf "\\x%02x",ord($1)/ge;
	eval '$str=~s/([\x{100}-\x{ffff}])/sprintf "\\u%04x",ord($1)/ge';
	$str=~s/(\r\n|\r|\n)/\\n/g;

	"'$str'";
}

method js_array :common {
	"[".(join ",",@_)."]";
}

method js_hash :common (%hash) {
  "{".(join ",",map "'$_':$hash{$_}",keys %hash)."}";
}


#
# HTTP utilities
#

# LIGHTWEIGHT HTTP/1.1 CLIENT
# by fatalM4/coda, modified by WAHa.06x36

const our $CACHEFILE_PREFIX => 'cache-'; # you can make this a directory (e.g. 'cachedir/cache-' ) if you'd like
const our $FORCETIME => '0.04'; 	# If the cache is less than (FORCETIME) days old, don't even attempt to refresh.
                                    # Saves everyone some bandwidth. 0.04 days is ~ 1 hour. 0.0007 days is ~ 1 min.
eval 'use IO::Socket::INET'; # Will fail on old Perl versions!

method get_http($url,$maxsize=undef,$referer=undef,$cacheprefix=undef)
{
	my ($host,$port,$doc)=$url=~m!^(?:http://|)([^/]+)(:[0-9]+|)(.*)$!;
	$port=80 unless($port);

	my $hash=encode_base64(rc4(null_string(6),"$host:$port$doc",0),"");
	$hash=~tr!/+!_-!; # remove / and +
	my $cachefile=($cacheprefix or $CACHEFILE_PREFIX).($doc=~m!([^/]{0,15})$!)[0]."-$hash"; # up to 15 chars of filename
	my ($modified,$cache);

	if(open CACHE,"<",$cachefile)  # get modified date and cache contents
	{
		$modified=<CACHE>;
		$cache=join "",<CACHE>;
		chomp $modified;
		close CACHE;

		return $cache if((-M $cachefile)<$FORCETIME);
	}

	my $sock=IO::Socket::INET->new("$host:$port") or return $cache;
	print $sock "GET $doc HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n";
	print $sock "If-Modified-Since: $modified\r\n" if $modified;
	print $sock "Referer: $referer\r\n" if $referer;
	print $sock "\r\n"; #finished!

	# header
	my ($line,$statuscode,$lastmod);
	do {
		$line=<$sock>;
		$statuscode=$1 if($line=~/^HTTP\/1\.1 (\d+)/);
		$lastmod=$1 if($line=~/^Last-Modified: (.*)/);
	} until ($line=~/^\r?\n/);

	# body
	{
	my ($line,$output);
	while($line=<$sock>)
	{
		$output.=$line;
		last if $maxsize and $output>=$maxsize;
	}
	undef $sock;

	if($statuscode=="200")
	{
		#navbar changed, update cache
		if(open our $cachefh,">$cachefile")
		{
			print $cachefh "$lastmod\n";
			print $cachefh $output;
			close $cachefh or die "close cache: $!";
		}
		return $output;
	}
	else # touch and return cache, or nothing if no cache
	{
		utime(time,time,$cachefile);
		return $cache;
	}
	}
}

method make_cookies :common (%cookies)
{

	my $charset=$cookies{'-charset'};
	my $expires=($cookies{'-expires'} or time+14*24*3600);
	my $autopath=$cookies{'-autopath'};
	my $path=$cookies{'-path'};

	my $date=make_date($expires,"cookie");

	unless($path)
	{
		if($autopath eq 'current') { ($path)=$ENV{SCRIPT_NAME}=~m!^(.*/)[^/]+$! }
		elsif($autopath eq 'parent') { ($path)=$ENV{SCRIPT_NAME}=~m!^(.*?/)(?:[^/]+/)?[^/]+$! }
		else { $path='/'; }
	}

	foreach my $name (keys %cookies)
	{
		next if($name=~/^-/); # skip entries that start with a dash

		my $value=$cookies{$name};
		$value="" unless(defined $value);

		$value=cookie_encode($value,$charset);

		print "Set-Cookie: $name=$value; path=$path; expires=$date;\n";
	}
}

method cookie_encode ($str, $charset = $self->config->{charset}) {
	if ($charset) {
		$str=Encode::decode($charset,$str);

		# use constant 
			$str=~s/&\#([0-9]+);/chr $1/ge;
			$str=~s/&\#x([0-9a-f]+);/chr hex $1/gei;
		}

		$str=~s/([^0-9a-zA-Z])/
			my $c=ord $1;
			sprintf($c>255?'%%u%04x':'%%%02x',$c);
		/sge;


	return $str;
}

method get_xhtml_content_type ($charset=$self->config->{charset},$usexhtml=$self->config->{use_xhtml})
{
	my $type;

	if($usexhtml and $ENV{HTTP_ACCEPT}=~/application\/xhtml\+xml/) { $type="application/xhtml+xml"; }
	else { $type="text/html"; }

	$type.="; charset=$charset" if($charset);

	return $type;
}

method expand_filename :common ($filename)
{
	return $filename if($filename=~m!^/!);
	return $filename if($filename=~m!^\w+:!);

	my ($self_path)=$ENV{SCRIPT_NAME}=~m!^(.*/)[^/]+$!;
	"$self_path$filename";
}

#
# Network utilities
#

method resolve_host :common ($ip)
{
	(gethostbyaddr inet_aton($ip),AF_INET or $ip);
}


#
# Data utilities
#

method process_tripcode($name,$tripkey,$secret = $self->config->{secret},$charset = $self->config->{charset},$nonamedecoding=undef)
{
	$tripkey="!" unless($tripkey);

	if($name=~/^(.*?)((?<!&)#|\Q$tripkey\E)(.*)$/)
	{
		my ($namepart,$marker,$trippart)=($1,$2,$3);
		my $trip;

		$namepart=decode_string($namepart,$charset) unless $nonamedecoding;
		$namepart=clean_string($namepart);

		if($secret and $trippart=~s/(?:\Q$marker\E)(?<!&#)(?:\Q$marker\E)*(.*)$//) # do we want secure trips, and is there one?
		{
			my $str=$1;
			my $maxlen=255-length($secret);
			$str=substr $str,0,$maxlen if(length($str)>$maxlen);
#			$trip=$tripkey.$tripkey.encode_base64(rc4(null_string(6),"t".$str.$secret),"");
			$trip=$tripkey.$tripkey.hide_data($1,6,"trip",$secret,1);
			return ($namepart,$trip) unless($trippart); # return directly if there's no normal tripcode
		}

		# 2ch trips are processed as Shift_JIS whenever possible
		eval 'use Encode qw(decode encode)';
		unless($@)
		{
			$trippart=decode_string($trippart,$charset);
			$trippart=encode("Shift_JIS",$trippart,0x0200);
		}

		$trippart=clean_string($trippart);
		my $salt=substr $trippart."H..",1,2;
		$salt=~s/[^\.-z]/./g;
		$salt=~tr/:;<=>?@[\\]^_`/ABCDEFGabcdef/;
		$trip=$tripkey.(substr crypt($trippart,$salt),-10).$trip;

		return ($namepart,$trip);
	}

	return clean_string($name) if $nonamedecoding;
	return (clean_string(decode_string($name,$charset)),"");
}

method make_date($time,$style,@locdays)
{
	my @days=qw(Sun Mon Tue Wed Thu Fri Sat);
	my @months=qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	@locdays=@days unless(@locdays);

	if($style eq "2ch")
	{
		my @ltime=localtime($time);

		return sprintf("%04d-%02d-%02d %02d:%02d",
		$ltime[5]+1900,$ltime[4]+1,$ltime[3],$ltime[2],$ltime[1]);
	}
	elsif($style eq "futaba" or $style eq "0")
	{
		my @ltime=localtime($time);

		return sprintf("%02d/%02d/%02d(%s)%02d:%02d",
		$ltime[5]-100,$ltime[4]+1,$ltime[3],$locdays[$ltime[6]],$ltime[2],$ltime[1]);
	}
	elsif($style eq "localtime")
	{
		return scalar(localtime($time));
	}
	elsif($style eq "tiny")
	{
		my @ltime=localtime($time);

		return sprintf("%02d/%02d %02d:%02d",
		$ltime[4]+1,$ltime[3],$ltime[2],$ltime[1]);
	}
	elsif($style eq "http")
	{
		my ($sec,$min,$hour,$mday,$mon,$year,$wday)=gmtime($time);
		return sprintf("%s, %02d %s %04d %02d:%02d:%02d GMT",
		$days[$wday],$mday,$months[$mon],$year+1900,$hour,$min,$sec);
	}
	elsif($style eq "cookie")
	{
		my ($sec,$min,$hour,$mday,$mon,$year,$wday)=gmtime($time);
		return sprintf("%s, %02d-%s-%04d %02d:%02d:%02d GMT",
		$days[$wday],$mday,$months[$mon],$year+1900,$hour,$min,$sec);
	}
	elsif($style eq "month")
	{
		my ($sec,$min,$hour,$mday,$mon,$year,$wday)=gmtime($time);
		return sprintf("%s %d",
		$months[$mon],$year+1900);
	}
	elsif($style eq "2ch-sep93")
	{
		my $sep93=timelocal(0,0,0,1,8,93);
		return make_date($time,"2ch") if($time<$sep93);

		my @ltime=localtime($time);

		return sprintf("%04d-%02d-%02d %02d:%02d",
		1993,9,int ($time-$sep93)/86400+1,$ltime[2],$ltime[1]);
	}
}

method parse_http_date :common :prototype($)
{
	my ($date)=@_;
	my %months=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);

	if($date=~/^[SMTWF][a-z][a-z], (\d\d) ([JFMASOND][a-z][a-z]) (\d\d\d\d) (\d\d):(\d\d):(\d\d) GMT$/)
	{ return eval { timegm($6,$5,$4,$1,$months{$2},$3-1900) } }

	undef
}

method cfg_expand :common ($str,%grammar)
{
	$str=~s/%(\w+)%/
		my @expansions=@{$grammar{$1}};
		cfg_expand($expansions[rand @expansions],%grammar);
	/ge;
	$str;
}

method dot_to_dec :common :prototype($)
{
	unpack('N',pack('C4',split(/\./, $_[0]))); # wow, magic.
}

method dec_to_dot :common :prototype($)
{
	join('.',unpack('C4',pack('N',$_[0])));
}

method mask_ip :common ($ip,$key,$algorithm=undef)
{
	$ip=dot_to_dec($ip) if $ip=~/\./;

	my ($block,$stir)=setup_masking($key,$algorithm);
	my $mask=0x80000000;

	for(1..32)
	{
		my $bit=$ip&$mask?"1":"0";
		$block=$stir->($block);
		$ip^=$mask if(ord($block)&0x80);
		$block=$bit.$block;
		$mask>>=1;
	}

	return sprintf "%08x",$ip;
}

method unmask_ip :common ($id,$key,$algorithm = undef)
{
	$id=hex($id);

	my ($block,$stir)=setup_masking($key,$algorithm);
	my $mask=0x80000000;

	for(1..32)
	{
		$block=$stir->($block);
		$id^=$mask if(ord($block)&0x80);
		my $bit=$id&$mask?"1":"0";
		$block=$bit.$block;
		$mask>>=1;
	}

	return dec_to_dot($id);
}

method setup_masking ($key,$algorithm = 'md5') {

	my ($block,$stir);

	if($algorithm eq "md5")
	{
		return (md5($key),method { md5(shift) })
	}
	else
	{
		setup_rc6($key);
		return (null_string(16),method { encrypt_rc6(shift) })
	}
}

method make_random_string :common ($num)
{
	my $chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	my $str;

	$str.=substr $chars,rand length $chars,1 for(1..$num);

	return $str;
}

method null_string :prototype($) { "\0"x(shift) }

method make_key :common($key,$secret,$length)
{
	my ($key,$secret,$length)=@_;
	return rc4(null_string($length),$key.$secret);
}

method hide_data :common ($data,$bytes,$key,$secret,$base64 = undef)
{
	my ($data,$bytes,$key,$secret,$base64)=@_;

	my $crypt=rc4(null_string($bytes),make_key($key,$secret,32).$data);

	return encode_base64($crypt,"") if $base64;
	return $crypt;
}



#
# File utilities
#

method read_array :common :prototype($)
{
	my ($file)=@_;

	if(ref $file eq "GLOB")
	{
		return map { s/\r?\n?$//; $_ } <$file>;
	}
	else
	{
		open FILE,$file or return ();
		binmode FILE;
		my @array=map { s/\r?\n?$//; $_ } <FILE>;
		close FILE;
		return @array;
	}
}

method write_array :common ($file,@array)
{

	if(ref $file eq "GLOB")
	{
		print $file join "\n", @array;
	}
	else # super-paranoid atomic write
	{
		my $rndname1="__".make_random_string(12).".dat";
		my $rndname2="__".make_random_string(12).".dat";
		if(open FILE,">$rndname1")
		{
			binmode FILE;
			if(print FILE join "\n", @array)
			{
				close FILE;
				rename $file,$rndname2 if -e $file;
				if(rename $rndname1,$file)
				{
					unlink $rndname2 if -e $rndname2;
					return;
				}
			}
		}
		close FILE;
		die "Couldn't write to file \"$file\"";
	}
}



#
# Spam utilities
#

method spam_check :common ($text,$spamfile) # Deprecated function
{
	return compile_spam_checker($spamfile)->($text);
}

method compile_spam_checker :common {
	my @re=map {
		s{(\\?\\?&\\?#([0-9]+)\\?;|\\?&\\?#x([0-9a-f]+)\\?;)}{
			sprintf("\\x{%x}",($2 or hex $3));
		}gei;
		$_;
	} map {
		s/(^|\s+)#.*//; s/^\s+//; s/\s+$//; # strip perl-style comments and whitespace
		if(!length) { () } # nothing left, skip
		elsif(m!^/(.*)/$!) { $1 } # a regular expression
		elsif(m!^/(.*)/([xism]+)$!) { "(?$2)$1" } # a regular expression with xism modifiers
		else { quotemeta } # a normal string
	} map read_array($_),@_;

	return eval 'method {
		$_=shift;
		# study; # causes a strange bug - moved to spam_engine()
		return '.(join "||",map "/$_/mo",(@re)).';
	}';
}

method spam_engine :common (%args)
{
	my @spam_files=@{$args{spam_files}||[]};
	my @trap_fields=@{$args{trap_fields}||[]};
	my @included_fields=@{$args{included_fields}||[]};
	my %excluded_fields=map ($_=>1),@{$args{excluded_fields}||[]};
	my $req=$args{req};
	my $charset=$args{charset};

	for(@trap_fields) { spam_screen($req) if $req->param($_) }

	my $spam_checker=compile_spam_checker(@spam_files);
	my @fields=@included_fields?@included_fields:$req->param;
	@fields=grep !$excluded_fields{$_},@fields if %excluded_fields;
	my $fulltext=join "\n",map $req->param($_),@fields;
	study $fulltext;

	spam_screen($req) if $spam_checker->($fulltext);
}

method spam_screen ($req)
{

	my $err = "<html><body>"
	  . "<h1>Anti-spam filters triggered.</h1>"
	  . "<p>If you are not a spammer, you are probably accidentially "
	  . "trying to use an URL that is listed in the spam file. Try "
	  . "editing your post to remove it. Sorry for any inconvenience.</p>"
	  . "<small style='color:white'><small>"
	  . "$_<br>" for(map $req->param($_),$req->param)
	  . "</small></small>";

	$self->render_403($err)
}


#
# Image utilities
#

method analyze_image ($file, $name) {
	my (@res);

	safety_check($file);

	return ("jpg", @res) if(@res = analyze_jpeg($name));
	return ("png", @res) if(@res = analyze_png($name));
	return ("gif", @res) if(@res = analyze_gif($name));

	if ($self->config->{alloq_webm}) {
		@res = analyze_webm($file);
		return ("webm", @res) if scalar @res == 2
	}

	# find file extension for unknown files
	my ($ext) = $name =~ /\.([^\.]+)$/;
	return (lc($ext), 0, 0);
}

method safety_check :common ($file) {
	# Check for IE MIME sniffing XSS exploit - thanks, MS, totally appreciating this
	read $file->filehandle,my $buffer,256;
	seek $file,0,0;
	die "Possible IE XSS exploit in file" if $buffer=~/<(?:body|head|html|img|plaintext|pre|script|table|title|a href|channel|scriptlet)/;
}

method analyze_jpeg :common ($file) {
	my ($buffer);

	read($file, $buffer, 2) or die $!;

	if($buffer eq "\xff\xd8") {
		OUTER:
		for(;;) {
			for(;;) {
				last OUTER unless(read($file,$buffer,1));
				last if($buffer eq "\xff");
			}

			last unless(read($file,$buffer,3)==3);
			my ($mark,$size)=unpack("Cn",$buffer);
			last if($mark==0xda or $mark==0xd9);  # SOS/EOI
			die "Possible virus in image" if($size<2); # MS GDI+ JPEG exploit uses short chunks

			if($mark>=0xc0 and $mark<=0xc2) # SOF0..SOF2 - what the hell are the rest?
			{
				last unless(read($file,$buffer,5)==5);
				my ($bits,$height,$width)=unpack("Cnn",$buffer);
				seek($file,0,0);

				return($width,$height);
			}

			seek($file,$size-2,1);
		}
	}

	seek($file, 0, 0);

	return ();
}

method analyze_png ($file) {
	my ($bytes,$buffer);

	$bytes=read($file,$buffer,24);
	seek($file,0,0);
	return () unless($bytes==24);

	my ($magic1,$magic2,$length,$ihdr,$width,$height)=unpack("NNNNNN",$buffer);

	return () unless($magic1==0x89504e47 and $magic2==0x0d0a1a0a and $ihdr==0x49484452);

	return ($width,$height);
}

method analyze_gif ($file) {
	my ($bytes,$buffer);

	$bytes=read($file,$buffer,10);
	seek($file,0,0);
	return () unless($bytes==10);

	my ($magic,$width,$height)=unpack("A6 vv",$buffer);

	return () unless($magic eq "GIF87a" or $magic eq "GIF89a");

	return ($width,$height);
}

method analyze_webm ($file) {
	my ($ffprobe,$stdout,$width,$height);

	$ffprobe = $self->config->{ffprobe_path};

	# get webm info
	$stdout = `$ffprobe -v quiet -print_format json -show_format -show_streams $file`;
	$stdout = decode_json($stdout) or return 1;

	carp np($stdout) if $ENV{WAKA_DEBUG};

	# check if file is legitimate
	return 1 if(!%$stdout); # empty json response from ffprobe
	return 1 unless($$stdout{format}->{format_name} eq 'matroska,webm'); # invalid format
	return 2 if(scalar @{$$stdout{streams}} > 1); # too many streams
	return 1 if(@{$$stdout{streams}}[0]->{codec_name} ne 'vp8'); # stream isn't webm
	return 1 unless(@{$$stdout{streams}}[0]->{width} and @{$$stdout{streams}}[0]->{height});
	return 1 if(!$$stdout{format} or $$stdout{format}->{duration} > 120);

	($width,$height) = (@{$$stdout{streams}}[0]->{width},@{$$stdout{streams}}[0]->{height});
}

method make_thumbnail ($filename, $thumbnail , $ext, $width, $height, $convert = $self->config->{convert}, $quality = $self->config->{quality}) {

	if ($ext eq 'webm') {
		$thumbnail =~ s/webm/avif/;
		#my $ffmpeg = FFMPEG_PATH;
		#my $stdout = `$ffmpeg -i $filename -v quiet -ss 00:00:00 -an -vframes 1 -f mjpeg -vf scale=$width:$height $thumbnail 2>&1`;
		FFmpeg::Inline->thumb($filename, out => $thumbnail, width => $width, height => $height, codec_id => 'AV_CODEC_ID_AV1');
		return "avif" unless $?;
	}

	if ($ext =~ /jpe?g/i) {
		$thumbnail =~ s/jpe?g/jxl/i;
		`cjxl -e 10 "$filename" "$thumbnail"`;
		#FFmpeg::Inline->thumb($filename, out => $thumbnail, width => $width, height => $height, codec_id => 'AV_CODEC_ID_JPEGXL');
		return "jxl" unless $?;
	}

	# do something else if animated thumbnails are disabled
	if (($filename =~ /\.gif$/) && ($self->config->{animated_thumbnails} == 0)) {
		my $magickname = $filename .= "[0]";
		$thumbnail =~ s/gif/jpg/;

		`gm convert $filename -sample ${width}x${height}! -quality $quality $thumbnail`;
		return "gif" unless $?;

		$convert = "convert" unless($convert);
		`gm $convert $magickname -flatten -sample ${width}x${height}! -quality $quality $thumbnail`;
		return "gif" unless $?;
	}

	# first try GraphicsMagick
	my ($tnext) = ($filename =~ /\.(png|gif)$/); 
	my $tnbg = $tnext ? '-background transparent' : '-background white';

	my $method = ($filename =~ /\.gif$/) ? '-coalesce -sample' : '-resize';
	`gm convert $tnbg $filename $method ${width}x${height}! -quality $quality $thumbnail`;
	return $tnext unless($?);

	# then ImageMagick
	$convert = "convert" unless($convert);
	`$convert $tnbg $filename $method ${width}x${height}! -quality $quality $thumbnail`;
	return $tnext unless($?)
}


#
# Crypto code
#

method rc4 ($message, $key, $skip = 256) {
	my @s=0..255;
	my @k=unpack 'C*',$key;
	my @message=unpack 'C*',$message;
	my ($x,$y);

	$y=0;
	for $x (0..255)
	{
		$y=($y+$s[$x]+$k[$x%@k])%256;
		@s[$x,$y]=@s[$y,$x];
	}

	$x=0; $y=0;
	for(1..$skip)
	{
		$x=($x+1)%256;
		$y=($y+$s[$x])%256;
		@s[$x,$y]=@s[$y,$x];
	}

	for(@message)
	{
		$x=($x+1)%256;
		$y=($y+$s[$x])%256;
		@s[$x,$y]=@s[$y,$x];
		$_^=$s[($s[$x]+$s[$y])%256];
	}

	return pack 'C*',@message;
	}

class wakautils::rc6 {
  field $key :param;
  field @S = [];

  ADJUST {
	$key .= "\0"x(4-(length $key)&3); # pad key
    my @L = unpack "V*", $key;
	
	$S[0] = 0xb7e15163;
	$S[$_] = add($S[$_-1],0x9e3779b9) for(1..43);

	my $v = @L > 44 ? @L * 3 : 132;
	my ($A,$B,$i,$j) = (0,0,0,0);

	for (1 .. $v) {
		$A = $S[$i] = rol(add($S[$i], $A, $B), 3);
		$B = $L[$j] = rol(add($L[$j] + $A + $B), add($A + $B));
		$i = ($i + 1) % @S;
		$j = ($j + 1) % @L
	}
  }

  	method encrypt_rc6 ($block) {
		...
    }
}


#
# Crypto code


method add  { my ($sum,$term); while(defined ($term=shift)) { $sum+=$term } return $sum%4294967296 }
method rol ($x,$n,@a) {   ( $x = shift @a ) << ( $n = 31 & shift @a ) | 2**$n - 1 & $x >> 32 - $n }
method ror { rol(shift,32-(31&shift)) } # rorororor
method mul ($a,$b) { return ( (($a>>16)*($b&65535)+($b>>16)*($a&65535))*65536+($a&65535)*($b&65535) )%4294967296 }
