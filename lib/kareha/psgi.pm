#!/usr/bin/perl
use Object::Pad;

package kareha::psgi 0.01;
class kareha::psgi :does(Frame)
                   :does(wakautils)
				   :does(kareha::config)
				   :does(kareha::template);

use utf8;
use v5.40;

use feature 'bareword_filehandles';

use Carp;
use Socket;
use Digest::MD5;
use Time::HiRes;
use JSON::MaybeXS;
use Data::Printer;
use Data::Dumper;
use Const::Fast;
use Fcntl ':flock';

use wakautils;
use kareha::config;
use kareha::template;

if ($ENV{WAKA_DEBUG}) {
	our $_caller = [ caller ];
	carp np($_caller);
	carp __PACKAGE__
}

const our $IS_NUM => qr/^[0-9]+$/;
const our $IS_RANGE => qr/^[a-z0-9]*$/i;
const our $REPLYRANGE_RE => qr{n?(?:[0-9\-,lrq]|&#44;)*[0-9\-lrq]}; # regexp to match reply ranges for >> links
#const our $protocol_re => protocol_regexp();
#const our $url_re => url_regexp();

field $markup_fmts;
field $stylesheets;
field $log;
field $config;

#
# Global init
#

method BUILDARGS :common {
	open => "config.toml", @_
}

ADJUSTPARAMS ($params) {
  $$config = $self->_config;
  $stylesheets = $self->get_stylesheets;
  $markup_fmts = [ map +{ id => $_ }, $config->{markup_formats}->@* ]
}

method startup {
	my $r = $self->routes;
	my $config = $self->config;

	my $board = $r->under('/', sub ($c) {
		unless (-e $$config{html_self}) {
			$c->build_pages;
			$c->update_threads
		}

		$c->redirect($$config{html_self}) unless $self->env->{PATH_INFO};
		$c->redirect($self->env->{HTTP_REFERER}) if $c->parameters->{r}
	});

	# const our $IS_NUM => qr/^[0-9]+$/;
	# const our $IS_RANGE => qr/^[a-z0-9]*$/i;

	$board->get('/:thread/:range?', { thread => $IS_NUM, range => $IS_RANGE }, 'show_thread');
	$board->post('/post', 'post_stuff');
	$board->post('/delete', 'delete_stuff');
	$board->post('/delete/:thread', { thread => $IS_NUM }, 'delete_thread');
}


# method router {

# 	elsif($task eq "preview")
# 	{
# 		my $comment=$query->param("comment");
# 		my $markup=$query->param("markup");
# 		my $thread=$query->param("thread");

# 		preview_post($comment,$markup,$thread);
# 		prepare_for_exit();

# 		exit;
# 	}
# 	elsif($task eq "delete")
# 	{
# 		my $password=$query->param("password");
# 		my $fileonly=$query->param("fileonly");
# 		my @posts=$query->param("delete");

# 		delete_stuff($password,$fileonly,@posts);
# 	}
# 	elsif($task eq "deletethread")
# 	{
# 		make_error(S_BADDELPASS) unless check_admin_pass($query->param("admin"));

# 		my $thread=$query->param("thread");
# 		delete_thread($thread);
# 	}
# 	elsif($task eq "permasagethread")
# 	{
# 		make_error(S_BADDELPASS) unless check_admin_pass($query->param("admin"));

# 		my $thread=$query->param("thread");
# 		my $state=$query->param("state");
# 		permasage_thread($thread,$state);
# 	}
# 	elsif($task eq "closethread")
# 	{
# 		make_error(S_BADDELPASS) unless check_admin_pass($query->param("admin"));

# 		my $thread=$query->param("thread");
# 		my $state=$query->param("state");
# 		close_thread($thread,$state);
# 	}
# 	elsif($task eq "rebuild")
# 	{
# 		make_error(S_BADDELPASS) unless check_admin_pass($query->param("admin"));

# 		build_pages();
# 		update_threads();
# 	}
# 	else
# 	{
# 		make_error(S_NOTASK);
# 	}
# }

method show_thread ($threadnum, $ranges = undef) {
	my $modified = (stat $$config{res_dir}. $threadnum. $$config{page_ext})[9];

	if ($ENV{HTTP_IF_MODIFIED_SINCE}) {
		my $ifmod = parse_http_date($ENV{HTTP_IF_MODIFIED_SINCE});
		if ($modified <= $ifmod) {
			return  $self->return_304
		}
	}

	my $thread = filter_post_ranges($threadnum,$ranges);

	my @headers = ( 'Content-Type' => get_xhtml_content_type($$config->@{qw(charset xhtm)})
	              , 'Date' => make_date(time, "http")
				  , 'Last-Modified' => make_date($modified, "http") );

	my %thread = %{$thread};

	my $content_body = join "\n",(
		$self->templates->thread_head_template(%{$thread}),
		(map { $$_{text} } @{$$thread{posts}}),
		$self->templates->thread_foot_template->(%{$thread}),
	);

	[ 200, \@headers, [ $content_body ] ]
}

method build_pages {
	my @allthreads = get_threads(1);
	my @copy = @allthreads;
	my @pages;

	# generate page subdivisions
	if ($$config{page_generation} eq "paged") {
		$pages[0]{threads} = [splice @copy, 0, $$config{threads_displayed}];
		$pages[0]{filename} = $$config{html_self};
		$pages[0]{page} = "0";

		my @threads;
		while (@threads = splice @copy,0,$$config{threads_displayed}) {
			push @pages, { threads=>[@threads], filename=>@pages.  $$config{page_ext}, page=>scalar @pages };
		}
	}
	elsif ($$config{page_generation} eq "monthly") {
		$pages[0]{threads}=[splice @copy,0,$$config{threads_displayed}];
		$pages[0]{filename}=$$config{html_self};
		$pages[0]{page} = $S_FRONT;

		my @unbumped=sort { $$b{thread}<=>$$a{thread} } @allthreads;
		foreach my $thread (@unbumped) { $$thread{month}=make_date($$thread{thread},"month") }

		while(@unbumped) {
			my @month=(shift @unbumped);
			while(@unbumped and $unbumped[0]{month} eq $month[0]{month}) { push @month,shift @unbumped }

			my $monthname=$month[0]{month};
			my $filename=lc($monthname).$$config{page_ext};
			$filename=~tr/ /_/;

			push @pages,{ threads=>\@month,filename=>$filename,page=>$monthname };
		}
	}
	else {
		$pages[0]{threads}=[splice @copy,0,$self->config->{threads_displayed}];
		$pages[0]{filename}=$self->config->{html_self};
		$pages[0]{page} = $S_FRONT;
	}

	# figure out next/prev links
	for (1..$#pages-1) {
		$pages[$_]{nextpage}=$pages[$_+1]{filename};
		$pages[$_]{prevpage}=$pages[$_-1]{filename};
	}
	if (@pages>1) {
		$pages[0]{nextpage}=$pages[1]{filename};
		$pages[$#pages]{prevpage}=$pages[$#pages-1]{filename};
	}

	# process and generate pages
	foreach my $page (@pages) {
		# fix up each thread
		foreach my $thread (@{$$page{threads}}) {
			$self->read_thread($thread);

			my $posts=$$thread{postcount};
			my $images=grep { get_post_images($thread,$_) } 1..$posts;
			my $curr_replies=$posts-1;
			my $curr_images=$images;
			my $max_replies=$$config{replies_per_thread};
			my $max_images=($$config{image_replies_per_thread} or $images);
			my $start=2;

			# drop replies until we have few enough replies and images
			while($curr_replies > $max_replies or $curr_images > $max_images) {
				$curr_images-- if get_post_images($thread, $start);
				$curr_replies--;
				$start++;
			}

			filter_post_ranges($thread, "l$curr_replies", $$config{max_lines_shown});

			$$thread{omit} = $posts - $curr_replies - 1;
			$$thread{omitimages} = $images - $curr_images;

			$$thread{nextnum} = $$thread{num} % ($$config{threads_displayed}) + 1;
			$$thread{prevnum} = ($$thread{num} + ($$config{threads_displayed}) - 2) % ($$config{threads_displayed}) + 1;
		}

		if ($$config{subback_index}) {
			write_array($$page{filename}, $self->templates->backlog_page_template->(
				threads => \@allthreads,
				postform => 1
			));
		}
		else {
			write_array($$page{filename}, $self->templates->main_page_template(
				%$page,
				pages=>\@pages,
				allthreads=>\@allthreads,
				current=>$$page{page},
			));
		}
	}

	write_array($$config{html_backlog}, $self->templates->backlog_page_template->(
		threads => \@allthreads,
		postform => $$config{subback_postform}
	)) if(($$config{html_backlog}) && (!$self->config->{subback_index}));

	write_array($self->config->{rss_file}
	  ,$self->rss_template(threads=>\@allthreads)) if($self->config->{rss_file});

	# delete extra pages
	# BUG: no deletion in monthly mode
	if($self->config->{page_generation} eq "paged") {
		my $page=@pages;
		while(-e $page.$self->config->{page_ext}) {
			unlink $page.$self->config->{page_ext};
			$page++
		}
	}
}

method update_threads
{
	my @threads=get_threads(1);

	foreach my $thread (@threads)
	{
		$self->read_thread($thread);
		$self->write_thread($thread);
	}
}

#
# Posting
#

method post_stuff {
	my ($thread, $name, $link, $title, $comment, $captcha, $password, $markup
	  , $savemarkup) = $self->parameters->@{qw(thread
	      field_a field_b title comment captcha password markup savemarkup)};

	my $key = $self->req->cookie('captchakey');
	my $file = $self->req->uploads->{file};
	my $uploadname = $file->filename;

	# get a timestamp for future use
	my $time = join '', Time::HiRes::gettimeofday;

	# check that the request came in as a POST, or from the command line
	make_error($S_UNJUST) if $ENV{REQUEST_METHOD} and $ENV{REQUEST_METHOD}
	  ne "POST";

	# check for weird characters
	make_error($S_UNUSUAL) if $thread=~/[^0-9]/;
	make_error($S_UNUSUAL) if length($thread)>10;
	make_error($S_UNUSUAL) if $name=~/[\n\r]/;
	make_error($S_UNUSUAL) if $link=~/[\n\r]/;
	make_error($S_UNUSUAL) if $title=~/[\n\r]/;

	# check for excessive amounts of text
	make_error(sprintf($S_TOOLONG,"name",length($name) - $self->config->{max_field_length})) if length($name) > $self->config->{max_field_length};
	make_error(sprintf($S_TOOLONG,"link",length($link) - $self->config->{max_field_length})) if length($link) > $self->config->{max_field_length};
	make_error(sprintf($S_TOOLONG,"title",length($title) - $self->config->{max_field_length})) if length($title) > $self->config->{max_field_length};
	make_error(sprintf($S_TOOLONG,"comment",length($comment) - $self->config->{max_field_length})) if length($comment) > $self->config->{max_field_length};

	# check for empty post
	make_error($S_NOTEXT) if $comment=~/^\s*$/ and !$file;
	make_error($S_NOTITLE) if $self->config->{require_thread_title} and $title=~/^\s*$/ and !$thread;

	# find hostname
	my $ip = $self->env->{REMOTE_ADDR};
	my $host = gethostbyaddr($ip, AF_INET);

	# spam check
	spam_engine(
		req => $self->req,
		trap_fields => $self->config->{spam_trap} ? [ "name", "link" ] : [],
		spam_files => [ $self->config->{samp_files} ],
		charset => $self->config->{charset},
	);

	# check captcha
	if($self->config->{enable_captcha}) {
		make_error($S_BADCAPTCHA) if find_key($log,$key);
		make_error($S_BADCAPTCHA) if !check_captcha($key,$captcha);
	}

	# proxy check - not implemented yet, and might not ever be
	#proxy_check($ip) unless($whitelisted);

	# remember cookies
	my $c_name=$name;
	my $c_link=$link;
	my $c_password=$password;
	my $c_markup=$markup;

	const our $NOKO => qr/^\s*noko*\s$/i;
	const our $SAGE => qr/^\s*sage*\s$/i;

	# get noko before $link is tampered with
	my $noko = $link =~ $NOKO;
	$link =~ s/$NOKO//i;

	# kill the name if anonymous posting is being enforced
	if ($self->config->{forced_anon}) {
		$name = '';
		if ($link =~ $SAGE) { $link='sage' }
		else { $link='' }
	}

	# clean up the inputs
	$link = clean_string($link);
	$title = clean_string($title);

	# fix up the link
	$link = "mailto:$link" if $link and $link !~ /^$kareha::template::protocol_re/;

	# process the tripcode
	my ($trip, $capped);
	($name, $trip) = process_tripcode($name, $self->config->@{qw(tripkey secret charset)}, 1);
	my %capped_trips = $self->config->{capped_trips}->%*;
	$capped = $capped_trips{$trip};

	# insert anonymous name if none entered
	$name=make_anonymous($ip,$time,($thread or $time)) unless $name or $trip;

	const our $FUSIANASAN_RE => qr/fusianasan/i;

	# reveal host when name is "fusianasan"
	($name, $trip) = ("", resolve_host($ENV{REMOTE_ADDR}) . $trip) if $name =~ $FUSIANASAN_RE;

	# check for posting limitations
	unless($capped) {
		if($thread) {
			$self->make_error($S_NOTALLOWED) if($file and !$self->config->{allow_image_replies});
			$self->make_error($S_NOTALLOWED) if(!$file and !$self->config->{allow_text_replies});
		}
		else
		{
			$self->make_error($S_NOTALLOWED) if($file and !$self->config->{allow_image_threads});
			$self->make_error($S_NOTALLOWED) if(!$file and !$self->config->{allow_text_threads});
		}
	}

	# copy file, do checksums, make thumbnail, etc
	my ($filename, $ext, $size, $md5, $width, $height, $thumbnail, $tn_width, $tn_height)
	  = process_file($file, $uploadname ,$time)
	    if($file);

	# create the thread if we are starting a new one
	$thread = make_thread($title,$time,$name.$trip) unless $thread;

	# format the comment
	$comment = format_comment($comment,$markup,$thread);

	# generate date
	my $date = make_date($time, $self->config->{date_style});

	# generate ID code if enabled
	$date.=' ID:'.make_id_code($ip,$time,$link,$thread) if $$config{display_id};

	# add the reply to the thread
	my $num=make_reply(
		ip=>$ip,thread=>$thread,name=>$name,trip=>$trip,link=>$link,capped=>$capped,
		time=>$time,date=>$date,title=>$title,comment=>$comment,
		image=>$filename,ext=>$ext,size=>$size,md5=>$md5,width=>$width,height=>$height,
		thumbnail=>$thumbnail,tn_width=>$tn_width,tn_height=>$tn_height,
	);

	# make entry in the log
	add_log($log,$thread,$num,$password,$ip,$key,$md5,$filename);

	# remove old threads from the database
	trim_threads();

	build_pages();

	# set the name, email and password cookies, plus a new captcha key
	make_cookies(name=>$c_name,link=>$c_link,password=>$c_password,
	$savemarkup?(markup=>$c_markup):(),
	captchakey=>make_random_string(8),-charset=>$$config{charset},-autopath=>$$config{cookie_path}); # yum!

	if($noko) {
		my $script = $ENV{SCRIPT_NAME};
		prepare_for_exit();

		make_http_forward("$script/$thread/l50#reply$num",$$config{alternate_redirect});
		exit;
	}
}

method preview_post ($comment,$markup,$thread) {
	$thread = time unless $thread;

	make_error($S_UNUSUAL) unless grep $markup eq $_, $$config{markup_formats};
	make_error(sprintf($S_TOOLONG, "comment", length($comment) - $$config{max_comment_length}))
	  if length($comment) > $$config{max_comment_length};

	# format the comment
	$comment=format_comment($comment,$markup,$thread);

	[ 200, [ 'Content-Type' => 'text/html' ], [ $comment ] ]
}

method proxy_check ($ip) {
	for my $port ($$config{proxy_check})
	{
		# needs to be implemented
		# die sprintf S_PROXY,$port);
	}
}

method format_comment ($comment,$markup,$thread) {
	$markup=$$config{default_markup} unless grep $markup eq $_,$$config{markup_formats};

	if($markup eq "none") { $comment=simple_format($comment,$thread) }
	elsif($markup eq "html") { $comment=html_format($comment,$thread) }
	elsif($markup eq "raw") { $comment=raw_html_format($comment,$thread) }
	elsif($markup eq "aa") { $comment=aa_format($comment,$thread) }
	else { $comment=wakabamark_format($comment,$thread) }

	# fix <blockquote> styles for old stylesheets
	$comment=~s/<blockquote>/<blockquote class="unkfunc">/g if($$config{fudge_blockquotes});

	return $comment;
}

method simple_format ($text,$thread) {
	return join "<br>", map {
		my $line = $_;

		$line =~ s!&gt;&gt;($REPLYRANGE_RE)!\<a href="$ENV{SCRIPT_NAME}/$thread/$1" rel="nofollow"\>&gt;&gt;$1\</a\>!gm;

		# make URLs into links
		$line =~ s{$url_re}{\<a href="$1" rel="nofollow"\>$1\</a\>$2}sgi;

		$line;
	} split /(?:\r\n|\n|\r)/, clean_string(decode_string($text));
}

method aa_format ($text, $thread) {
	'<div class="aa">'.simple_format($text,$thread).'</div>'
}

method wakabamark_format ($text, $thread)
{
	$text=clean_string(decode_string($text));

	# hide >>1 references from the quoting code
	$text=~s/&gt;&gt;($REPLYRANGE_RE})/&gtgt;$1/g;

	my $handler=sub # fix up >>1 references
	{
		my $line=shift;
		$line=~s!&gtgt;($REPLYRANGE_RE)!\<a href="$ENV{SCRIPT_NAME}/$thread/$1" rel="nofollow"\>&gt;&gt;$1\</a\>!gm;
		return $line;
	};

	$text=do_wakabamark($text,$handler);

	# restore >>1 references hidden in code blocks
	$text=~s/&gtgt;/&gt;&gt;/g if $text;

	$text
}

method html_format ($text,$thread) {
	$text=sanitize_html(decode_string($text),$$config{allowed_html});

	$text=~s!&gt;&gt;($$REPLYRANGE_RE)!\<a href="$ENV{SCRIPT_NAME}/$thread/$1" rel="nofollow"\>&gt;&gt;$1\</a\>!gm;
	$text=~s!(?:\r\n|\n|\r)!<br />!sg;

	$text
}

method raw_html_format ($text,$thread) {
	$text=sanitize_html($text,$$config{allowed_html});
	$text=~s!\s+! !sg;

	$text
}

method make_anonymous ($ip,$time,$thread)
{
	return $$config{s_anoname} unless($$config{silly_anonymous});

	my $string=$ip;
	$string.=",".int($time/86400) if($$config{silly_anonymous}=~/day/i);
	$string.=",".$ENV{SCRIPT_NAME} if($$config{silly_anonymous}=~/board/i);
	$string.=",".$thread if($$config{silly_anonymous}=~/thread/i);

	srand unpack "N",hide_data($string,4,"silly",$$config{secret});

	cfg_expand("%G% %W%",
		W => ["%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%","%O%%E%","%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%","%O%%E%","%B%%V%%M%%I%%V%%F%","%B%%V%%M%%E%"],
		B => ["B","B","C","D","D","F","F","G","G","H","H","M","N","P","P","S","S","W","Ch","Br","Cr","Dr","Bl","Cl","S"],
		I => ["b","d","f","h","k","l","m","n","p","s","t","w","ch","st"],
		V => ["a","e","i","o","u"],
		M => ["ving","zzle","ndle","ddle","ller","rring","tting","nning","ssle","mmer","bber","bble","nger","nner","sh","ffing","nder","pper","mmle","lly","bling","nkin","dge","ckle","ggle","mble","ckle","rry"],
		F => ["t","ck","tch","d","g","n","t","t","ck","tch","dge","re","rk","dge","re","ne","dging"],
		O => ["Small","Snod","Bard","Billing","Black","Shake","Tilling","Good","Worthing","Blythe","Green","Duck","Pitt","Grand","Brook","Blather","Bun","Buzz","Clay","Fan","Dart","Grim","Honey","Light","Murd","Nickle","Pick","Pock","Trot","Toot","Turvey"],
		E => ["shaw","man","stone","son","ham","gold","banks","foot","worth","way","hall","dock","ford","well","bury","stock","field","lock","dale","water","hood","ridge","ville","spear","forth","will"],
		G => ["Albert","Alice","Angus","Archie","Augustus","Barnaby","Basil","Beatrice","Betsy","Caroline","Cedric","Charles","Charlotte","Clara","Cornelius","Cyril","David","Doris","Ebenezer","Edward","Edwin","Eliza","Emma","Ernest","Esther","Eugene","Fanny","Frederick","George","Graham","Hamilton","Hannah","Hedda","Henry","Hugh","Ian","Isabella","Jack","James","Jarvis","Jenny","John","Lillian","Lydia","Martha","Martin","Matilda","Molly","Nathaniel","Nell","Nicholas","Nigel","Oliver","Phineas","Phoebe","Phyllis","Polly","Priscilla","Rebecca","Reuben","Samuel","Sidney","Simon","Sophie","Thomas","Walter","Wesley","William"],
	);
}

method make_id_code ($ip,$time,$link,$thread) {
	return $$config{email_id} if($link and $$config{display_id}=~/link/i);
	return $$config{email_id} if($link=~/sage/i and $$config{display_id}=~/sage/i);

	return resolve_host($ENV{REMOTE_ADDR}) if($$config{display_id}=~/host/i);
	return $ENV{REMOTE_ADDR} if($$config{display_id}=~/ip/i);

	my $string="";
	$string.=",".int($time/86400) if($$config{display_id}=~/day/i);
	$string.=",".$ENV{SCRIPT_NAME} if($$config{display_id}=~/board/i);
	$string.=",".$thread if($$config{display_id}=~/thread/i);

	return mask_ip($ENV{REMOTE_ADDR},make_key("mask",$$config{secret},32).$string) if($$config{display_id}=~/mask/i);

	hide_data($ip.$string,6,"id",$$config{secret},1)
}

method make_reply (%vars) {
	my $thread=read_thread($vars{thread});

	make_error($S_THREADCLOSED) if($$thread{closed});

	$$thread{postcount}++;
	$$thread{lastmod}=$vars{time};
	$$thread{lasthit}=$vars{time} unless($vars{link}=~/sage/i or $$thread{postcount}>=$$config{max_res} or $$thread{permasage}); # bump unless sage, too many replies, or permasage

	my $num=$$thread{postcount};
	set_post_text($thread,$num,$self->reply_template(%vars,num=>$num));

	write_thread($thread);

	$num
}

#
# Deleting
#

method delete_stuff ($password,$fileonly,@posts) {
	foreach my $post (@posts)
	{
		my ($thread,$num)=$post=~/([0-9]+),([0-9]+)/;

		delete_post($thread,$num,$password,$fileonly);
	}

	build_pages();
}

method trim_threads
{
	my @threads=get_threads($$config{trim_method});

	my ($posts,$size);
	$posts+=$$_{postcount} for(@threads);
	$size+=-s $_ for(glob($$config{img_dir}."*"));

	my $max_threads=($$config{max_threads} or @threads);
	my $max_posts=($$config{max_posts} or $posts);
	my $max_size=($$config{max_megabytes}*1024*1024 or $size);

	while(@threads>$max_threads or $posts>$max_posts or $size>$max_size)
	{
		my $thread=pop @threads;
		read_thread($thread);

		foreach my $num (1..$$thread{postcount})
		{
			my ($image,$thumb)=get_post_images($thread,$num);
			$size-=-s $image;
		}
		$posts-=$$thread{postcount};

		delete_thread($$thread{thread});
	}

	foreach my $thread (@threads)
	{
		close_thread($$thread{thread},1) if($$config{autoclose_posts} and $$thread{postcount}>=$$config{autoclose_posts});
		close_thread($$thread{thread},1) if($$config{autoclose_days} and ((join '', Time::HiRes::gettimeofday) - $$thread{lastmod})>=$$config{autoclose_days}*86400);
		close_thread($$thread{thread},1) if($$config{autoclose_size} and $$thread{size}>=$$config{autoclose_size}*1024);
	}
}

method delete_post ($threadnum,$postnum,$password,$fileonly = undef) {
	my $admin_pass=check_admin_pass($password);

	make_error($S_BADDELPASS) unless($password);
	make_error($S_BADDELPASS) unless($admin_pass or match_password($log,$threadnum,$postnum,$password));

	my $reason;
	if($admin_pass) { $reason="mod"; }
	else { $reason="user"; }

	my $thread=read_thread($threadnum);
	return unless $thread;

	if($postnum==1 and !$fileonly)
	{
		if($$config{delete_first} eq 'remove' or ($$config{delete_first} eq 'single' and $$thread{postcount}==1))
		{ delete_thread($threadnum); return }
	}

	# remove images
	unlink get_post_images($thread,$postnum);

	# remove post
	unless($fileonly)
	{
		set_post_text($thread,$postnum,DELETED_TEMPLATE->(num=>$postnum,reason=>$reason));
		write_thread($thread);
	}
}

method delete_thread ($threadnum) {
	$self->make_error($S_UNUSUAL) if($threadnum=~$IS_NUM); # check to make sure the thread argument is safe

	my $thread=read_thread($threadnum);

	# remove images
	foreach my $num (1..$$thread{postcount}) { unlink get_post_images($thread,$num) }

	unlink $$thread{filename};

	build_pages();
}

method permasage_thread ($threadnum,$state) {
	make_error($S_UNUSUAL) if $threadnum !~ $IS_NUM; # check to make sure the thread argument is safe

	my $thread=read_thread($threadnum);
	$$thread{permasage}=$state;
	write_thread($thread);

	build_pages();
}

method close_thread ($threadnum,$state) {
	make_error($S_UNUSUAL) if($threadnum !~ $IS_NUM); # check to make sure the thread argument is safe

	my $thread=read_thread($threadnum);
	$$thread{closed}=$state;
	write_thread($thread);

	build_pages();
}

#
# Thread access utils
#

method get_threads ($bumped) {
	my @pages=map { get_thread($_) } glob($$config{res_dir}."*".$$config{page_ext});

	if($bumped) { @pages=sort { $$b{lasthit}<=>$$a{lasthit} } @pages; }
	else { @pages=sort { $$b{thread}<=>$$a{thread} } @pages; }

	my $num=1;
	$$_{num}=$num++ for(@pages);

    @pages;
}

method get_thread ($arg) {
	my ($thread,$filename);

	if($arg=~$IS_NUM)
	{
		$thread=$arg;
		$filename=$$config{res_dir}.$thread.$$config{page_ext};
	}
	else
	{
		my $re=$$config{res_dir}.'([0-9]+)'.$$config{page_ext};
		$filename=$arg;
		($thread)=$filename=~/$re/;
	}

	open PAGE,$filename or $self->make_error($S_NOTHREADERR);
	my $head=<PAGE>;
	close PAGE;

	my ($code)=$head=~/\<!--(.*)--\>/;
	return undef unless $code;
	my %meta=%{eval $code};

	$meta{lastmod}=$meta{lasthit} unless $meta{lastmod};

	{
		%meta,
		thread=>$thread,
		filename=>$filename,
		size=>-s $filename,
	}
}

method read_thread ($thread) {
	$thread=get_thread($thread) or return undef if ref($thread) ne "HASH";
	return $thread if $$thread{allposts};

	my @page=map { s/\r//g; $_ } read_array($$thread{filename});
	return undef unless @page;

	shift @page; # drop metadata
	$$thread{head}=shift @page;
	$$thread{foot}=pop @page;

	my @posts=map +{ text=>$page[$_],num=>$_+1 },(0..$#page);

	$$thread{allposts}=$$thread{posts}=\@posts;

	$thread
}

method get_post_text ($thread,$postnum)
{
	$thread=read_thread($thread);
	$$thread{allposts}[$postnum-1]{text}
}

method set_post_text ($thread,$postnum,$text)
{
	$thread=read_thread($thread);
	$$thread{allposts}[$postnum-1]={ text=>$text,num=>$postnum };
	return $thread;
}

method get_post_images ($thread,$postnum)
{
	my $post=get_post_text($thread,$postnum);

	my @images;
	my $img_dir=quotemeta $$config{img_dir};
	my $thumb_dir=quotemeta $$config{thumb_dir};

	push @images,$1 if($post=~m!<a [^>]*href="/[^>"]*($img_dir[^>"/]+)"!);
	push @images,$1 if($post=~m!<img [^>]*src="/[^>"]*($thumb_dir[^>"/]+)"!);

	return map { s/\%([0-9a-fA-F]{2})/chr hex $1/ge; $_ } @images;
}

method filter_post_ranges ($thread,$ranges,$lines)
{
	$thread=read_thread($thread);

	my $nofirst;
	$nofirst=1 if $ranges=~s/^n//i;

	my @postnums;
	my $total=$$thread{postcount};

	foreach my $range (split /,/,$ranges)
	{
		if($range=~/^([0-9]*)-([0-9]*)$/)
		{
			my $start=($1 or 1);
			my $end=($2 or $total);

			$start=$total if $start>$total;
			$end=$total if $end>$total;

			if($start<$end) { push @postnums,($start..$end) }
			else { push @postnums,reverse ($end..$start) }
		}
		elsif($range=~/^([0-9]+)$/)
		{
			my $post=$1;
			push @postnums,$post if $post>0 and $post<=$total;
		}
		elsif($range=~/^l([0-9]+)$/i)
		{
			my $start=$total-$1+1;
			$start=1 if $start<1;
			push @postnums,($start..$total);
		}
		elsif($range=~/^r([0-9]{1,4})$/i)
		{
			my $num=($1 or 1);
			push @postnums,int (rand $total)+1 for(1..$num);
		}
		elsif($range=~/^q([0-9]+)$/i)
		{
			my $num=$1;

			push @postnums,$num;
			OUTER: foreach my $post (1..$total)
			{
				next if $post eq $num;
				my $text=get_post_text($thread,$post);
				while($text=~/&gt;&gt;($REPLYRANGE_RE)/g)
				{
					if(in_range($num,$1)) { push @postnums,$post; next OUTER; }
				}
			}
		}
	}

	@postnums=@postnums[0..999] if @postnums>1000;
	@postnums=(1..$total) unless @postnums;

	if($ranges=~/^[0-9]*-[0-9]*$/ or $ranges=~/^l[0-9]+$/i)
	{
		my $start=$postnums[0];
		my $end=$postnums[$#postnums];

		if($start<=$end)
		{
			$$thread{prevpost}=$start-1 unless $start<=1;
			$$thread{nextpost}=$end+1 unless $end>=$total;
			unshift @postnums,1 unless $nofirst or $start==1;
		}
	}

	# fix up and abbreviate posts
	my @posts=map {
		my %post;
		my $text=get_post_text($thread,$_);

		$post{text}=$text;
		$post{num}=$_;

		if($lines)
		{
			my $abbrev=abbreviate_post($text,$lines);
			$post{abbreviation}=$abbrev||$text;
			$post{abbreviated}=$abbrev?1:0;
		}
		else
		{
			$post{text}=$text;
		}

		\%post;
	} @postnums;

	$$thread{posts}=\@posts;

	return $thread;
}

method abbreviate_post ($post, $lines) {
	my $abbrev = abbreviate_html($post,$lines,$self->config->{approx_line_length});
	$abbrev // undef
}

method in_range ($num, $ranges) {
	foreach my $range (split /(,|&#44;)/, $ranges) {
		if ($range =~ /^([0-9]*)-([0-9]*)$/) {
			my $start = ($1 or 1);
			my $end = ($2 or 1000000); # arbitary large number

			($start, $end) = ($end, $start) if $start > $end;

			return 1 if $num >= $start and $num <= $end
		}
		elsif ($range =~ /^([0-9]+)$/) {
			return 1 if $num == $1;
		}
		#elsif($range=~/^l([0-9]+)$/i) {} # l ranges never match
		#elsif($range=~/^r([0-9]*)$/i) {} # r ranges never match
		#elsif($range=~/^q([0-9]+)$/i) {} # q ranges never match
	}

	0
}

method write_thread ($thread) {
	my @written = qw(postcount author title lasthit lastmod permasage closed);
	my %meta;
	@meta{@written} = @{$thread}{@written};

	my @page;

	$Data::Dumper::Terse = 1;
	$Data::Dumper::Indent = 0;

	push @page,'<!-- '.Dumper(\%meta).' -->';
	push @page,$self->thread_head_template(%{$thread});
	push @page,map { get_post_text($thread,$_) } 1..$$thread{postcount};
	push @page,$self->thread_foot_template->(%{$thread});

	write_array($$thread{filename},@page);
}

method make_thread ($title,$time,$author)
{
	my $filename=$$config{res_dir}.$time.$$config{page_ext};

	make_error($S_THREADCOLL) if(-e $filename);

	write_thread({
		thread=>$time,
		filename=>$filename,
		title=>$title,
		postcount=>0,
		lasthit=>$time,
		lastmod=>$time,
		permasage=>0,
		closed=>0,
		author=>$author,
		head=>"",
		foot=>"",
		posts=>[],
		allposts=>[],
	});

	return $time;
}

#
# Log fuctions
#

method match_password ($log,$thread,$post,$password)
{
	my $encpass = hide_password($password);

	return 0 unless($$config{enable_deletion});

	foreach (@{$log}) {
		my @data = split /\s*,\s*/;
		if ($data[0] == $thread and $data[1] == $post) {
 			return 1 if($data[2] eq $encpass or decrypt_string($data[2], "cryptpass") eq $encpass);
 		}
	}

	0
}

method find_key ($log,$key) {
	foreach (@{$log}) {
		my @data = split /\s*,\s*/;
		return 1 if($data[4] eq $key);
	}
	
	0
}

method find_md5 ($log,$md5) {
	foreach (@{$log}) {
		my @data = split /\s*,\s*/;
		return ($data[0], $data[1]) if ($data[5] && $md5) && $data[5] eq $md5 && -e $data[6];
	}

	()
}

method lock_log {
	open LOGFILE , "+>>" . $$config{log_file} or make_error($S_NOLOG);
	eval "flock LOGFILE,LOCK_EX"; # may not work on some platforms - ignore it if it does not.
	seek LOGFILE, 0, 0;

	my @log = grep { /($IS_NUM)/; -e $$config{res_dir} . $1 . $$config{page_ext} } read_array(\*LOGFILE);

	# should remove MD5 for deleted files somehow
	return \@log;
}

method release_log ($log)
{
	if ($log) {
		seek LOGFILE,0,0;
		truncate LOGFILE,0;
		write_array(\*LOGFILE,@$log)
	}

	close LOGFILE;
}

method add_log ($log,$thread,$post,$password,$ip,$key,$md5,$file) #= undef)
{
	$password=encrypt_string(hide_password($password),"cryptpass");
	$ip=encrypt_string($ip,"ip");

	unshift @$log,"$thread,$post,$password,$ip,$key,$md5,$file";
}

method hide_password 
{
	return hide_data(shift,6,"password",$$config{secret},1)
}

method encrypt_string ($str,$key)
{
	my $iv=make_random_string(8);
	return $iv.';'.encode_base64(rc4($str,make_key($key,$$config{secret},32).$iv),"");
}

method decrypt_string ($str,$key)
{
	my ($iv,$crypt)=$str=~/(.*?);(.*)/;
	return rc4(decode_base64($crypt),make_key($key,$$config{secret},32).$iv);
}

#
# Utility funtions
#

method prepare_for_exit ($no_release_log = 0) {
	release_log($log) unless $no_release_log;
}

method get_stylesheets {
	my $found = 0;

	my @stylesheets = map {
		my %sheet;

		$sheet{filename} = $_;

		($sheet{title}) = m!([^/]+)\.css$!i;
		$sheet{title} = ucfirst $sheet{title};
		$sheet{title} =~ s/_/ /g;
		$sheet{title} =~ s/ ([a-z])/ \u$1/g;
		$sheet{title} =~ s/([a-z])([A-Z])/$1 $2/g;

		if($sheet{title} eq $$config{default_style}) { $sheet{default} = 1; $found = 1; }
		else { $sheet{default} = 0; }

		\%sheet;
	} grep { $_ ne $$config{css_dir} . $$config{global_style} } glob($$config{css_dir} . "*.css");

	$stylesheets[0]{default} = 1 if(@stylesheets and !$found);

	return \@stylesheets;
}

method check_admin_pass ($password) {
	return 1 if $password eq encode_admin_pass($$config{admin_pass});
	0
}

method encode_admin_pass 
{
	my $crypt=hide_data((shift).$ENV{REMOTE_ADDR},9,"admin",$$config{secret},1);
	$crypt=~tr/+/./; # for web shit
	return $crypt;
}

#
# Error handling
#

method make_error ($error)
{
	prepare_for_exit();
	$self->render_500($error);

	#exit;
}

#
# Image handling
#

method get_filetypes
{
	my %filetypes = $$config{filetypes}->%*;
	#$filetypes{gif}=$filetypes{jpg}=$filetypes{png}=1;
	return join ", ", map { uc } sort keys %filetypes;
}

method process_file ($file,$uploadname,$time) {
	my %filetypes = $$config{filetypes}->%*;

	# find out the file size
	my $size=-s $file;

	make_error($S_TOOBIG) if $size > $$config{max_kb} * 1024;
	make_error($S_EMPTY) if $size == 0;

	# make sure to read file in binary mode on platforms that care about such things
	binmode $file;

	# analyze file and check that it's in a supported format
	my ($ext,$width,$height) = $self->analyze_image(path($file->path)->filehandle, $uploadname);

	if(($ext eq "webm") && (!$height)) {
		make_error($S_INVALIDWEBM) if $width == 1;
		make_error($S_WEBMAUDIO) if $width == 2;
	}

	my $known=$width || $filetypes{$ext};

	make_error($S_BADFORMAT) unless($$config{allow_unknown} or $known);
	make_error($S_BADFORMAT) if(grep { $_ eq $ext } $$config{forbidden_extensions});
	make_error($S_TOOBIG) if($$config{max_image_width} and $width > $$config{max_image_width});
	make_error($S_TOOBIG) if($$config{max_image_height} and $height > $$config{max_image_height});
	make_error($S_TOOBIG) if($$config{max_image_pixels} and $width * $height > $$config{max_image_pixels});

	my $tnbase = join '', Time::HiRes::gettimeofday;
	my $filebase = $tnbase;
	my $filename = $$config{img_dir} . $filebase . '.' . $ext;
	my $thumbnail = $ext =~ /jpe?g/ ? $$config{thumb_dir} . $filebase . "s.jxl"  : $$config{thumb_dir} . $tnbase . "s.$ext";
	$filename .= $$config{munge_unkown} unless $known;

	# do copying and MD5 checksum
	my ($md5, $md5ctx, $buffer);

	# prepare MD5 checksum if the Digest::MD5 module is available
	$md5ctx=Digest::MD5->new unless($@);

	# copy file
	open (OUTFILE,">>$filename") or make_error($S_NOTWRITE);
	binmode OUTFILE;
	while (read($file,$buffer,1024)) # should the buffer be larger?
	{
		print OUTFILE $buffer;
		$md5ctx->add($buffer) if($md5ctx);
	}
	close $file;
	close OUTFILE;

	# unlink $file->path; # Plack::App::WrapCGI isn't deleting these
	#                                    # for whatever reason

	if($md5ctx) # if we have Digest::MD5, get the checksum
	{
		$md5=$md5ctx->hexdigest()
	}

	if($md5) # if we managed to generate an md5 checksum, check for duplicate files
	{
		my ($thread,$post)=find_md5($log,$md5);
		if($thread)
		{
			unlink $filename; # make sure to remove the file
			make_error(sprintf $S_DUPE,"$ENV{SCRIPT_NAME}/$thread/$post");
		}
	}

	# do thumbnail
	my ($tn_width,$tn_height,$tn_ext);

	if(!$width) # unsupported file
	{
		if($filetypes{$ext}) # externally defined filetype
		{
			open THUMBNAIL,$filetypes{$ext};
			binmode THUMBNAIL;
			($tn_ext,$tn_width,$tn_height)=analyze_image(\*THUMBNAIL,$filetypes{$ext});
			close THUMBNAIL;

			# was that icon file really there?
			if(!$tn_width) { $thumbnail=undef }
			else { $thumbnail=$filetypes{$ext} }
		}
		else
		{
			$thumbnail=undef;
		}
	}
	elsif($width > $$config{max_w} or $height > $$config{max_h} or $$config{thumbnail_small}) {
		($tn_width, $tn_height) = get_thumbnail_dimensions($width,$height);

		if ($$config{stupid_thumbnailing}) { $thumbnail = $filename }
		else {
			my $tnmethod = make_thumbnail($filename,$thumbnail,$ext,$tn_width,$tn_height,$$config{thumbnail_quality},$$config{convert_command});

			if ($tnmethod) {
				$thumbnail =~ s/$ext/$tnmethod/
			}
			else {
				$thumbnail = undef;
			}
		}
	}
	else {
		$tn_width=$width;
		$tn_height=$height;
		$thumbnail=$filename;
	}

	if($filetypes{$ext}) # externally defined filetype - restore the name
	{
		my $newfilename=$uploadname;
		$newfilename=~s!^.*[\\/]!!; # cut off any directory in filename
		$newfilename=$$config{img_dir}.$newfilename;

		unless(-e $newfilename) # verify no name clash
		{
			rename $filename,$newfilename;
			$filename=$newfilename;
		}
		else
		{
			unlink $filename;
			make_error($S_DUPENAME);
		}
	}

	return ($filename,$ext,$size,$md5,$width,$height,$thumbnail,$tn_width,$tn_height);
}

method get_thumbnail_dimensions {
	my ($width,$height) = @_;
	my ($tn_width,$tn_height);

	if($width <= $$config{max_w} and $height <= $$config{max_h}) {
		$tn_width = $width;
		$tn_height = $height;
	}
	else {
		$tn_width = $$config{max_w};
		$tn_height = int(($height*($$config{max_w}))/$width);

		if($tn_height>$$config{max_h}) {
			$tn_width = int(($width*($$config{max_h}))/$height);
			$tn_height = $$config{max_h};
		}
	}

	return ($tn_width,$tn_height);
}

__END__

=encoding utf-8

=head1 NAME

kareha::psgi - It's new $module

=head1 SYNOPSIS

    use kareha::psgi

=head1 DESCRIPTION

App::BS is ...

=head1 LICENSE

Copyright (C) Ian P Bradley.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Ian P Bradley E<lt>ian.bradley@studiocrabapple.comE<gt>

=cut

 