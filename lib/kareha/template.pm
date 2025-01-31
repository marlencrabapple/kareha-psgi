use Object::Pad;

package kareha::template;
role kareha::template :does(kareha::config)
			          :does(wakautils);

use utf8;
use v5.40;

use Const::Fast::Exporter;
use Data::Printer;

use kareha::config;
use wakautils;

#
# Interface strings
#

const our $S_NAVIGATION => 'Navigation:';
const our $S_RETURN => 'Return';
const our $S_TOP => 'Top';
const our $S_BOTTOM => 'Bottom';
const our $S_ENTIRE => 'Entire thread';
const our $S_LAST50 => 'Last 50 posts';
const our $S_FIRST100 => 'First 100 posts';
const our $S_PREV100 => 'Previous 100 posts';
const our $S_NEXT100 => 'Next 100 posts';
const our $S_THREADLIST => 'Thread list';
const our $S_BOARDLOOK => 'Board look:';
const our $S_MANAGE => 'Manage';
const our $S_REBUILD => 'Rebuild caches';
const our $S_ALLTHREADS => 'All threads';
const our $S_NEWTHREAD_TITLE => 'New thread';
const our $S_NAME => 'Name:';
const our $S_LINK => 'Link:';
const our $S_FORCEDANON => '(Anonymous posting is being enforced)';
const our $S_CAPTCHA => 'Verification:';
const our $S_TITLE => 'Title:';
const our $S_NEWTHREAD => 'New Thread';
const our $S_IMAGE => 'Image:';
const our $S_IMAGEDIM => 'Image: ';
const our $S_NOTHUMBNAIL => 'No<br />thumbnail';
const our $S_REPLY => 'Reply';
const our $S_LISTEXPL => 'Jump to thread list';
const our $S_PREVEXPL => 'Jump to previous thread';
const our $S_NEXTEXPL => 'Jump to next thread';
const our $S_LISTBUTTON => '&#9632;';
const our $S_PREVBUTTON => '&#9650;';
const our $S_NEXTBUTTON => '&#9660;';
const our $S_TRUNC => 'Post too long. Click to view the <a href="%s" rel="nofollow">whole post</a> or the <a href="%s">thread page</a>.';
const our $S_PERMASAGED => ', permasaged';
const our $S_POSTERNAME => 'Name:';
const our $S_DELETE => 'Del';
const our $S_USERDELETE => 'Post deleted by user.';
const our $S_MODDELETE => 'Post deleted by moderator.';
const our $S_CLOSEDTHREAD => 'This thread has been closed. You cannot post in this thread any longer.';
const our $S_SPAMTRAP => 'Leave these fields empty (spam trap): ';

const our $S_MOREOPTS => "More options...";
const our $S_FORMATTING => "Formatting:";
const our $S_SAVE_FORMATTING => "Always use this formatting";
const our $S_FORMATS => { none => "None", waka => "WakabaMark", html => "HTML"
                        , raw => "Raw HTML", aa => "Text Art" };

method s_describe_formats {
	none=>'Only auto-links URLs and >> references.',
	waka=>'Simple text formatting. See the description <a href="http://wakaba.c3.cx/docs/docs.html#WakabaMark">here</a>.',
	html=>'Allowed tags: <em>' . wakautils->describe_allowed($self->config->{allowed_html}).'</em>.',
	aa=>'Only auto-links URLs and >> references, and sets the font to be suitable for SJIS art.',
};

const our $S_COL_NUM => "Num";
const our $S_COL_TITLE => "Title";
const our $S_COL_POSTS => "Posts";
const our $S_COL_DATE => "Last post";
const our $S_COL_SIZE => "File size";
const our $S_LIST_PERMASAGED => 'permasaged';
const our $S_LIST_CLOSED => 'closed';

const our $S_FRONT => 'Front page';								# Title of the front page in page list


#
# Error strings
#

const our $S_BADCAPTCHA => 'Wrong verification code entered.';			# Error message when the captcha is wrong
const our $S_UNJUST => 'Posting must be done through a POST request.';	# Error message on an unjust POST - prevents floodbots or ways not using POST method?
const our $S_NOTEXT => 'No text entered.';								# Error message for no text entered in to title/comment
const our $S_NOTITLE => 'No title entered.';								# Error message for no title entered
const our $S_NOTALLOWED => 'Posting not allowed.';						# Error message when the posting type is forbidden for non-admins
const our $S_TOOLONG => 'The %s field is too long, by %d characters.';	# Error message for too many characters in a given field
const our $S_UNUSUAL => 'Abnormal reply.';								# Error message for abnormal reply? (this is a mystery!)
const our $S_SPAM => 'Spammers are not welcome here!';					# Error message when detecting spam
const our $S_THREADCOLL => 'Somebody else tried to post a thread at the same time. Please try again.';		# If two people create threads during the same second
const our $S_NOTHREADERR => 'Thread specified does not exist.';			# Error message when a non-existant thread is accessed
const our $S_BADDELPASS => 'Password incorrect.';							# Error message for wrong password (when user tries to delete file)
const our $S_NOTWRITE => 'Cannot write to directory.';					# Error message when the script cannot write to the directory, the chmod (777) is wrong
const our $S_NOTASK => 'Script error; no valid task specified.';			# Error message when calling the script incorrectly
const our $S_NOLOG => 'Couldn\'t write to log.txt.';						# Error message when log.txt is not writeable or similar
const our $S_TOOBIG => 'The file you tried to upload is too large.';		# Error message when the image file is larger than MAX_KB
const our $S_EMPTY => 'The file you tried to upload is empty.';			# Error message when the image file is 0 bytes
const our $S_INVALIDWEBM => 'The webm you uploaded is invalid.'; 		# General webm error
const our $S_WEBMAUDIO => 'The webm you uploaded contained an audio or another forbidden track.'; 		# Not so general webm error
const our $S_BADFORMAT => 'File format not allowed.';						# Error message when the file is not in a supported format.
const our $S_DUPE => 'This file has already been posted <a href="%s">here</a>.';	# Error message when an md5 checksum already exists.
const our $S_DUPENAME => 'A file with the same name already exists.';		# Error message when an filename already exists.
const our $S_THREADCLOSED => 'This thread is closed.';					# Error message when posting in a legen^H^H^H^H^H closed thread

#
# Templates
#

method global_head_include { q{
	<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
	<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
	<head>
	<title><if $title><var $title> - </if><const TITLE></title>
	<meta http-equiv="Content-Type" content="text/html;charset=<const CHARSET>" />
	<meta name="viewport" content="width=device-width,initial-scale=1" />
	<link rel="shortcut icon" href="<var expand_filename(FAVICON)>" />

	<if RSS_FILE>
	<link rel="alternate" title="RSS feed" href="<var expand_filename(RSS_FILE)>" type="application/rss+xml" />
	</if>

	<link rel="stylesheet" type="text/css" href="<var expand_filename(CSS_DIR . GLOBAL_STYLE)>" />

	<loop $stylesheets>
	<link rel="<if !$default>alternate </if>stylesheet" type="text/css" href="<var expand_filename($filename)>" title="<var $title>" />
	</loop>

	<script type="text/javascript">
	var self="<var $self>";
	var style_cookie="<const STYLE_COOKIE>";
	var markup_descriptions={
	<loop $markup_formats><var $id>:<var js_string($self->template->{s_mar}-\>{$id})>,</loop>dummy:''
	};
	var default_markup="<const $self->config->{default_markup}>";
	</script>
	<script type="text/javascript" src="<var expand_filename($self->config->{js_file})>"></script>
	<script type="text/javascript">require_script_version("3.a");</script>
	</head>
	}
}

method global_foot_include ($include = 'footer.html') {
	$self->include($include) . q{
	<div id="bottom"></div>
	</body></html>
	}
}

method install_template {
	wakautils->compile_template($self->global_head_include
	  . 'Just  a test.'
	  . $self->global_foot_include)
}

method posting_form_template {
  wakautils->compile_template(q{
<if !$thread><tr>
	<td><const S_TITLE></td>
	<td class="newthreadtitle">
		<input type="text" name="title" size="46" maxlength="<const MAX_FIELD_LENGTH>" />
		<input type="submit" value="<const S_NEWTHREAD>" />
	</td>
</tr></if>

<tr>
	<td>
		<if !$self->config->{forced_anon}><const S_NAME></if>
		<if $self->config->{forced_anon}><const S_LINK></if>
	</td>
	<td class="namelink">
		<if $self->config->{spam_trap}>
			<div style="display:none">
			<const S_SPAMTRAP>
			<input type="text" name="name" size="19" autocomplete="off" />
			<input type="text" name="link" size="19" autocomplete="off" /><
			/div>
		</if>
		<if !$self->config->{forced_anon}>
		  <input type="text" name="field_a" size="19" maxlength="<const $self->config->{max_field_length}>" />
			<span class="fpostblock"><const S_LINK></span>
		</if>
		<if $self->config->{forced_anon}><input type="hidden" name="field_a" /></if>
 		<input type="text" name="field_b" size="19" maxlength="<const $self->config->{max_field_length}>" />
		<if $thread><input type="submit" value="<const S_REPLY>" /></if>
	</td>
</tr>

<if $self->config->{enable_captcha} ><tr>
	<td><const S_CAPTCHA></td>
	<td>
		<input type="text" name="captcha" size="19" />
		<img class="<var $captchaclass>" src="<var expand_filename('captcha.pl')>?selector=.<var $captchaclass>" />
	</td>
</tr></if>

<tr class="optionstoggle">
<td></td>
<td><small><a href="javascript:show('options<var $thread>')"><const S_MOREOPTS></a></small></td>
</tr>

<tr style="display:none;vertical-align:top" id="options<var $thread>" class="options">
	<td><const S_FORMATTING></td>
	<td>
		<select name="markup" onchange="select_markup(this)"><loop $markup_formats>
		<option value="<var $id>" <if DEFAULT_MARKUP eq $id>selected="selected"</if>><var S_FORMATS-\>{$id}></option>
		</loop></select>
		<label><input type="checkbox" name="savemarkup" /> <const S_SAVE_FORMATTING></label>
		&nbsp;&nbsp; <input type="button" value="Preview post" onclick="preview_post('<var $formid>','<var $thread>')" />
		<br /><small></small>
		<div id="preview<var $thread>" class="replytext" style="display:none"></div>
	</td>
</tr>

<tr>
	<td></td>
	<td><textarea name="comment" cols="64" rows="5"></textarea></td>
</tr>

<if $allowimages><tr>
	<td><const $S_IMAGE></td>
	<td><input name="file" size="49" type="file" /></td>
</tr></if>
})
};



method main_page_template{
    wakautils->compile_template($self->global_head_include.q{
<body class="mainpage">

}.$self->include($self->config->{incldue_dir}."header.html").q{

<div id="titlebox" class="outerbox"><div class="innerbox">

<h1>
<if $self->config->{showtitleimg}==1><img src="<var expand_filename($self->config->{TITLEIMG})>" alt="<const $self->config->{title}>" /></if>
<if $self->config->{showtitleimg}==2><img src="<var expand_filename($self->config->{TITLEIMG})>" onclick="this.src=this.src;" alt="<const $self->config->{title}>" /></if>
<if $self->config->{showtitleimg} and $self->config->{showtitletxt}><br /></if>
<if $self->config->{showtitletxt}><const TITLE></if>
</h1>

<div class="threadnavigation">
<a href="#menu" title="<const $S_LISTEXPL>"><const $S_LISTBUTTON></a>
<a href="#1" title="<const $S_NEXTEXPL>"><const $S_NEXTBUTTON></a>
</div>

<div id="rules">
}.$self->include($self->config->{include_dir}."rules.html").q{
</div>

</div></div>

<div id="stylebox" class="outerbox"><div class="innerbox">

<strong><const $S_BOARDLOOK></strong>
<loop $stylesheets>
	<a href="javascript:set_stylesheet('<var $title>')"><var $title></a>
</loop>

</div></div>

<a name="menu"></a>

}.$self->include($self->config->{include_dir}."mid.html").q{

<div id="threadbox" class="outerbox"><div class="innerbox">

<div id="threadlist">
<loop $allthreads><if $num<=$self->config->{threads_listed}>
	<span class="threadlink">
	<a href="<var $self>/<var $thread>/l50" rel="nofollow"><var $num>:
	<if $num<=$self->config->{threads_displayed}></a><a href="#<var $num>"></if>
	<var $title> (<var $postcount>)</a>
	</span>
</if></loop>
</div>

<div id="threadlistnav">
<a href="#newthread"><const $S_NEWTHREAD_TITLE></a>
<a href="<var expand_filename($self->config->{http_backlog})>"><const $S_ALLTHREADS></a>
</div>

</div></div>

<div id="posts">

<loop $threads>
	<a name="<var $num>"></a>
	<if $permasage><div class="sagethread"></if>
	<if !$permasage><div class="thread"></if>
	<h2><a href="<var $self>/<var $thread>/l50" rel="nofollow"><var $title>
	<small>(<var $postcount><if $permasage>, permasaged</if>)</small></a></h2>

	<div class="threadnavigation">
	<a href="#menu" title="<const S_LISTEXPL>"><const S_LISTBUTTON></a>
	<a href="#<var $prevnum>" title="<const S_PREVEXPL>"><const S_PREVBUTTON></a>
	<a href="#<var $nextnum>" title="<const S_NEXTEXPL>"><const S_NEXTBUTTON></a>
	</div>

	<div class="replies">

	<if $omit><div class="firstreply"></if>
	<if !$omit><div class="allreplies"></if>

	<loop $posts>
		<var $abbreviation>
		<if $abbreviated>
			<div class="replyabbrev">
			<var sprintf(S_TRUNC,"$self/$thread/$num","$self/$thread/l50")>
			</div>
		</if>

		<if $omit and $num==1>
		</div><div class="repliesomitted"></div><div class="finalreplies">
		</if>
	</loop>

	</div>
	</div>

	<form id="postform<var $thread>" action="<var $self>" method="post" class="postform" enctype="multipart/form-data">
	<input type="hidden" name="task" value="post" />
	<input type="hidden" name="thread" value="<var $thread>" />
	<input type="hidden" name="password" value="" />
	<table><tbody>
	<if !$closed><var POSTING_FORM_TEMPLATE-\>(thread=\>$thread,captchaclass=\>"postcaptcha",formid=\>"postform$thread",allowimages=\>ALLOW_IMAGE_REPLIES)></if>
	<if $closed><tr><td></td><td><big><const S_CLOSEDTHREAD></big></td></tr></if>
	<tr>
		<td></td>
		<td><div class="threadlinks">
		<a href="<var $self>/<var $thread>/"><const S_ENTIRE></a>
		<a href="<var $self>/<var $thread>/l50" rel="nofollow"><const S_LAST50></a>
		<a href="<var $self>/<var $thread>/-100" rel="nofollow"><const S_FIRST100></a>
		<a href="#menu"><const S_THREADLIST></a>
		</div></td>
	</tr>
	</tbody></table>
	</form>
	<script type="text/javascript">set_new_inputs("postform<var $thread>");</script>

	</div>
</loop>

</div>

<a name="newthread"></a>

<div id="createbox" class="outerbox"><div class="innerbox">

<div id="newthreadhead">
	<h2><const S_NEWTHREAD_TITLE></h2>
	<div id="newthreadnav">
		<a href="#threadlist"><const S_THREADLIST></a>
		<a href="<var expand_filename(HTML_BACKLOG)>"><const S_ALLTHREADS></a>
	</div>
</div>

<form id="threadform" action="<var $self>" method="post" class="postform" enctype="multipart/form-data">

<input type="hidden" name="task" value="post" />
<input type="hidden" name="password" value="" />
<table><tbody>
<var POSTING_FORM_TEMPLATE-\>(captchaclass=\>"threadcaptcha",formid=\>"threadform",allowimages=\>ALLOW_IMAGE_THREADS)>
</tbody></table>
</form>

</div></div>

<script type="text/javascript">set_new_inputs("threadform");</script>

}.$self->global_foot_include, $self->config->{keep_mainpage_newlines})
}

method thread_head_template { 
	compile_template( $self->global_head_include.q{
<body class="threadpage">

}.include( $self->config->{include_dir}."header.html").q{

<div id="navigation">
<strong><const S_NAVIGATION></strong>
<a href="<var expand_filename(HTML_SELF)>"><const S_RETURN></a>
<a href="<var $self>/<var $thread>/"><const S_ENTIRE></a>
<a href="<var $self>/<var $thread>/-100" rel="nofollow"><const S_FIRST100></a>
<loop [map {+{'start'=\>$_*100+1}} (1..($postcount-1)/100)]>
	<a href="<var $self>/<var $thread>/<var $start>-<var $start+99<$postcount?$start+99:$postcount>" rel="nofollow"><var $start>-</a>
</loop>
<a href="<var $self>/<var $thread>/l50" rel="nofollow"><const S_LAST50></a>
<a href="#bottom"><const S_BOTTOM></a>
</div>

<div id="posts">

<if $permasage><div class="sagethread"></if>
<if !$permasage><div class="thread"></if>
<h2><var $title> <small>(<var $postcount><if $permasage><const S_PERMASAGED></if>)</small></h2>

<div class="replies">
<div class="allreplies">
})
}



method thread_foot_template {
	wakautils->compile_template( q{

</div>
</div>

<if $self->config->{autoclose_size}>
<h4><var int($size/1024)> kb</h4>
</if>

<form id="postform<var $thread>" action="<var $self>" method="post" class="postform" enctype="multipart/form-data">

<input type="hidden" name="task" value="post" />
<input type="hidden" name="thread" value="<var $thread>" />
<input type="hidden" name="password" value="" />
<table><tbody>
<tr>
	<td></td>
	<td><div class="threadlinks">
	<a href="<var expand_filename($self->config->{html_self})>"><const S_RETURN></a>
	<a href="<var $self>/<var $thread>/"><const S_ENTIRE></a>
	<if $prevpost><a href="<var $self>/<var $thread>/<var $prevpost\>99?$prevpost-99:1>-<var $prevpost>" rel="nofollow"><const S_PREV100></a></if>
	<if $nextpost><a href="<var $self>/<var $thread>/<var $nextpost>-<var $nextpost<$postcount-99?$nextpost+99:$postcount>" rel="nofollow"><const S_NEXT100></a></if>
	<a href="<var $self>/<var $thread>/l50" rel="nofollow"><const S_LAST50></a>
	<a href="#top"><const S_TOP></a>
	</div></td>
</tr>
<if !$closed><var POSTING_FORM_TEMPLATE-\>(thread=\>$thread,captchaclass=\>"postcaptcha",formid=\>"postform$thread",allowimages=\>ALLOW_IMAGE_REPLIES)></if>
<if $closed><tr><td></td><td><big><const S_CLOSEDTHREAD></big></td></tr></if>
</tbody></table>

</form>

<script type="text/javascript">set_new_inputs("postform<var $thread>");</script>

</div>
</div>

}.$self->global_foot_include)
}


method reply_template {
	wakautils->compile_template(q{
<div class="reply" id="reply<var $num>">

<h3>
<span class="replynum"><a title="Quote post number in reply" href="javascript:insert('&gt;&gt;<var $num>',<var $thread>)"><var $num></a></span>
<const S_POSTERNAME>
<if $link><span class="postername"><a href="<var $link>" rel="nofollow"><var $name></a></span><span class="postertrip"><a href="<var $link>" rel="nofollow"><if !$capped><var $trip></if><if $capped><var $capped></if></a></span></if>
<if !$link><span class="postername"><var $name></span><span class="postertrip"><if !$capped><var $trip></if><if $capped><var $capped></if></span></if>
: <var $date>
<if $image><span class="filesize">(<const S_IMAGEDIM><em><var $width>x<var $height> <var $ext>, <var int($size/1024)> kb</em>)</span></if>
<span class="deletebutton">
<if ENABLE_DELETION>[<a href="javascript:delete_post(<var $thread>,<var $num><if $image>,true</if>)"><const S_DELETE></a>]</if>
<if !ENABLE_DELETION><span class="manage" style="display:none;">[<a href="javascript:delete_post(<var $thread>,<var $num><if $image>,true</if>)"><const S_DELETE></a>]</span></if>
</span>
</h3>

<if $image>
	<if $thumbnail>
		<a href="<var expand_filename(clean_path($image))>" target="_blank">
		<img src="<var expand_filename($thumbnail)>" width="<var $tn_width>" height="<var $tn_height>"
		alt="<var clean_string($image)>: <var $width>x<var $height>, <var int($size/1024)> kb"
		title="<var clean_string($image)>: <var $width>x<var $height>, <var int($size/1024)> kb"
		class="thumb" /></a>
	</if><if !$thumbnail>
		<div class="nothumbnail">
		<a href="<var expand_filename(clean_path($image))>"><const S_NOTHUMBNAIL></a>
		</div>
	</if>
</if>

<div class="replytext"><var $comment></div>

</div>
})
};

method deleted_template {
	wkautils->compile_template( q{
<div class="deletedreply">
<h3>
<span class="replynum"><var $num></span>
<if $reason eq 'user'><const S_USERDELETE></if>
<if $reason eq 'mod'><const S_MODDELETE></if>
</h3>
</div>
});
}

method backlog_thread_tempalte {
	wakautils->compile_template( $self->global_head_include.q{
<body class="backlogpage">

}.$self->include($self->config->{include_dir}."header.html").q{

<div id="navigation">
<strong><const S_NAVIGATION></strong>
<if $postform>
<script>set_stylesheet('<const $self->config->{default_style} >'); set_preferred_stylesheet('<const $self->config->{default_style}>');</script>
<a href="#newthread"><const S_NEWTHREAD_TITLE></a>
<span class="longdash">—</span>
}.$self->include($self->config->{include_dir}."header.html").q{
</if>
<if !postform>
<a href="<var expand_filename($self->config->{html_self})>"><const S_RETURN></a>
</if>
</div>

<div id="threads">

<h1><const $self->config->{title} ></h1>

<table id="oldthreadlist">

<thead>
<tr class="head">
<th><const S_COL_NUM></th>
<th><const S_COL_TITLE></th>
<th><const S_COL_POSTS></th>
<th><const S_COL_DATE></th>
<th><const S_COL_SIZE></th>
</tr>
</thead>

<tbody>
<loop $threads>
<tr class="line<var $num&1>">

<td class="sb-num" align="right"><var $num>:</td>
<td class="sb-title"><a href="<var $self>/<var $thread>/l50" rel="nofollow">
<var $title><if $closed or $permasage> <small>
(<if $closed><const S_LIST_CLOSED></if><if !$closed and $permasage><const S_LIST_PERMASAGED></if>)
</small></if></a></td>
<td class="sb-postcount" align="right"><a href="<var $self>/<var $thread>/"><var $postcount></a></td>
<td class="sb-date"><var make_date($lastmod,$self->config{date_style})></td>
<td class="sb-size" align="right"><var int($size/1024)> kb</td>

</tr>
</loop>
</tbody></table>

</div>

<if $postform>
<a name="newthread"></a>

<div id="createbox" class="outerbox"><div class="innerbox">

<div id="newthreadhead">
	<h2><const S_NEWTHREAD_TITLE></h2>
</div>

<form id="threadform" action="<var $self>" method="post" class="postform" enctype="multipart/form-data">

<input type="hidden" name="task" value="post" />
<input type="hidden" name="password" value="" />
<table><tbody>
<var POSTING_FORM_TEMPLATE-\>(captchaclass=\>"threadcaptcha",formid=\>"threadform",allowimages=\>ALLOW_IMAGE_THREADS)>
</tbody></table>
</form>

</div></div>

<script type="text/javascript">set_new_inputs("threadform");</script>
</if>

}.$self->global_foot_include);
}



method rss_tempalate {
	wakautils->compile_template( q{
<?xml version="1.0" encoding="<const CHARSET>"?>
<rss version="2.0">

<channel>
<title><const $self->config->{title}></title>
<link><var $absolute_path><const HTML_SELF></link>
<description>Posts on <const $self->config->{title}> at <var $ENV{SERVER_NAME}>.</description>

<loop $threads><if $num<=$self->config->{threads_displayed}>
	<item>
	<title><var $title> (<var $postcount>)</title>
	<link><var $absolute_self>/<var $thread>/</link>
	<guid><var $absolute_self>/<var $thread>/</guid>
	<comments><var $absolute_self>/<var $thread>/</comments>
	<author><var $author></author>
	<description><![CDATA[
		<var $$posts[0]{abbreviation}=~m!<div class="replytext".(.*?)</div!; $1 >
		<if $abbreviated><p><small>Post too long, full version <a href="<var $absolute_self>/<var $thread>/">here</a>.</small></p>
		</if>
	]]></description>
	</item>
</if></loop>

</channel>
</rss>
})
}

method error_template {
	wakautils->compile_template($self->global_head_include . q{
<body class="errorpage">}
  .$self->include($self->config->{include_dir}."header.html")
  .q{<div id="navigation">
	<strong><const S_NAVIGATION></strong>
	<a href="<var escamp($ENV{HTTP_REFERER})>"><const S_RETURN></a>
  < /div>
<h1><var $error></h1>
<h2><a href="<var escamp($ENV{HTTP_REFERER})>"><const S_RETURN></a></h2>
} . $self->global_foot_include)
}

