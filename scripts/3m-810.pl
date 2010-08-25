#!/usr/bin/perl

use strict;
use warnings;

use Data::Dump qw/dump/;
use Carp qw/confess/;
use Getopt::Long;
use File::Slurp;
use JSON;
use POSIX qw(strftime);

use IO::Socket::INET;

my $debug = 0;

my $tags_data;
my $tags_security;
my $visible_tags;

my $listen_port = 9000;                  # pick something not in use
my $server_url  = "http://localhost:$listen_port";

sub http_server {

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalPort => $listen_port,
		Listen    => SOMAXCONN,
		Reuse     => 1
	);
								  
	die "can't setup server: $!" unless $server;

	print "Server $0 ready at $server_url\n";

	sub static {
		my ($client,$path) = @_;

		$path = "www/$path";
		$path .= 'rfid.html' if $path =~ m{/$};

		return unless -e $path;

		my $type = 'text/plain';
		$type = 'text/html' if $path =~ m{\.htm};
		$type = 'application/javascript' if $path =~ m{\.js};

		print $client "HTTP/1.0 200 OK\r\nContent-Type: $type\r\n\r\n";
		open(my $html, $path);
		while(<$html>) {
			print $client $_;
		}
		close($html);

		return $path;
	}

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		my $request = <$client>;

		warn "WEB << $request\n" if $debug;

		if ($request =~ m{^GET (/.*) HTTP/1.[01]}) {
			my $method = $1;
			my $param;
			if ( $method =~ s{\?(.+)}{} ) {
				foreach my $p ( split(/[&;]/, $1) ) {
					my ($n,$v) = split(/=/, $p, 2);
					$param->{$n} = $v;
				}
				warn "WEB << param: ",dump( $param ) if $debug;
			}
			if ( my $path = static( $client,$1 ) ) {
				warn "WEB >> $path" if $debug;
			} elsif ( $method =~ m{/scan} ) {
				my $tags = scan_for_tags();
				my $json = { time => time() };
				map {
					my $d = decode_tag($_);
					$d->{sid} = $_;
					$d->{security} = $tags_security->{$_};
					push @{ $json->{tags} },  $d;
				} keys %$tags;
				print $client "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n",
					$param->{callback}, "(", to_json($json), ")\r\n";
			} elsif ( $method =~ m{/program} ) {

				my $status = 501; # Not implementd

				foreach my $p ( keys %$param ) {
					next unless $p =~ m/^(E[0-9A-F]{15})$/;
					my $tag = $1;
					my $content = "\x04\x11\x00\x01" . $param->{$p};
					$content = "\x00" if $param->{$p} eq 'blank';
					$status = 302;

					warn "PROGRAM $tag $content\n";
					write_tag( $tag, $content );
					secure_tag_with( $tag, $param->{$p} =~ /^130/ ? 'DA' : 'D7' );
				}

				print $client "HTTP/1.0 $status $method\r\nLocation: $server_url\r\n\r\n";

			} elsif ( $method =~ m{/secure(.js)} ) {

				my $json = $1;

				my $status = 501; # Not implementd

				foreach my $p ( keys %$param ) {
					next unless $p =~ m/^(E[0-9A-F]{15})$/;
					my $tag = $1;
					my $data = $param->{$p};
					$status = 302;

					warn "SECURE $tag $data\n";
					secure_tag_with( $tag, $data );
				}

				if ( $json ) {
					print $client "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n",
						$param->{callback}, "({ ok: 1 })\r\n";
				} else {
					print $client "HTTP/1.0 $status $method\r\nLocation: $server_url\r\n\r\n";
				}

			} else {
				print $client "HTTP/1.0 404 Unkown method\r\n\r\n";
			}
		} else {
			print $client "HTTP/1.0 500 No method\r\n\r\n";
		}
		close $client;
	}

	die "server died";
}


my $last_message = {};
sub _message {
	my $type = shift @_;
	my $text = join(' ',@_);
	my $last = $last_message->{$type};
	if ( $text ne $last ) {
		warn $type eq 'diag' ? '# ' : '', $text, "\n";
		$last_message->{$type} = $text;
	}
}

sub _log { _message('log',@_) };
sub diag { _message('diag',@_) };


my $program_path = './program/';
my $secure_path = './secure/';

# http server
my $http_server = 1;

# 3M defaults: 8,4
# cards 16, stickers: 8
my $max_rfid_block = 8;
my $read_blocks = 8;

my $response = {
	'd500090400110a0500027250'				=> 'version?',
	'd60007fe00000500c97b'					=> 'no tag in range',

	'd6000ffe00000501e00401003123aa26941a'	=> 'tag #1',
	'd6000ffe00000501e0040100017c0c388e2b'	=> 'rfid card',
	'd6000ffe00000501e00401003123aa2875d4'  => 'tag red-stripe',

	'd60017fe00000502e00401003123aa26e0040100017c0c38cadb' => 'tag #1 + card',
	'd60017fe00000502e00401003123aa26e00401003123aa283124' => 'tag #1 + tag red-stripe',
};

GetOptions(
	'd|debug+'    => \$debug,
	'device=s'    => \$device,
	'baudrate=i'  => \$baudrate,
	'databits=i'  => \$databits,
	'parity=s'    => \$parity,
	'stopbits=i'  => \$stopbits,
	'handshake=s' => \$handshake,
	'http-server!' => \$http_server,
) or die $!;

my $verbose = $debug > 0 ? $debug-- : 0;

=head1 NAME

3m-810 - support for 3M 810 RFID reader

=head1 SYNOPSIS

3m-810.pl --device /dev/ttyUSB0

=head1 DESCRIPTION

Communicate with 3M 810 RFID reader and document it's protocol

=head1 SEE ALSO

L<Device::BiblioPort(3)>

L<perl(1)>

L<http://stackoverflow.com/questions/149617/how-could-i-guess-a-checksum-algorithm>

=head1 AUTHOR

Dobrica Pavlinusic <dpavlin@rot13.org> L<http://www.rot13.org/~dpavlin/>

=head1 COPYRIGHT AND LICENSE

This program is free software; you may redistribute it and/or modify
it under the same terms ans Perl itself.

=cut

my $item_type = {
	1 => 'Book',
	6 => 'CD/CD ROM',
	2 => 'Magazine',
	13 => 'Book with Audio Tape',
	9 => 'Book with CD/CD ROM',
	0 => 'Other',

	5 => 'Video',
	4 => 'Audio Tape',
	3 => 'Bound Journal',
	8 => 'Book with Diskette',
	7 => 'Diskette',
};

warn "## known item type: ",dump( $item_type ) if $debug;

# Just in case: reset our timing and buffers
$port->lookclear();
$port->read_const_time(100);
$port->read_char_time(5);

# Turn on parity checking:
#$port->stty_inpck(1);
#$port->stty_istrip(1);

# initial hand-shake with device

cmd( 'D5 00  05   04 00 11                 8C66', 'hw version',
     'D5 00  09   04 00 11   0A 05 00 02   7250', sub {
	my $hw_ver = join('.', unpack('CCCC', skip_assert(3) ));
	print "hardware version $hw_ver\n";
});

cmd( 'D6 00  0C   13  04  01 00  02 00  03 00  04 00   AAF2','FIXME: stats?',
     'D6 00  0C   13  00  02 01 01 03 02 02 03  00     E778', sub { assert() }  );

sub scan_for_tags {

	my @tags;

	cmd( 'D6 00  05   FE     00  05         FA40', "scan for tags",
		 'D6 00  0F   FE  00 00  05 ', sub { # 01 E00401003123AA26  941A	 # seen, serial length: 8
			my $rest = shift || die "no rest?";
			my $nr = ord( substr( $rest, 0, 1 ) );

			if ( ! $nr ) {
				_log "no tags in range\n";
				update_visible_tags();
				$tags_data = {};
			} else {

				my $tags = substr( $rest, 1 );
				my $tl = length( $tags );
				die "wrong length $tl for $nr tags: ",dump( $tags ) if $tl =! $nr * 8;

				push @tags, uc(unpack('H16', substr($tags, $_ * 8, 8))) foreach ( 0 .. $nr - 1 );
				warn "## tags ",as_hex($tags), " [$tl] = ",dump( $tags ) if $debug;
				_log "$nr tags in range: ", join(',', @tags ) , "\n";

				update_visible_tags( @tags );
			}
		}
	);

	diag "tags: ",dump( @tags );
	return $tags_data;

}

# start scanning for tags

if ( $http_server ) {
	http_server;
} else {
	while (1) {
		scan_for_tags;
		sleep 1;
	}
}

die "over and out";

sub update_visible_tags {
	my @tags = @_;

	my $last_visible_tags = $visible_tags;
	$visible_tags = {};

	foreach my $tag ( @tags ) {
		$visible_tags->{$tag}++;
		if ( ! defined $last_visible_tags->{$tag} ) {
			if ( defined $tags_data->{$tag} ) {
				warn "$tag in range\n";
			} else {
				read_tag( $tag );
			}
		} else {
			warn "## using cached data for $tag" if $debug;
		}
		delete $last_visible_tags->{$tag}; # leave just missing tags

		if ( -e "$program_path/$tag" ) {
				write_tag( $tag );
		}
		if ( -e "$secure_path/$tag" ) {
				secure_tag( $tag );
		}
	}

	foreach my $tag ( keys %$last_visible_tags ) {
		my $data = delete $tags_data->{$tag};
		warn "$tag removed ", dump($data), $/;
	}

	warn "## update_visible_tags(",dump( @tags ),") = ",dump( $visible_tags )," removed: ",dump( $last_visible_tags ), " data: ",dump( $tags_data ) if $debug;
}

my $tag_data_block;

sub read_tag_data {
	my ($start_block,$rest) = @_;
	die "no rest?" unless $rest;

	my $last_block = 0;

	warn "## DATA [$start_block] ", dump( $rest ) if $debug;
	my $tag = uc(unpack('H16',substr( $rest, 0, 8 )));
	my $blocks = ord(substr($rest,8,1));
	$rest = substr($rest,9); # leave just data blocks
	foreach my $nr ( 0 .. $blocks - 1 ) {
		my $block = substr( $rest, $nr * 6, 6 );
		warn "## block ",as_hex( $block ) if $debug;
		my $ord   = unpack('v',substr( $block, 0, 2 ));
		my $expected_ord = $nr + $start_block;
		warn "got block $ord, expected block $expected_ord from ",dump( $block ) if $ord != $expected_ord;
		my $data  = substr( $block, 2 );
		die "data payload should be 4 bytes" if length($data) != 4;
		warn sprintf "## tag %9s %02d: %s |%-4s|\n", $tag, $ord, as_hex( $data ), $data;
		$tag_data_block->{$tag}->[ $ord ] = $data;
		$last_block = $ord;
	}
	$tags_data->{ $tag } = join('', @{ $tag_data_block->{$tag} });

	my $item_type_nr = ord(substr( $tags_data->{$tag}, 3, 1 ));
	print "DATA $tag ",dump( $tags_data ), " item type: ", ( $item_type->{ $item_type_nr } || "UNKWOWN '$item_type_nr'" ), "\n";

	return $last_block + 1;
}

my $saved_in_log;

sub decode_tag {
	my $tag = shift;

	my $data = $tags_data->{$tag};
	if ( ! $data ) {
		warn "no data for $tag\n";
		return;
	}

	my ( $u1, $set_item, $u2, $type, $content, $br_lib, $custom ) = unpack('C4Z16Nl>',$data);
	my $hash = {
		u1 => $u1,
		u2 => $u2,
		set => ( $set_item & 0xf0 ) >> 4,
		total => ( $set_item & 0x0f ),

		type => $type,
		content => $content,

		branch => $br_lib >> 20,
		library => $br_lib & 0x000fffff,

		custom => $custom,
	};

	if ( ! $saved_in_log->{$tag}++ ) {
		open(my $log, '>>', 'rfid-log.txt');
		print $log strftime( "%Y-%m-%d %H:%M:%S", localtime ), ",$tag,$content\n";
		close($log);
	}

	return $hash;
}

sub forget_tag {
	my $tag = shift;
	delete $tags_data->{$tag};
	delete $visible_tags->{$tag};
}

sub read_tag {
	my ( $tag ) = @_;

	confess "no tag?" unless $tag;

	print "read_tag $tag\n";

	my $start_block = 0;

	while ( $start_block < $max_rfid_block ) {

		cmd(
			 sprintf( "D6 00  0D  02      $tag   %02x   %02x     BEEF", $start_block, $read_blocks ),
				"read $tag offset: $start_block blocks: $read_blocks",
			"D6 00  1F  02 00", sub { # $tag  03   00 00   04 11 00 01   01 00   31 32 33 34   02 00   35 36 37 38    531F\n";
				$start_block = read_tag_data( $start_block, @_ );
				warn "# read tag upto $start_block\n";
			},
			"D6 00  0F  FE  00 00  05 01   $tag    BEEF", sub {
				print "FIXME: tag $tag ready? (expected block read instead)\n";
			},
			"D6 00 0D 02 06 $tag", sub {
				my $rest = shift;
				print "ERROR reading $tag ", as_hex($rest), $/;
				forget_tag $tag;
				$start_block = $max_rfid_block; # XXX break out of while
			},
		);

	}

	my $security;

	cmd(
		"D6 00 0B 0A $tag BEEF", "check security $tag",
		"D6 00 0D 0A 00", sub {
			my $rest = shift;
			my $from_tag;
			( $from_tag, $security ) = ( substr($rest,0,8), substr($rest,8,1) );
			die "security from other tag: ",as_hex( $from_tag ) if $from_tag ne str2bytes( $tag );
			$security = as_hex( $security );
			$tags_security->{$tag} = $security;
			warn "# SECURITY $tag = $security\n";
		},
		"D6 00 0C 0A 06", sub {
			my $rest = shift;
			warn "ERROR reading security from $rest\n";
			forget_tag $tag;
		},
	);

	print "TAG $tag ", dump(decode_tag( $tag ));
}

sub write_tag {
	my ($tag,$data) = @_;

	my $path = "$program_path/$tag";
	$data = read_file( $path ) if -e $path;

	die "no data" unless $data;

	my $hex_data;

	if ( $data =~ s{^hex\s+}{} ) {
		$hex_data = $data;
		$hex_data =~ s{\s+}{}g;
	} else {

		$data .= "\0" x ( 4 - ( length($data) % 4 ) );

		my $max_len = $max_rfid_block * 4;

		if ( length($data) > $max_len ) {
			$data = substr($data,0,$max_len);
			warn "strip content to $max_len bytes\n";
		}

		$hex_data = unpack('H*', $data);
	}

	my $len = length($hex_data) / 2;
	# pad to block size
	$hex_data .= '00' x ( 4 - $len % 4 );
	my $blocks = sprintf('%02x', length($hex_data) / 4);

	print "write_tag $tag = ",dump( $data ), " [$len/$blocks] == $hex_data\n";

	my $ok = 0;

	cmd(
		"d6 00  ff  04  $tag  00 $blocks 00  $hex_data  BEEF", "write $tag",
		"d6 00  0d  04 00  $tag  $blocks  BEEF", sub { assert(); $ok++ },
		"d6 00  0d  04 06  ", sub {
			my $data = shift;
			warn "no tag ",as_hex( substr($data,0,8) ), " in range for write\n";
		},
	); # foreach ( 1 .. 3 ); # XXX 3m software does this three times!

	if ( $ok ) {

		my $to = $path;
		$to .= '.' . time();

		rename $path, $to;
		print ">> $to\n";

	}

	forget_tag $tag;
}

sub secure_tag_with {
	my ( $tag, $data ) = @_;

	cmd(
		"d6 00  0c  09  $tag $data BEEF", "secure $tag -> $data",
		"d6 00  0c  09 00  $tag    BEEF", sub { assert() },
		"d6 00  0c  09 06  ", sub {
			my $data = shift;
			warn "no tag ",as_hex( substr($data,0,8) ), " in range for secure\n";
		},
	);

	forget_tag $tag;
}

sub secure_tag {
	my ($tag) = @_;

	my $path = "$secure_path/$tag";
	my $data = substr(read_file( $path ),0,2);

	secure_tag_with( $tag, $data );

	my $to = $path;
	$to .= '.' . time();

	rename $path, $to;
	print ">> $to\n";
}

exit;

for ( 1 .. 3 ) {

#                                                              ++-->type 00-0a
#     D6 00  2A  04     E00401003123AA26  00  07  00  04 11 00 01 31 31 31 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1C D4
#     D6 00 2A 04 E0 04 01 00 31 23 AA 26 00  07  00  04 11 00 06 32 32 32 32 32 32 32 32 32 32 32 00 00 00 00 00 00 00 00 00 00 00 00 00 32B7
#     D6 00 2A 04 E0 04 01 00 31 23 AA 26 00  07  00  04 11 00 02 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 00 00 00 00 00 00 00 00 42 1F

cmd(' D6 00  2A  04     E00401003123AA26  00  07  00  04 11 00 01 30 30 30 30 30 30 30 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00   8843', "write offset 0, block: 7 -- 0000000000 $_" );
warn "D6 00  0D  04 00  E00401003123AA26  07  CFF1 -- ack 7 block?\n";

}
warn "  D6 00   0F   FE 00   00   05 01  E00401003123AA26 941A\n";

cmd( 'D6 00 05 FE 00 05 FA 40', "port-write scan $_" ) foreach ( 1 .. 2 );

cmd('D6 00  0C  09    E00401003123AA26  D7  3AF0', 'checkin?',
    'D6 00  0C  09 00 E00401003123AA26      6A44 -- no?' );
cmd('D6 00  0C  09    E00401003123AA26  DA  EB5D', 'checkout?',
    'D6 00  0C  09 00 E00401003123AA26      6A44 -- no?' );

cmd('D6 00  26  04    E00401003123AA26  00  06  00  55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55  A98B', 'blank offset: 0 blocks: 6', 
    'D6 00  0D  04 00 E00401003123AA26  06  DFD0 -- ack 6 blocks' ) foreach ( 1 .. 3 );

undef $port;
print "Port closed\n";

sub writechunk
{
	my $str=shift;
	my $count = $port->write($str);
	my $len = length($str);
	die "wrong write length $count != $len in ",as_hex( $str ) if $count != $len;
	print "#> ", as_hex( $str ), "\t[$count]\n" if $debug;
}

sub as_hex {
	my @out;
	foreach my $str ( @_ ) {
		my $hex = uc unpack( 'H*', $str );
		$hex =~ s/(..)/$1 /g if length( $str ) > 2;
		$hex =~ s/\s+$//;
		push @out, $hex;
	}
	return join(' | ', @out);
}

sub read_bytes {
	my ( $len, $desc ) = @_;
	my $data = '';
	while ( length( $data ) < $len ) {
		my ( $c, $b ) = $port->read(1);
		die "no bytes on port: $!" unless defined $b;
		#warn "## got $c bytes: ", as_hex($b), "\n";
		$data .= $b;
	}
	$desc ||= '?';
	warn "#< ", as_hex($data), "\t$desc\n" if $debug;
	return $data;
}

our $assert;

# my $rest = skip_assert( 3 );
sub skip_assert {
	assert( 0, shift );
}

sub assert {
	my ( $from, $to ) = @_;

	$from ||= 0;
	$to = length( $assert->{expect} ) if ! defined $to;

	my $p = substr( $assert->{payload}, $from, $to );
	my $e = substr( $assert->{expect},  $from, $to );
	warn "EXPECTED ",as_hex($e), " GOT ", as_hex($p), " [$from-$to] in ",dump( $assert ), "\n" if $e ne $p;

	# return the rest
	return substr( $assert->{payload}, $to );
}

use Digest::CRC;

sub crcccitt {
	my $bytes = shift;
	my $crc = Digest::CRC->new(
		# midified CCITT to xor with 0xffff instead of 0x0000
		width => 16, init => 0xffff, xorout => 0xffff, refout => 0, poly => 0x1021, refin => 0,
	) or die $!;
	$crc->add( $bytes );
	pack('n', $crc->digest);
}

# my $checksum = checksum( $bytes );
# my $checksum = checksum( $bytes, $original_checksum );
sub checksum {
	my ( $bytes, $checksum ) = @_;

	my $len = ord(substr($bytes,2,1));
	my $len_real = length($bytes) - 1;

	if ( $len_real != $len ) {
		print "length wrong: $len_real != $len\n";
		$bytes = substr($bytes,0,2) . chr($len_real) . substr($bytes,3);
	}

	my $xor = crcccitt( substr($bytes,1) );	# skip D6
	warn "## checksum ",dump( $bytes, $xor, $checksum ) if $debug;

	if ( defined $checksum && $xor ne $checksum ) {
		warn "checksum error: ", as_hex($xor), " != ", as_hex($checksum), " data: ", as_hex($bytes), "\n" if $checksum ne "\xBE\xEF";
		return $bytes . $xor;
	}
	return $bytes . $checksum;
}

our $dispatch;

sub readchunk {
#	sleep 1;	# FIXME remove

	# read header of packet
	my $header = read_bytes( 2, 'header' );
	my $length = read_bytes( 1, 'length' );
	my $len = ord($length);
	my $data = read_bytes( $len, 'data' );

	my $payload  = substr( $data, 0, -2 );
	my $payload_len = length($data);
	warn "## payload too short $payload_len != $len\n" if $payload_len != $len;

	my $checksum = substr( $data, -2, 2 );
	checksum( $header . $length . $payload , $checksum );

	print "<< ",as_hex( $header ), " [$len] ", as_hex( $payload ), " | sum: ",as_hex($checksum),"\n" if $verbose;

	$assert->{len}      = $len;
	$assert->{payload}  = $payload;

	my $full = $header . $length . $data; # full
	# find longest match for incomming data
	my ($to) = grep {
		my $match = substr($payload,0,length($_));
		m/^\Q$match\E/
	} sort { length($a) <=> length($b) } keys %$dispatch;
	warn "?? payload dispatch to ",dump( $payload, $dispatch, $to ) if $debug;

	if ( defined $to ) {
		my $rest = substr( $payload, length($to) ) if length($to) < length($payload);
		warn "## DISPATCH payload to with rest", dump( $payload, $to, $rest ) if $debug;
		$dispatch->{ $to }->( $rest );
	} else {
		die "NO DISPATCH for ",as_hex( $full ), " in ", dump( $dispatch );
	}

	return $data;
}

sub str2bytes {
	my $str = shift || confess "no str?";
	my $b = $str;
	$b =~ s/\s+//g;
	$b =~ s/(..)/\\x$1/g;
	$b = "\"$b\"";
	my $bytes = eval $b;
	die $@ if $@;
	warn "## str2bytes( $str ) => $b => ",as_hex($bytes) if $debug;
	return $bytes;
}

sub cmd {
	my $cmd = shift || confess "no cmd?";
	my $cmd_desc = shift || confess "no description?";
	my @expect = @_;

	my $bytes = str2bytes( $cmd );

	# fix checksum if needed
	$bytes = checksum( substr( $bytes, 0, -2 ), substr( $bytes, -2, 2 ) );

	warn ">> ", as_hex( $bytes ), "\t## $cmd_desc\n" if $verbose;
	$assert->{send} = $cmd;
	writechunk( $bytes );

	while ( @expect ) {
		my $pattern = str2bytes( shift @expect ) || confess "no pattern?";
		my $coderef = shift @expect || confess "no coderef?";
		confess "not coderef" unless ref $coderef eq 'CODE';

		next if defined $dispatch->{ $pattern };

		$dispatch->{ substr($pattern,3) } = $coderef;
		warn "++ dispatch ", as_hex($pattern) ,dump( $dispatch ) if $debug;
	}

	readchunk;
}

