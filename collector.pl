#!/usr/bin/perl -w

# This is a Cisco NetFlow datagram collector

# Netflow protocol reference:
# http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm

use strict;
use warnings;
use IO;
use Socket;
use Carp;
use POSIX qw(strftime);
use Getopt::Long;

############################################################################

sub timestamp()
{
	return strftime "%02Y/%02m/%02d-%02H:%02M:%02S", localtime;
}

sub do_listen($)
{
	my $port = shift
		or confess "No UDP port specified";
        my $socket = IO::Socket::INET -> new (
	    Proto => 'udp', LocalPort => $port)
		or croak "Couldn't open UDP socket: $!";

	return $socket;
}

sub process_nf_v1($)
{
	my $pkt = shift;
	my %header;
	my %flow;
	
	%header = qw();

	($header{ver}, $header{flows}, $header{uptime}, $header{secs}, 
	 $header{nsecs}) = unpack("nnNNNNCC", $pkt);

	if (length($pkt) < (16 + (48 * $header{flows}))) {
		printf STDERR timestamp()." Short Netflow v.1 packet: %d < %d\n",
		    length($pkt), 16 + (48 * $header{flows});
		return;
	}

	printf timestamp() . " HEADER v.%u (%u flow%s)\n", $header{ver},
	    $header{flows}, $header{flows} == 1 ? "" : "s";

	for(my $i = 0; $i < $header{flows}; $i++) {
		my $off = 16 + (48 * $i);
		my $ptr = substr($pkt, $off, 52);

		%flow = qw();

		(my $src1, my $src2, my $src3, my $src4,
		 my $dst1, my $dst2, my $dst3, my $dst4, 
		 my $nxt1, my $nxt2, my $nxt3, my $nxt4, 
		 $flow{in_ndx}, $flow{out_ndx}, $flow{pkts}, $flow{bytes}, 
		 $flow{start}, $flow{finish}, $flow{src_port}, $flow{dst_port}, 
		 my $pad1, $flow{protocol}, $flow{tos}, $flow{tcp_flags}) =
		    unpack("CCCCCCCCCCCCnnNNNNnnnCCC", $ptr);

		$flow{src} = sprintf "%u.%u.%u.%u", $src1, $src2, $src3, $src4;
		$flow{dst} = sprintf "%u.%u.%u.%u", $dst1, $dst2, $dst3, $dst4;
		$flow{nxt} = sprintf "%u.%u.%u.%u", $nxt1, $nxt2, $nxt3, $nxt4;

		printf timestamp() .
		    "     %16s:%6u %16s:%6u %3u %10u %10u\n",
		    $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port}, 
		    $flow{protocol}, $flow{pkts}, $flow{bytes};
	}
}

sub process_nf_v5($)
{
	my $pkt = shift;
	my %header;
	my %flow;
	
	%header = qw();

	($header{ver}, $header{flows}, $header{uptime}, $header{secs}, 
	 $header{nsecs}, $header{seq}, $header{engine_type}, 
	 $header{engine_id}) = unpack("nnNNNNCC", $pkt);

	if (length($pkt) < (24 + (48 * $header{flows}))) {
		printf STDERR timestamp()." Short Netflow v.5 packet: %d < %d\n",
		    length($pkt), 24 + (48 * $header{flows});
		return;
	}

	printf timestamp() . " HEADER v.%u (%u flow%s)\n", $header{ver},
	    $header{flows}, $header{flows} == 1 ? "" : "s";

	for(my $i = 0; $i < $header{flows}; $i++) {
		my $off = 24 + (48 * $i);
		my $ptr = substr($pkt, $off, 52);

		%flow = qw();

		(my $src1, my $src2, my $src3, my $src4,
		 my $dst1, my $dst2, my $dst3, my $dst4, 
		 my $nxt1, my $nxt2, my $nxt3, my $nxt4, 
		 $flow{in_ndx}, $flow{out_ndx}, $flow{pkts}, $flow{bytes}, 
		 $flow{start}, $flow{finish}, $flow{src_port}, $flow{dst_port}, 
		 my $pad1, $flow{tcp_flags}, $flow{protocol}, $flow{tos}, 
		 $flow{src_as}, $flow{dst_as}, $flow{src_mask}, 
		 $flow{dst_mask}) = unpack("CCCCCCCCCCCCnnNNNNnnCCCCnnCC", $ptr);

		$flow{src} = sprintf "%u.%u.%u.%u", $src1, $src2, $src3, $src4;
		$flow{dst} = sprintf "%u.%u.%u.%u", $dst1, $dst2, $dst3, $dst4;
		$flow{nxt} = sprintf "%u.%u.%u.%u", $nxt1, $nxt2, $nxt3, $nxt4;

		printf timestamp() .
		    "     %16s:%6u %16s:%6u %3u %10u %10u\n",
		    $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port}, 
		    $flow{protocol}, $flow{pkts}, $flow{bytes};
	}
}

sub process_nf_v7($)
{
	my $pkt = shift;
	my %header;
	my %flow;
	
	%header = qw();

	($header{ver}, $header{flows}, $header{uptime}, $header{secs}, 
	 $header{nsecs}, $header{seq}) = unpack("nnNNNNCC", $pkt);

	if (length($pkt) < (24 + (52 * $header{flows}))) {
		printf STDERR timestamp()." Short Netflow v.7 packet: %d < %d\n",
		    length($pkt), 24 + (52 * $header{flows});
		return;
	}

	printf timestamp() . " HEADER v.%u (%u flow%s)\n", $header{ver},
	    $header{flows}, $header{flows} == 1 ? "" : "s";

	for(my $i = 0; $i < $header{flows}; $i++) {
		my $off = 24 + (52 * $i);
		my $ptr = substr($pkt, $off, 52);

		%flow = qw();

		(my $src1, my $src2, my $src3, my $src4,
		 my $dst1, my $dst2, my $dst3, my $dst4, 
		 my $nxt1, my $nxt2, my $nxt3, my $nxt4, 
		 $flow{in_ndx}, $flow{out_ndx}, $flow{pkts}, $flow{bytes}, 
		 $flow{start}, $flow{finish}, $flow{src_port}, $flow{dst_port}, 
		 $flow{flags1}, $flow{tcp_flags}, $flow{protocol}, 
		 $flow{tos}, $flow{src_as}, $flow{dst_as}, $flow{src_mask}, 
		 $flow{dst_mask}, $flow{flags2}, $flow{bypassed}) =
		     unpack("CCCCCCCCCCCCnnNNNNnnCCCCnnCCnN", $ptr);

		$flow{src} = sprintf "%u.%u.%u.%u", $src1, $src2, $src3, $src4;
		$flow{dst} = sprintf "%u.%u.%u.%u", $dst1, $dst2, $dst3, $dst4;
		$flow{nxt} = sprintf "%u.%u.%u.%u", $nxt1, $nxt2, $nxt3, $nxt4;

		printf timestamp() .
		    "     %16s:%6u %16s:%6u %3u %10u %10u\n",
		    $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port}, 
		    $flow{protocol}, $flow{pkts}, $flow{bytes};
	}
}

############################################################################

# Commandline options
my $debug = 0;
my $port;
#		Long option		Short option
GetOptions(	'debug+' => \$debug,	'd+' => \$debug,
		'port=i' => \$port,	'p=i' => \$port);

# Unbuffer output
$| = 1;

die "You must specify a port (collector.pl -p XXX).\n" unless $port;

# Main loop - receive and process a packet
for (;;) {
	my $socket;
	my $from;
	my $payload;
	my $ver;
	my $failcount = 0;
	my $netflow;

	# Open the listening port if we haven't already
	$socket = do_listen($port) unless defined $socket;

	# Fetch a packet
	$from = $socket->recv($payload, 8192, 0);
	
	# Reopen listening socket on error
	if (!defined $from) {
		$socket->close;
		undef $socket;

		$failcount++;
		die "Couldn't recv: $!\n" if ($failcount > 5);
		next; # Socket will be reopened at start of loop
	}
	
	if (length($payload) < 16) {
		printf STDERR timestamp()." Short packet recevied: %d < 16\n",
		    length($payload);
		next;
	}

	# The version is always the first 16 bits of the packet
	($ver) = unpack("n", $payload);

	if	($ver == 1)	{ process_nf_v1($payload); }
	elsif	($ver == 5)	{ process_nf_v5($payload); }
	elsif	($ver == 7)	{ process_nf_v7($payload); }
	else {
		printf STDERR timestamp()." Unsupported netflow version %d\n",
		    $ver;
		next;
	}
	
	undef $payload;
	next;	
}

exit 0;