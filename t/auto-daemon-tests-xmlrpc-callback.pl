#!/usr/bin/perl

use strict;
use warnings;
use lib 't/lib';
use NGCP::Rtpengine::Test;
use NGCP::Rtpengine::AutoTest;
use XMLRPCMock qw(start_mock received_requests shutdown_mock);
use Test::More;
use IO::Socket::IP;
use Socket qw(SOCK_DGRAM pack_sockaddr_in inet_aton);
use Time::HiRes qw(sleep time);

my $MOCK_PORT = 18080;
my $MOCK_URL  = "http://127.0.0.1:$MOCK_PORT/rpc";
my $RTPE_IFACE = '203.0.113.1';

my $mock = start_mock($MOCK_PORT);
sleep 0.3;

autotest_start(qw(--config-file=none -t -1
    -i 203.0.113.1 -n 2223 -b 127.0.0.1:18080
    --timeout=6
    --silent-timeout=6
    --unidirectional-timeout=2
    --xmlrpc-format=2
    -f -L 7 -E)) or die "failed to start rtpengine";

my $tag_ctr = 0;

sub fresh_call {
    my ($enable_unidir) = @_;
    $tag_ctr++;
    my $cid = "cb-call-$tag_ctr-$$";
    my $ft  = "cb-ft-$tag_ctr-$$";
    my $tt  = "cb-tt-$tag_ctr-$$";

    my $a_port = 7400 + ($tag_ctr * 2);
    my $b_port = 7401 + ($tag_ctr * 2);

    my $sock_a = IO::Socket::IP->new(
        Type => SOCK_DGRAM, Proto => 'udp',
        LocalHost => '198.51.100.1', LocalPort => $a_port,
    ) or die "sockA bind: $!";
    my $sock_b = IO::Socket::IP->new(
        Type => SOCK_DGRAM, Proto => 'udp',
        LocalHost => '198.51.100.3', LocalPort => $b_port,
    ) or die "sockB bind: $!";

    my $offer_sdp =
        "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.1\r\nt=0 0\r\n"
      . "m=audio $a_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
    my $answer_sdp =
        "v=0\r\no=- 1 1 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";

    my $offer_req = {
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address'],
    };
    push @{$offer_req->{flags}}, 'unidirectional-timeout' if $enable_unidir;

    my $oresp = rtpe_raw_req($offer_req);
    is ref($oresp), 'HASH', "offer returned hash (cid=$cid)" or diag "resp=$oresp";
    is $oresp->{result}, 'ok', "offer result ok (cid=$cid)";
    my ($rtpe_port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $rtpe_port_a, "rtpengine A-side port allocated";

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', "answer result ok (cid=$cid)";
    my ($rtpe_port_b) = ($aresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $rtpe_port_b, "rtpengine B-side port allocated";

    return ($cid, $ft, $tt, $sock_a, $sock_b, $rtpe_port_a, $rtpe_port_b,
            $a_port, $b_port);
}

sub delete_call {
    my ($cid, $ft) = @_;
    rtpe_raw_req({
        command    => 'delete',
        'call-id'  => $cid,
        'from-tag' => $ft,
    });
}

sub rtp_pkt {
    my ($seq, $ts, $ssrc) = @_;
    return pack('CCnNN a*', 0x80, 0x00, $seq, $ts, $ssrc, "\x00" x 160);
}

# Minimal RTCP Receiver Report: V=2, P=0, RC=0, PT=201 (RR), length=1 (8 bytes),
# SSRC=0xdeadbeef. No report blocks. Enough for rtpengine to accept and bump
# the RTCP stream's last_packet_us timestamp.
sub rtcp_rr {
    return pack('CCnN', 0x80, 201, 1, 0xdeadbeef);
}

# --- Subtest 1: mock harness sanity ---
subtest 'mock harness captures a manual POST' => sub {
    received_requests($mock);  # drain
    my $s = IO::Socket::IP->new(PeerAddr => "127.0.0.1:$MOCK_PORT", Proto => 'tcp')
        or die "connect mock: $!";
    my $body = 'ping';
    print $s "POST /rpc HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    my $buf = '';
    while (sysread($s, my $chunk, 4096)) { $buf .= $chunk; }
    close $s;
    sleep 0.3;
    my @got = received_requests($mock);
    is scalar @got, 1, 'mock captured one request';
    is $got[0], 'ping', 'mock captured the body';
};

# --- Subtest 2: baseline — bidirectional silence still fires callback ---
subtest 'baseline: bidirectional silence fires xmlrpc-callback' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft) = fresh_call(0);
    # neither side sends RTP; wait past --timeout=6
    sleep 8;
    my @got = received_requests($mock);
    ok scalar(@got) >= 1, "callback fired on bidirectional timeout (got " . scalar(@got) . ")";
    like(($got[0] // ''), qr/dlg\.terminate_dlg/, 'payload is Kamailio format-2 methodCall');
    like(($got[0] // ''), qr/\Q$cid\E/, 'payload contains call-id');
    delete_call($cid, $ft);
};

# --- Subtest 3: unidirectional silence fires callback when flag set ---
subtest 'unidirectional: one-way silence fires callback when flag enabled' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1);
    my $deadline = time() + 4;
    my $seq = 1000;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x1111), 0, $dest);
        $seq++;
        sleep 0.02;
    }
    sleep 0.5;
    my @got = received_requests($mock);
    ok scalar(@got) >= 1, "unidirectional callback fired within ~4s (got " . scalar(@got) . ")";
    like(($got[0] // ''), qr/\Q$cid\E/, 'payload contains call-id');
    delete_call($cid, $ft);
};

# --- Subtest 4: opt-out — one-way silence does NOT fire callback early ---
subtest 'opt-out: one-way silence does not fire callback without flag' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(0);
    my $deadline = time() + 4;
    my $seq = 2000;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x2222), 0, $dest);
        $seq++;
        sleep 0.02;
    }
    my @got = received_requests($mock);
    is scalar @got, 0, 'no callback fired within 4s when flag absent';
    delete_call($cid, $ft);
};

# --- Subtest 5: RTCP liveness — DTX/muted side with RTCP RR keeps call alive ---
# B is muted: sends no RTP. But B keeps emitting RTCP RR every second (well
# faster than the 2s --unidirectional-timeout threshold). A sends RTP
# continuously. Since B's RTP stream's rtcp_sibling is fresh, rtpengine must
# NOT consider the call unidirectionally idle, and NO xmlrpc callback should
# fire.
subtest 'unidirectional: fresh RTCP RR on silent side suppresses teardown' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b, $a_port, $b_port)
        = fresh_call(1);

    # Non-muxed: RTCP lives on port+1 on both sides.
    my $sock_b_rtcp = IO::Socket::IP->new(
        Type => SOCK_DGRAM, Proto => 'udp',
        LocalHost => '198.51.100.3', LocalPort => $b_port + 1,
    ) or die "sockB RTCP bind: $!";

    my $dest_rtp  = pack_sockaddr_in($port_a,     inet_aton($RTPE_IFACE));
    my $dest_rtcp = pack_sockaddr_in($port_b + 1, inet_aton($RTPE_IFACE));

    my $deadline      = time() + 5;  # well past 2s threshold
    my $next_rtcp     = time();
    my $rtcp_interval = 1.0;         # twice per threshold
    my $seq           = 3000;
    my $rtcp_sent     = 0;

    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x3333), 0, $dest_rtp);
        $seq++;
        if (time() >= $next_rtcp) {
            $sock_b_rtcp->send(rtcp_rr(), 0, $dest_rtcp);
            $rtcp_sent++;
            $next_rtcp = time() + $rtcp_interval;
        }
        sleep 0.02;
    }
    sleep 0.5;
    my @got = received_requests($mock);
    ok $rtcp_sent >= 4, "sent $rtcp_sent RTCP RR packets from B";
    is scalar(@got), 0,
        "no callback fired: RTCP RR proves B alive despite RTP silence (got "
        . scalar(@got) . ")";
    delete_call($cid, $ft);
    close $sock_b_rtcp;
};

shutdown_mock($mock);

done_testing();
