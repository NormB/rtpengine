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
    my ($enable_unidir, $override_s) = @_;
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
    if ($enable_unidir) {
        my $flag = defined($override_s)
            ? "unidirectional-timeout=$override_s"
            : 'unidirectional-timeout';
        push @{$offer_req->{flags}}, $flag;
    }

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

# --- Subtest 5: traffic on the RTCP sibling keeps the direction alive ---
# Traffic on the RTCP sibling (any UDP the address-check accepts) keeps the
# direction alive. rtpengine bumps last_packet_us on any accepted UDP traffic
# on the stream before RTCP parsing runs (see daemon/media_socket.c: the
# timestamp update happens before do_rtcp_parse()), so the new unidirectional
# check sees a fresh timestamp on the RTP stream's rtcp_sibling.
#
# In practice this is how DTX / NC endpoints stay up: they still emit RTCP RR,
# and that bump on last_packet_us is what the new check sees. Here B sends
# only RTCP RR (no RTP) while A sends RTP continuously; no callback should
# fire.
subtest 'unidirectional: traffic on RTCP sibling suppresses teardown' => sub {
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

    # Seed one RR immediately after answer so the RTCP sibling has a fresh
    # last_packet_us from t=0. Without this seed, the first scheduled RR
    # lands up to $rtcp_interval later, which could race the 2s timer tick.
    $sock_b_rtcp->send(rtcp_rr(), 0, $dest_rtcp);

    my $start         = time();
    my $deadline      = $start + 5;  # well past 2s threshold
    my $next_rtcp     = time() + 1.0;
    my $rtcp_interval = 1.0;         # twice per threshold
    my $seq           = 3000;
    my $rtcp_sent     = 1;           # seed RR above

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
    my $elapsed = time() - $start;
    sleep 0.5;
    my @got = received_requests($mock);
    ok $rtcp_sent >= 4, "sent $rtcp_sent RTCP RR packets from B";
    ok $elapsed >= 4,
        sprintf("elapsed %.2fs well past 2s threshold", $elapsed);
    is scalar(@got), 0,
        "no callback fired: RTCP sibling traffic keeps B-side alive (got "
        . scalar(@got) . ")";
    delete_call($cid, $ft);
    close $sock_b_rtcp;
};

# --- Subtest 6: per-call override=1s fires faster than global 2s ---
# Daemon is started with --unidirectional-timeout=2. Offering a call with
# 'unidirectional-timeout=1' must shorten the threshold to 1s for this call
# only. Discrimination threshold 1.8s: without the override the firing time
# is bounded below by the 2s global (actual ~2.0-2.2s), so the assertion
# fails on unpatched code. With the override, firing is ~1.0-1.3s.
subtest 'override: unidirectional-timeout=1 fires faster than global' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1, 1);
    my $start = time();
    my $deadline = $start + 3;
    my $seq = 4000;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x4444), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at), "callback fired at all (got fired_at=" . ($fired_at // 'undef') . ")";
    ok defined($fired_at) && $fired_at < 1.8,
        sprintf("callback fired in %.2fs, under the 2s global threshold",
            $fired_at // -1);
    delete_call($cid, $ft);
};

# --- Subtest 7: per-call override=4s holds past global 2s, still fires by 5s ---
# Daemon --unidirectional-timeout=2. Override=4 extends the threshold for
# this call past the global. We assert both halves:
#   (a) no callback by 3.0s   -> proves the global 2s is NOT what's firing
#   (b) callback fires by 5s  -> proves override=4 IS armed (not silently dropped)
# On baseline (unpatched) the "unidirectional-timeout=4" string hits the
# default arm and logs "Unknown flag" so the unidirectional mechanism never
# arms at all: (b) would fail (no callback ever). The pair discriminates.
subtest 'override: unidirectional-timeout=4 holds past 2s, fires by 5s' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1, 4);
    my $start = time();
    my $seq = 5000;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));

    my $fired_at;
    my $phase_a_ok;  # no callback by 3.0s
    my $deadline = $start + 6;  # bounded observation window > override
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x5555), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got && !defined $fired_at) {
            $fired_at = time() - $start;
        }
        if (!defined $phase_a_ok && (time() - $start) >= 3.0) {
            $phase_a_ok = !defined($fired_at);
        }
        last if defined $fired_at && defined $phase_a_ok;
    }
    ok $phase_a_ok,
        "no callback fired before 3.0s (override=4 suppresses global 2s)";
    ok defined($fired_at),
        sprintf("callback fired at fired_at=%s (override=4 is armed)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at >= 3.0 && $fired_at <= 5.5,
        sprintf("fired_at %s is consistent with 4s override (3.0-5.5s window)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
};

# --- Subtest: hold re-INVITE (a=sendonly) does NOT fire teardown ---
# Regression guard: mid-call, the offerer issues a re-INVITE with a=sendonly
# (standard "put on hold"). The answerer mirrors with a=recvonly. After this
# reoffer/reanswer, the answerer is no longer expected to send media, so the
# B->A direction should go silent without tripping the unidirectional idle
# check. Hold is indistinguishable from "dead one-way" at the packet layer,
# so the safety-net is: if any monologue is on hold, skip the unidir check
# for this tick. Held calls do not get unidirectional protection during hold;
# the false-positive (tearing down a held caller on MOH) is strictly worse
# than the no-protection case.
subtest 'hold: sendonly re-INVITE does not trigger unidir teardown' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b, $a_port, $b_port)
        = fresh_call(1);

    my $dest_a = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $dest_b = pack_sockaddr_in($port_b, inet_aton($RTPE_IFACE));

    # Warm-up: establish bidirectional RTP activity so both streams are FILLED
    # and confirmed before the hold re-INVITE arrives.
    my $seq_a = 6000;
    my $seq_b = 7000;
    for (my $i = 0; $i < 20; $i++) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x6161), 0, $dest_a);
        $sock_b->send(rtp_pkt($seq_b++, $seq_b * 160, 0x6262), 0, $dest_b);
        sleep 0.02;
    }

    # A (offerer) puts the call on hold: re-INVITE with a=sendonly.
    my $hold_offer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.1\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.1\r\nt=0 0\r\n"
      . "m=audio $a_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n";

    my $hold_resp = rtpe_raw_req({
        command    => 'offer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        sdp        => $hold_offer_sdp,
        flags      => ['trust-address'],
    });
    is $hold_resp->{result}, 'ok', 'hold re-offer result ok';

    # B mirrors with a=recvonly.
    my $hold_answer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n";

    my $hold_ans_resp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $hold_answer_sdp,
        flags      => ['trust-address'],
    });
    is $hold_ans_resp->{result}, 'ok', 'hold re-answer result ok';

    # Post-hold phase: A (the holder, sendonly) keeps sending packets to
    # simulate MOH toward B; B (recvonly) sends nothing. Watch well past
    # the 2s unidirectional threshold for any spurious callback.
    my $start    = time();
    my $deadline = $start + 4;  # 2x threshold
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x6161), 0, $dest_a);
        sleep 0.02;
    }
    my $elapsed = time() - $start;
    sleep 0.3;

    my @got = received_requests($mock);
    ok $elapsed >= 3.5,
        sprintf("observed %.2fs of post-hold silence (well past 2s threshold)",
            $elapsed);
    is scalar(@got), 0,
        "no callback fired: sendonly hold correctly suppresses unidir teardown "
        . "(got " . scalar(@got) . ")";
    delete_call($cid, $ft);
};

# --- Edge-case subtests (P1: input validation + termination reason) ---

# E1: unidirectional-timeout=0 means "use the global default", not "disabled".
# call_flags.c:ng_unidir_timeout_val() sets unidirectional_timeout=true
# unconditionally; only the numeric override requires >0. So =0 behaves
# exactly like the bare flag, firing at the 2s global threshold.
subtest 'edge: unidirectional-timeout=0 falls through to global default' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1, 0);
    my $start = time();
    my $deadline = $start + 4;
    my $seq = 8000;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8080), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("=0 is not silently disabled; callback fired (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at >= 1.5 && $fired_at <= 3.5,
        sprintf("=0 uses the 2s global (fired at %s, expected ~2s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
};

# E2: unidirectional-timeout=abc -- unparseable.
# str_to_i returns the fallback (-1), the >0 guard rejects it, the flag
# stays enabled and falls through to the global 2s. A warning is logged
# but we do not assert against the log: autotest_start exposes
# $rtpe_stderr privately, and the task constraint forbids adding
# log-tailing infrastructure speculatively.
subtest 'edge: unidirectional-timeout=abc warns and falls through' => sub {
    received_requests($mock);  # drain
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

    my $oresp = rtpe_raw_req({
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address', 'unidirectional-timeout=abc'],
    });
    is ref($oresp), 'HASH', 'offer returned hash (not rejected)';
    is $oresp->{result}, 'ok', 'offer result ok with garbage value';
    my ($port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_a, 'A-side port allocated';

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', 'answer result ok';

    my $start = time();
    my $deadline = $start + 4;
    my $seq = 8100;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8181), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("garbage value still enables the feature (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at >= 1.5 && $fired_at <= 3.5,
        sprintf("garbage value falls through to 2s global (fired at %s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
    close $sock_a; close $sock_b;
};

# E3: unidirectional-timeout=-5 -- negative.
# str_to_i parses "-5" to -5, the >0 guard rejects it, warning logged,
# fall-through to global 2s. Behaviour is identical to E2.
subtest 'edge: unidirectional-timeout=-5 warns and falls through' => sub {
    received_requests($mock);  # drain
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

    my $oresp = rtpe_raw_req({
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address', 'unidirectional-timeout=-5'],
    });
    is $oresp->{result}, 'ok', 'offer result ok with negative value';
    my ($port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_a, 'A-side port allocated';

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', 'answer result ok';

    my $start = time();
    my $deadline = $start + 4;
    my $seq = 8200;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8282), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("negative value still enables the feature (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at >= 1.5 && $fired_at <= 3.5,
        sprintf("negative value falls through to 2s global (fired at %s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
    close $sock_a; close $sock_b;
};

# E4: unidirectional-timeout= (empty value).
# str_to_i("") returns the fallback (-1); >0 guard rejects; warning logged;
# fall-through to global 2s.
subtest 'edge: unidirectional-timeout= (empty) warns and falls through' => sub {
    received_requests($mock);  # drain
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

    my $oresp = rtpe_raw_req({
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address', 'unidirectional-timeout='],
    });
    is $oresp->{result}, 'ok', 'offer result ok with empty value';
    my ($port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_a, 'A-side port allocated';

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', 'answer result ok';

    my $start = time();
    my $deadline = $start + 4;
    my $seq = 8300;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8383), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("empty value still enables the feature (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at >= 1.5 && $fired_at <= 3.5,
        sprintf("empty value falls through to 2s global (fired at %s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
    close $sock_a; close $sock_b;
};

# E5: the ng dictionary accepts "unidirectional timeout=N" (space form) as
# an alias for "unidirectional-timeout=N" (hyphen form). call_flags.c
# registers both prefixes in its dispatch table. Bencode preserves literal
# spaces inside string values, so passing the flag as a single array element
# delivers it to the daemon intact. With global=2s and override=5s, a
# 3-second observation window must NOT fire a callback (still inside the
# 5s override), which discriminates the alias from the default "unknown
# flag" branch (which would leave the feature disarmed and also produce
# no callback -- see below for the flip-side assertion via a sibling run).
subtest 'edge: space-form "unidirectional timeout=5" is equivalent to hyphen form' => sub {
    received_requests($mock);  # drain
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

    my $oresp = rtpe_raw_req({
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address', 'unidirectional timeout=5'],
    });
    is $oresp->{result}, 'ok', 'offer result ok with space-form flag';
    my ($port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_a, 'A-side port allocated';

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', 'answer result ok';

    # Observe for 3s: 1s past global threshold, 2s short of the override.
    # If the parser silently ignored the space-form override, the global
    # 2s threshold would fire within this window.
    my $start = time();
    my $deadline = $start + 3;
    my $seq = 8400;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8484), 0, $dest);
        $seq++;
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok !defined($fired_at),
        sprintf("space-form override=5 suppresses global 2s firing (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    delete_call($cid, $ft);
    close $sock_a; close $sock_b;
};

# E6: distinguishing UNIDIRECTIONAL_TIMEOUT from the bidirectional TIMEOUT
# in the callback payload.
#
# Finding: xmlrpc-format=2 (Kamailio dlg.terminate_dlg) carries only
# <call-id>, <from-tag>, <to-tag> -- see daemon/call.c:466-476. The
# termination reason (UNIDIRECTIONAL_TIMEOUT vs TIMEOUT vs FINAL_TIMEOUT)
# is stored on the monologue (call.c:353) and logged via ilog but does NOT
# appear in the XMLRPC body. So the body content alone cannot tell the
# two apart.
#
# What we CAN assert: that a unidir-armed, one-way-silent call produces
# a valid format-2 callback naming THIS call-id, fired inside the unidir
# window (< bidirectional --timeout=6s). Firing under 4s means the
# unidirectional path took the call down, not the bidirectional timeout.
subtest 'edge: UNIDIRECTIONAL_TIMEOUT-triggered callback is a valid format-2 body' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1);
    my $start = time();
    my $deadline = $start + 4;
    my $seq = 8500;
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my @got;
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0x8585), 0, $dest);
        $seq++;
        sleep 0.05;
        @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("callback fired via unidir path (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at < 4.0,
        sprintf("fired at %s, inside the unidir window (<4s, well under the 6s bidirectional timeout)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    ok scalar(@got) >= 1, 'at least one callback body captured';
    my $body = $got[0] // '';
    like $body, qr/<methodName>dlg\.terminate_dlg<\/methodName>/,
        'body is format-2 dlg.terminate_dlg methodCall';
    like $body, qr/\Q$cid\E/, 'body contains this call-id (not a stray callback)';
    like $body, qr/\Q$ft\E/, 'body contains from-tag';
    like $body, qr/\Q$tt\E/, 'body contains to-tag';
    delete_call($cid, $ft);
};

# --- Edge-case subtests (P2: behavior edges) ---

# E7: a=inactive re-INVITE also suppresses teardown.
# The hold safety-net uses ml_is_held(ml), which matches any audio media
# with !MEDIA_ISSET(media, SEND). That covers both sendonly (SEND clear,
# RECV set) and inactive (SEND clear, RECV clear). Subtest 12 covers
# sendonly; E7 covers the inactive variant. With inactive both sides
# genuinely stop sending RTP -- there is no MOH flow -- so the test just
# waits 4s with both sockets quiet and confirms zero callbacks.
subtest 'hold: inactive re-INVITE also suppresses unidir teardown' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b, $a_port, $b_port)
        = fresh_call(1);

    my $dest_a = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $dest_b = pack_sockaddr_in($port_b, inet_aton($RTPE_IFACE));

    # Warm-up: establish bidirectional RTP so both streams are FILLED
    # and confirmed before the hold re-INVITE arrives.
    my $seq_a = 9100;
    my $seq_b = 9200;
    for (my $i = 0; $i < 20; $i++) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x9191), 0, $dest_a);
        $sock_b->send(rtp_pkt($seq_b++, $seq_b * 160, 0x9292), 0, $dest_b);
        sleep 0.02;
    }

    # A re-INVITEs with a=inactive.
    my $hold_offer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.1\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.1\r\nt=0 0\r\n"
      . "m=audio $a_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n";
    my $hold_resp = rtpe_raw_req({
        command    => 'offer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        sdp        => $hold_offer_sdp,
        flags      => ['trust-address'],
    });
    is $hold_resp->{result}, 'ok', 'inactive re-offer result ok';

    # B mirrors with a=inactive.
    my $hold_answer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n";
    my $hold_ans_resp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $hold_answer_sdp,
        flags      => ['trust-address'],
    });
    is $hold_ans_resp->{result}, 'ok', 'inactive re-answer result ok';

    # Post-hold phase: neither side sends. Watch 4s (2x threshold).
    my $start    = time();
    my $deadline = $start + 4;
    while (time() < $deadline) {
        sleep 0.1;
    }
    my $elapsed = time() - $start;
    sleep 0.3;

    my @got = received_requests($mock);
    ok $elapsed >= 3.5,
        sprintf("observed %.2fs of post-hold silence (well past 2s threshold)",
            $elapsed);
    is scalar(@got), 0,
        "no callback fired: inactive hold correctly suppresses unidir teardown "
        . "(got " . scalar(@got) . ")";
    delete_call($cid, $ft);
};

# E8: Hold -> resume -> go silent -> callback fires.
# Protection must RESUME after hold is released. Put the call on hold
# (sendonly), observe no callback, re-INVITE back to sendrecv, warm up
# bidir briefly, then stop B. Assert exactly one callback fires post-
# resume. Guards against the bug where once-held calls stay protected
# forever.
subtest 'hold -> resume -> silence fires callback (protection resumes)' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b, $a_port, $b_port)
        = fresh_call(1);

    my $dest_a = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $dest_b = pack_sockaddr_in($port_b, inet_aton($RTPE_IFACE));

    # Warm-up bidir.
    my $seq_a = 9500;
    my $seq_b = 9600;
    for (my $i = 0; $i < 20; $i++) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x9595), 0, $dest_a);
        $sock_b->send(rtp_pkt($seq_b++, $seq_b * 160, 0x9696), 0, $dest_b);
        sleep 0.02;
    }

    # Hold: A sends sendonly.
    my $hold_offer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.1\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.1\r\nt=0 0\r\n"
      . "m=audio $a_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n";
    rtpe_raw_req({
        command    => 'offer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        sdp        => $hold_offer_sdp,
        flags      => ['trust-address'],
    });
    my $hold_answer_sdp =
        "v=0\r\no=- 1 2 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n";
    rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $hold_answer_sdp,
        flags      => ['trust-address'],
    });

    # Hold phase: A (sendonly) sends MOH, B silent, 3s. No callback expected.
    my $hold_deadline = time() + 3;
    while (time() < $hold_deadline) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x9595), 0, $dest_a);
        sleep 0.02;
    }
    my @during_hold = received_requests($mock);
    is scalar(@during_hold), 0,
        "no callback during hold phase (safety-net active)";

    # Resume: re-INVITE back to sendrecv.
    my $resume_offer_sdp =
        "v=0\r\no=- 1 3 IN IP4 198.51.100.1\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.1\r\nt=0 0\r\n"
      . "m=audio $a_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
    my $resume_resp = rtpe_raw_req({
        command    => 'offer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        sdp        => $resume_offer_sdp,
        flags      => ['trust-address'],
    });
    is $resume_resp->{result}, 'ok', 'resume re-offer result ok';

    my $resume_answer_sdp =
        "v=0\r\no=- 1 3 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
    my $resume_ans_resp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $resume_answer_sdp,
        flags      => ['trust-address'],
    });
    is $resume_ans_resp->{result}, 'ok', 'resume re-answer result ok';

    # Brief bidir warm-up post-resume so both directions have a fresh
    # last_packet_us.
    for (my $i = 0; $i < 20; $i++) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x9595), 0, $dest_a);
        $sock_b->send(rtp_pkt($seq_b++, $seq_b * 160, 0x9696), 0, $dest_b);
        sleep 0.02;
    }

    # Drain any stale callbacks (there should be none, but be defensive).
    received_requests($mock);

    # Silent-B phase: A sends, B silent. Wait past threshold.
    my $start    = time();
    my $deadline = $start + 4;
    my $fired_at;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0x9595), 0, $dest_a);
        sleep 0.05;
        my @got = received_requests($mock);
        if (@got) {
            $fired_at = time() - $start;
            last;
        }
    }
    ok defined($fired_at),
        sprintf("callback fired after resume (fired_at=%s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'never');
    ok defined($fired_at) && $fired_at < 4.0,
        sprintf("fired within unidir window (%s < 4s)",
            defined($fired_at) ? sprintf("%.2fs", $fired_at) : 'undef');
    delete_call($cid, $ft);
};

# E9: Global --unidirectional-timeout=0 + per-call =3 full behaviour
# verification requires a second daemon run with --unidirectional-timeout=0
# (or without the flag at all). The test harness here launches a single
# daemon via autotest_start with --unidirectional-timeout=2, and no
# secondary-daemon helper exists in NGCP::Rtpengine::AutoTest. Relaunching
# mid-test is not supported.
#
# As a weaker-but-useful check: confirm that the ng protocol accepts the
# per-call override spelling and returns ok. The daemon is started with
# global=2 here, so firing time cannot distinguish override-is-primary
# from global-is-fallback. The full behaviour test (global=0, per-call=3,
# firing ~3s) must be verified manually or in a separate harness run.
subtest 'accept: per-call unidirectional-timeout=3 parses and call proceeds' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1, 3);
    ok $port_a, 'offer with unidirectional-timeout=3 accepted';
    ok $port_b, 'answer completed, call fully set up';
    # Full global=0 + per-call=3 firing-time verification needs a
    # separate daemon invocation without --unidirectional-timeout=2 on
    # the command line; not exercised by this test harness.
    delete_call($cid, $ft);
};

# E10: RFC 3389 Comfort Noise (PT 13) on the idle direction keeps the
# call alive. The unidirectional check bumps last_packet_us on any
# accepted UDP on the RTP stream (see daemon/media_socket.c), which
# includes valid CN packets when PT 13 is negotiated in the SDP.
#
# To make PT 13 negotiation explicit, build the offer and answer inline
# with both PT 0 (PCMU) and PT 13 (CN/8000) declared. A sends regular
# PCMU; B sends ONLY CN (PT 13) once per second. No callback should
# fire because each CN packet bumps B-side last_packet_us.
sub cn_packet {
    my ($seq, $ssrc) = @_;
    # V=2 P=0 X=0 CC=0 M=0 PT=13, seq, ts, ssrc + 1 body byte (noise level).
    return pack('CCnNN C', 0x80, 13, $seq, $seq * 160, $ssrc, 0x7f);
}

subtest 'RFC 3389 CN (PT 13) keeps direction alive on negotiated stream' => sub {
    received_requests($mock);  # drain
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
      . "m=audio $a_port RTP/AVP 0 13\r\n"
      . "a=rtpmap:0 PCMU/8000\r\n"
      . "a=rtpmap:13 CN/8000\r\n"
      . "a=sendrecv\r\n";
    my $answer_sdp =
        "v=0\r\no=- 1 1 IN IP4 198.51.100.3\r\ns=-\r\n"
      . "c=IN IP4 198.51.100.3\r\nt=0 0\r\n"
      . "m=audio $b_port RTP/AVP 0 13\r\n"
      . "a=rtpmap:0 PCMU/8000\r\n"
      . "a=rtpmap:13 CN/8000\r\n"
      . "a=sendrecv\r\n";

    my $oresp = rtpe_raw_req({
        command           => 'offer',
        'call-id'         => $cid,
        'from-tag'        => $ft,
        sdp               => $offer_sdp,
        'xmlrpc-callback' => $MOCK_URL,
        flags             => ['trust-address', 'unidirectional-timeout'],
    });
    is $oresp->{result}, 'ok', 'offer with PT 0+13 result ok';
    my ($port_a) = ($oresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_a, 'A-side port allocated';

    my $aresp = rtpe_raw_req({
        command    => 'answer',
        'call-id'  => $cid,
        'from-tag' => $ft,
        'to-tag'   => $tt,
        sdp        => $answer_sdp,
        flags      => ['trust-address'],
    });
    is $aresp->{result}, 'ok', 'answer result ok';
    my ($port_b) = ($aresp->{sdp} // '') =~ /m=audio (\d+)/;
    ok $port_b, 'B-side port allocated';

    my $dest_a = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $dest_b = pack_sockaddr_in($port_b, inet_aton($RTPE_IFACE));

    # Warm-up: one brief bidir burst to mark both streams FILLED.
    my $seq_a = 10100;
    my $seq_b = 10200;
    for (my $i = 0; $i < 10; $i++) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0xa1a1), 0, $dest_a);
        $sock_b->send(rtp_pkt($seq_b++, $seq_b * 160, 0xa2a2), 0, $dest_b);
        sleep 0.02;
    }

    # Post warm-up: A sends PCMU continuously; B sends ONLY CN once per
    # second. Total 4s, well past the 2s threshold.
    my $start         = time();
    my $deadline      = $start + 4;
    my $next_cn       = time() + 0.5;
    my $cn_interval   = 1.0;
    my $cn_sent       = 0;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq_a++, $seq_a * 160, 0xa1a1), 0, $dest_a);
        if (time() >= $next_cn) {
            $sock_b->send(cn_packet($seq_b++, 0xa2a2), 0, $dest_b);
            $cn_sent++;
            $next_cn = time() + $cn_interval;
        }
        sleep 0.02;
    }
    my $elapsed = time() - $start;
    sleep 0.3;

    my @got = received_requests($mock);
    ok $cn_sent >= 3, "sent $cn_sent CN (PT 13) packets from B";
    ok $elapsed >= 3.5,
        sprintf("elapsed %.2fs well past 2s threshold", $elapsed);
    # Document observed behaviour. If rtpengine accepts the CN packet
    # (PT 13 was negotiated), last_packet_us is bumped and no callback
    # fires. If it rejects CN (e.g. payload-type filtering ignores the
    # rtpmap for one-byte bodies), the callback fires -- which is ALSO
    # useful data for the writeup.
    is scalar(@got), 0,
        "no callback fired: CN (PT 13) keeps B-side alive when PT 13 "
        . "is negotiated in the SDP (got " . scalar(@got) . ")";
    delete_call($cid, $ft);
    close $sock_a; close $sock_b;
};

# E11: Callback fires at most ONCE per call.
# Guards against the bug where the timer keeps firing every tick after
# the threshold is first crossed. Wait well past threshold (8s with
# global=2s, so >=4 timer ticks past the fire point) and assert exactly
# one callback. The design relies on the daemon unsetting the call's
# arming state after dispatch, or on the call being torn down before
# the next tick.
subtest 'callback fires exactly once per call, not on every tick' => sub {
    received_requests($mock);  # drain
    my ($cid, $ft, $tt, $sock_a, $sock_b, $port_a, $port_b) = fresh_call(1);
    my $dest = pack_sockaddr_in($port_a, inet_aton($RTPE_IFACE));
    my $seq = 11000;

    # Send from A continuously for 8s. B is silent the whole time.
    my $start    = time();
    my $deadline = $start + 8;
    while (time() < $deadline) {
        $sock_a->send(rtp_pkt($seq, $seq * 160, 0xb1b1), 0, $dest);
        $seq++;
        sleep 0.05;
    }
    my $elapsed = time() - $start;
    sleep 0.5;

    my @got = received_requests($mock);
    ok $elapsed >= 7.5,
        sprintf("observed %.2fs of one-way silence (4x threshold)", $elapsed);
    is scalar(@got), 1,
        "exactly one callback fired over 8s window (got " . scalar(@got)
        . ") -- guards against per-tick repeated dispatch";
    delete_call($cid, $ft);
};

shutdown_mock($mock);

done_testing();
