#!/usr/bin/perl

use strict;
use warnings;
use NGCP::Rtpengine::Test;
use NGCP::Rtpclient::SRTP;
use NGCP::Rtpengine::AutoTest;
use Test::More;
use NGCP::Rtpclient::ICE;
use POSIX;

autotest_start(qw(--config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1
			-n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 --log-level-internals=7))
		or die;

new_call;

offer('rtpp-flags: basic A to B call', { 'rtpp-flags' => 'replace-origin replace-session-connection strict-source label=caller OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('rtpp-flags: basic A to B call', { 'rtpp-flags' => 'replace-origin replace-session-connection strict-source label=callee OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

new_call;

offer('rtpp-flags: basic A to B call, remove ICE',
	{ 'rtpp-flags' => 'ICE=remove replace-origin replace-session-connection strict-source label=caller OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
a=sendrecv
a=ice-pwd:bd5e8b8d6dd8e1bc6
a=ice-ufrag:q27e93
a=candidate:1 1 UDP 2130706303 198.51.100.4 2412 typ host
a=candidate:1 2 UDP 2130706302 198.51.100.4 2413 typ host
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('rtpp-flags: basic A to B call, remove ICE',
	{ 'rtpp-flags' => 'replace-origin replace-session-connection strict-source label=callee OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.3
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.3
a=sendrecv
--------------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
a=ice-ufrag:ICEUFRAG
a=ice-pwd:ICEPWD
a=candidate:ICEBASE 1 UDP 2130706431 203.0.113.1 PORT typ host
a=candidate:ICEBASE 1 UDP 2130706175 2001:db8:4321::1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706430 203.0.113.1 PORT typ host
a=candidate:ICEBASE 2 UDP 2130706174 2001:db8:4321::1 PORT typ host
SDP

new_call;

offer('rtpp-flags: replace option, media level',
	{ 'rtpp-flags' => 'replace-zero-address replace-session-connection strict-source label=caller OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 16478 RTP/AVP 8
c=IN IP4 0.0.0.0
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio PORT RTP/AVP 8
c=IN IP4 203.0.113.1
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('rtpp-flags: replace option, session level',
	{ 'rtpp-flags' => 'replace-zero-address replace-session-connection strict-source label=caller OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 0.0.0.0
t=0 0
m=audio 16478 RTP/AVP 8
----------------------------------
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
c=IN IP4 203.0.113.1
t=0 0
m=audio PORT RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendonly
a=rtcp:PORT
SDP

new_call;

offer('rtpp-flags: codec-accept',
	{ 'rtpp-flags' => 'codec-accept=PCMU replace-origin replace-session-connection strict-source label=caller OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 0 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0 8
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
a=rtcp:PORT
SDP

answer('rtpp-flags: codec-accept',
	{ 'rtpp-flags' => 'replace-origin replace-session-connection strict-source label=callee OSRTP-accept address-family=IP4 transport-protocol=RTP/AVP' }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.101.40
s=tester
t=0 0
m=audio 3000 RTP/AVP 8
c=IN IP4 198.51.100.1
----------------------------------
v=0
o=- 1545997027 1 IN IP4 203.0.113.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

done_testing();