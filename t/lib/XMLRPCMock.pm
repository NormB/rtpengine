package XMLRPCMock;

use strict;
use warnings;
use HTTP::Daemon;
use HTTP::Status;
use IO::Socket::INET;
use POSIX qw(:sys_wait_h);
use Exporter qw(import);

our @EXPORT_OK = qw(start_mock received_requests shutdown_mock);

sub start_mock {
    my ($port) = @_;
    pipe(my $rd, my $wr) or die "pipe: $!";
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        close $rd;
        my $d = HTTP::Daemon->new(
            LocalAddr => '127.0.0.1',
            LocalPort => $port,
            ReuseAddr => 1,
        ) or die "HTTP::Daemon on $port: $!";
        $wr->autoflush(1);
        while (my $c = $d->accept) {
            while (my $r = $c->get_request) {
                my $body = $r->content // '';
                my $len  = length($body);
                print $wr pack('N', $len), $body;
                my $resp = HTTP::Response->new(200, 'OK');
                $resp->content(
                    "<?xml version=\"1.0\"?><methodResponse><params><param>"
                  . "<value><int>1</int></value></param></params></methodResponse>"
                );
                $c->send_response($resp);
            }
            $c->close;
        }
        exit 0;
    }
    close $wr;
    return { pid => $pid, rd => $rd, port => $port };
}

sub received_requests {
    my ($h) = @_;
    my $rd = $h->{rd};
    $rd->blocking(0);
    my @out;
    while (1) {
        my $hdr;
        my $n = sysread($rd, $hdr, 4);
        last unless defined $n && $n == 4;
        my $len  = unpack('N', $hdr);
        my $body = '';
        while (length($body) < $len) {
            my $chunk;
            my $got = sysread($rd, $chunk, $len - length($body));
            last unless defined $got && $got > 0;
            $body .= $chunk;
        }
        push @out, $body;
    }
    return @out;
}

sub shutdown_mock {
    my ($h) = @_;
    kill 'TERM', $h->{pid};
    waitpid($h->{pid}, 0);
    close $h->{rd};
}

1;
