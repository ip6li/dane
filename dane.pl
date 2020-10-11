#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';


sub main {
    my ($host, $port, @openssl_args) = @_;

    my $cmdline = "echo | openssl s_client -servername ${host} -connect ${host}:${port} -showcerts @{openssl_args} 2>&1";
    my $cmd;
    open($cmd, "$cmdline|") || die "cannot exec $cmdline";
    my $pem;
    my $loadcert = 0;
    while (my $line = <$cmd>) {
        chomp $line;
        if ($line =~ /-----BEGIN CERTIFICATE-----/) {
            $loadcert = 1;
            $pem = "-----BEGIN CERTIFICATE-----\n";
        }
        elsif ($line =~ /-----END CERTIFICATE-----/) {
            $pem .= "-----END CERTIFICATE-----\n";
            $loadcert = 0;
            if (isCa($pem)) {
                analyze("--ca", "$pem", "$host", "$port");
            }
            else {
                analyze("", "$pem", "$host", "$port");
            }
        }
        elsif (defined $loadcert) {
            $pem .= "$line\n";
        }
    }
    close $cmd;
}

sub usage {
    die "usage: $0 <host> <port>\n";
}


sub isCa {
    my ($pem) = @_;

    my $cmdline = "echo \"$pem\" | openssl x509 -noout -text";
    my $cmd;
    open($cmd, "$cmdline|") || die "cannot exec $cmdline";
    while (my $line = <$cmd>) {
        chomp $line;
        if ($line =~ /CA:FALSE/) {
            return 0;
        }
        elsif ($line =~ /CA:TRUE/) {
            return 1;
        }
    }
    close $cmd;
}


sub analyze {
    my ($ca, $pem, $host, $port) = @_;
    my $cmdline = "echo \"$pem\" | openssl x509 -pubkey -noout";
    my $cmd;
    open($cmd, "$cmdline|") || die "cannot exec $cmdline";
    my $pubkeyFile = "/tmp/pubkey.pem.$$";
    open OUT, ">$pubkeyFile" || die "cannot open $pubkeyFile for write\n";
    while (my $line = <$cmd>) {
        chomp $line;
        print OUT "$line\n";
    }
    close OUT;
    close $cmd;

    $cmdline = "danetool --tlsa-rr $ca --host=${host} --port ${port} --proto=tcp --load-pubkey=${pubkeyFile}";
    open($cmd, "$cmdline|") || die "cannot exec $cmdline";
    while (my $line = <$cmd>) {
        chomp $line;
        print "$line\n";
    }
    close $cmd;
    unlink "$pubkeyFile";
}


my $host = shift;
my $port = shift;
my @openssl_args = @ARGV;

if (!defined($host) || !defined($port)) {
    usage();
}

main($host, $port, @openssl_args);
