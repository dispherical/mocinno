#!/usr/bin/perl

use strict;
use warnings;

my $vmid  = shift or die "missing vmid\n";
my $phase = shift or die "missing phase\n";

exit 0 if $phase ne 'post-start';

my $reserved = 4;

my $online = `getconf _NPROCESSORS_ONLN`;
chomp $online;
$online =~ /^(\d+)$/ or exit 0;
my $ncpus = $1;

exit 0 if $ncpus <= $reserved;

my $cpuset = "$reserved-" . ($ncpus - 1);

my @candidates = (
    "/sys/fs/cgroup/lxc/$vmid/cpuset.cpus",
    "/sys/fs/cgroup/lxc/$vmid/ns/cpuset.cpus",
);

for my $path (@candidates) {
    next unless -w $path;
    if (open(my $fh, '>', $path)) {
        print $fh $cpuset;
        close($fh);
    } else {
        warn "cpuset-pin: failed to write $path: $!\n";
    }
}

exit 0;
