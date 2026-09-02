#!/usr/bin/env perl
#
# logdate
#
# Fast SAS Metadata Server log timeline utility.
#
# Author: Douglas Hunt (SAS domain expertise)
# Developed with GitHub Copilot assistance
#
use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use Time::Local qw(timegm);

our $VERSION = '2.2.18';

my $details = 1;
my $help = 0;
my $version = 0;

my $block_size = 1024 * 1024;
my $marker_bytes = 4 * 1024 * 1024;

GetOptions(
    'details|d'      => sub { $details = 1 },
    'verbose|v'      => sub { $details = 1 },
    'compact|c'      => sub { $details = 0 },
    'version|V'      => \$version,
    'help|h'         => \$help,
    'block-size=i'   => \$block_size,
    'marker-bytes=i' => \$marker_bytes,
) or usage(2);

if ($version) {
    print "logdate $VERSION\n";
    exit 0;
}

usage(0) if $help;
usage(2, 'no log files supplied') unless @ARGV;

die "logdate: --block-size must be at least 4096\n"
    if $block_size < 4096;

die "logdate: --marker-bytes must be at least 4096\n"
    if $marker_bytes < 4096;

my $TIMESTAMP_RE = qr{
    ^
    (
        \d{4}-\d{2}-\d{2}
        T
        \d{2}:\d{2}:\d{2},
        \d{3}
    )
}mx;

print "logdate $VERSION\n\n";

my %seen;
my @rows;

for my $file (grep { !$seen{$_}++ } @ARGV) {
    if (!-f $file) {
        warn "logdate: warning: not a regular file: $file\n";
        next;
    }
    push @rows, analyze_file($file);
}

usage(1, 'no readable log files supplied') unless @rows;

@rows = sort {
       ($a->{begin} // '9999') cmp ($b->{begin} // '9999')
    || ($a->{end}   // '9999') cmp ($b->{end}   // '9999')
    || $a->{file} cmp $b->{file}
} @rows;

print "=== Hostname Analysis ===\n";
for my $row (@rows) {
    print "File: $row->{file}\n";
    print "  Header Host: $row->{header_host}  ->  $row->{norm_header}\n" if $row->{header_host};
    print "  Filename Host: $row->{name_host}  ->  $row->{norm_name}\n" if $row->{name_host};
    print "  Redirect Target(s): $row->{redirect_hosts}  ->  $row->{norm_redirects}\n" if $row->{redirect_hosts};
    print "  Classification: $row->{cluster}\n\n";
}

if ($details) {
    print_details_summary(@rows);
    print_verbose(@rows);
}
else {
    print_compact(@rows);
}

exit 0;

sub usage {
    my ($status, $message) = @_;
    warn "logdate: $message\n" if defined $message;
    my $fh = $status ? *STDERR : *STDOUT;

    print $fh <<'USAGE';
logdate - Read SAS Metadata Server logs and determine start/end timing,
state markers, and whether the log appears TRACE-enabled.

Usage:
  logdate [options] LOGFILE...
  logdate -d file1.log file2.log
  logdate -c SASMeta*.log
  logdate --version
USAGE
    exit $status;
}

sub analyze_file {
    my ($file) = @_;

    my %row = (
        file           => $file,
        begin          => undef,
        end            => undef,
        duration_ms    => undef,
        trace          => 0,
        trace_count    => 0,
        debug_count    => 0,
        info_count     => 0,
        trace_ratio    => 0,
        cluster        => 'UNKNOWN',
        header_host    => '',
        name_host      => '',
        redirect_hosts => '',
        norm_header    => '',
        norm_name      => '',
        norm_redirects => '',
        startup        => 0,
        running        => 0,
        status         => 'OK',
    );

    my $size = -s $file;
    if (!defined $size) {
        $row{status} = 'STAT_ERROR';
        return \%row;
    }

    my $fh;
    if (!open($fh, '<', $file)) {
        $row{status} = "OPEN_ERROR: $!";
        return \%row;
    }
    binmode($fh);

    $row{begin} = find_begin($fh, $size);
    $row{end}   = find_end($fh, $size);

    my $sample_size = $size < $marker_bytes ? $size : $marker_bytes;

    if ($sample_size > 0 && defined sysseek($fh, 0, 0)) {
        my $sample = read_exact($fh, $sample_size);

        if ($sample =~ /Host:\s*'([^']+)'/i) {
            $row{header_host} = $1;
            $row{norm_header} = normalize_host($1);
        }

        if ($file =~ /SASMeta_MetadataServer_[0-9T-]+_([A-Z0-9]+)_/i) {
            $row{name_host} = $1;
            $row{norm_name} = lc(normalize_host($1));
        }

        my %seen_redirect;
        my @redirect_targets;
        while ($sample =~ /redirect(?:ing)?[^\n]{0,200}?\bat\s+([A-Za-z0-9._-]+)/ig) {
            my $target = $1;
            next unless length $target;
            my $norm = normalize_host($target);
            push @redirect_targets, $target unless $seen_redirect{$norm}++;
        }

        if (@redirect_targets) {
            $row{redirect_hosts} = join(', ', @redirect_targets);
            $row{norm_redirects} = join(', ', map { normalize_host($_) } @redirect_targets);
        }

        my $trace_count = () = $sample =~ /^\d{4}-.*?\bTRACE\b/mg;
        my $debug_count = () = $sample =~ /^\d{4}-.*?\bDEBUG\b/mg;
        my $info_count  = () = $sample =~ /^\d{4}-.*?\bINFO\b/mg;

        my $signal = $trace_count + $debug_count;
        my $noise  = $info_count;

        $row{trace_count} = $trace_count;
        $row{debug_count} = $debug_count;
        $row{info_count}  = $info_count;
        $row{trace_ratio} = $signal / ($noise + 1);
        $row{trace}       = ($signal > 0 && $signal > $noise) ? 1 : 0;
        $row{cluster}     = classify_cluster($sample);

        $row{startup} = ($sample =~ /\bSAH011001I\b.*?\bState,\s*starting\b/i) ? 1 : 0;
        $row{running} = ($sample =~ /\bSAH011999I\b.*?\bState,\s*running\b/i) ? 1 : 0;
    }

    close($fh);

    return \%row unless defined $row{begin} && defined $row{end};

    my $begin_ms = timestamp_ms($row{begin});
    my $end_ms   = timestamp_ms($row{end});

    if (!defined $begin_ms || !defined $end_ms) {
        $row{status} = 'BAD_TIMESTAMP';
        return \%row;
    }

    $row{duration_ms} = $end_ms - $begin_ms;
    $row{status} = 'END_BEFORE_BEGIN' if $row{duration_ms} < 0;

    return \%row;
}

sub read_exact {
    my ($fh, $length) = @_;
    my $buffer = '';
    my $offset = 0;

    while ($offset < $length) {
        my $count = sysread($fh, $buffer, $length - $offset, $offset);
        last if !defined $count || $count == 0;
        $offset += $count;
    }
    return $buffer;
}

sub find_begin {
    my ($fh, $size) = @_;
    my $offset = 0;
    my $carry = '';

    while ($offset < $size) {
        my $remaining = $size - $offset;
        my $length = $remaining < $block_size ? $remaining : $block_size;

        return undef unless defined sysseek($fh, $offset, 0);
        my $block = read_exact($fh, $length);
        last if $block eq '';

        my $data = $carry . $block;
        return $1 if $data =~ /$TIMESTAMP_RE/;

        $carry = length($data) > 128 ? substr($data, -128) : $data;
        $offset += length($block);
    }
    return undef;
}

sub find_end {
    my ($fh, $size) = @_;
    my $offset = $size;
    my $carry = '';

    while ($offset > 0) {
        my $length = $offset < $block_size ? $offset : $block_size;
        my $start = $offset - $length;

        return undef unless defined sysseek($fh, $start, 0);
        my $block = read_exact($fh, $length);
        last if $block eq '';

        my $data = $block . $carry;
        my @timestamps = ($data =~ /$TIMESTAMP_RE/g);
        return $timestamps[-1] if @timestamps;

        $carry = length($data) > 128 ? substr($data, 0, 128) : $data;
        $offset = $start;
    }
    return undef;
}

sub timestamp_ms {
    my ($timestamp) = @_;
    return undef unless defined $timestamp && $timestamp =~ m{
        ^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}),(\d{3})$
    }x;

    my $epoch;
    eval {
        $epoch = timegm($6, $5, $4, $3, $2 - 1, $1);
    };
    return undef if $@;
    return $epoch * 1000 + $7;
}

sub format_duration_verbose {
    my ($milliseconds) = @_;
    return 'N/A' unless defined $milliseconds;
    return 'END<BEGIN' if $milliseconds < 0;

    my $days = int($milliseconds / 86400000);
    $milliseconds %= 86400000;
    my $hours = int($milliseconds / 3600000);
    $milliseconds %= 3600000;
    my $minutes = int($milliseconds / 60000);
    $milliseconds %= 60000;
    my $seconds = int($milliseconds / 1000);
    my $millis = $milliseconds % 1000;

    my $clock = sprintf('%02d:%02d:%02d.%03d', $hours, $minutes, $seconds, $millis);
    return $days ? "$days+$clock" : $clock;
}

sub split_timestamp {
    my ($timestamp) = @_;
    return ('', '') unless defined $timestamp;
    return $1 eq '' ? ('', $timestamp) : ($1, $2) if $timestamp =~ /^(\d{4}-\d{2}-\d{2})T(.+)$/;
    return ('', $timestamp);
}

sub normalize_host {
    my ($host) = @_;
    return '' unless defined $host;
    $host =~ s/^['"]|['"]$//g;
    $host =~ s/\s+$//;
    $host = lc($host);
    $host =~ s/\..*$//;
    return $host;
}

sub classify_cluster {
    my ($sample) = @_;
    return 'NO' unless defined $sample && length $sample;

    my $local_host = '';
    if ($sample =~ /Host:\s*'([^']+)'/i) {
        $local_host = normalize_host($1);
    }
    elsif ($sample =~ /SASMeta_MetadataServer_[0-9T-]+_([A-Z0-9]+)_/i) {
        $local_host = lc($1);
    }

    my %seen_redirect;
    my @redirect_targets;
    while ($sample =~ /redirect(?:ing)?[^\n]{0,200}?\bat\s+([A-Za-z0-9._-]+)/ig) {
        my $target = normalize_host($1);
        next unless length $target;
        push @redirect_targets, $target unless $seen_redirect{$target}++;
    }

    return 'PRI' if grep { length $local_host && $_ ne $local_host } @redirect_targets;
    return 'NO' if @redirect_targets;

    return 'PRI' if $sample =~ /\b(?:Setting the master|Changing the master|the master node|master node)\b/i;
    return '2'   if $sample =~ /\b(?:master|primary)\b.*\b(?:secondary|standby|backup|slave)\b/i ||
                    $sample =~ /\b(?:secondary|standby|backup|slave)\b.*\b(?:master|primary)\b/i;
    return '3'   if $sample =~ /\b(?:third|tertiary|3rd\s+node|node\s+3)\b/i;

    return 'NO';
}

sub cluster_code {
    my ($cluster) = @_;
    return 'PRI' if defined $cluster && $cluster =~ /^(?:PRIMARY|PRI)$/i;
    return '2'   if defined $cluster && $cluster =~ /^(?:SECONDARY|2)$/i;
    return '3'   if defined $cluster && $cluster =~ /^(?:TERTIARY|3)$/i;
    return 'CL'  if defined $cluster && $cluster =~ /^CLUSTERED$/i;
    return 'NO';
}

sub print_compact {
    my @items = @_;
    printf "%-10s %-12s %-23s %-12s %-13s %-1s %-1s %-1s %-7s %s\n",
        'DATE', 'BEGIN', 'END', 'DUR', 'RATIO(T+D/I)', 'T', 'S', 'R', 'CLUSTER', 'FILE';

    my $previous_date = '';
    for my $row (@items) {
        my ($begin_date, $begin_time) = split_timestamp($row->{begin});
        my ($end_date, $end_time)     = split_timestamp($row->{end});
        my $display_date = ($begin_date ne '' && $begin_date ne $previous_date) ? $begin_date : '';
        $previous_date = $begin_date if $begin_date ne '';

        my $display_end = $end_time || 'N/A';
        $display_end = "$end_date T $end_time" if ($end_date ne '' && $begin_date ne '' && $end_date ne $begin_date);

        printf "%-10s %-12s %-23s %-12s %-13.2f %-1s %-1s %-1s %-7s %s",
            $display_date,
            $begin_time || 'N/A',
            $display_end,
            format_duration_verbose($row->{duration_ms}),
            $row->{trace_ratio} || 0,
            $row->{trace} ? 'Y' : '-',
            $row->{startup} ? 'Y' : '-',
            $row->{running} ? 'Y' : '-',
            cluster_code($row->{cluster}),
            $row->{file};

        print " [$row->{status}]" if $row->{status} ne 'OK';
        print "\n";
    }
}

sub print_verbose {
    my @items = @_;
    printf "%-10s %-12s %-23s %-15s %-13s %-5s %-7s %-7s %-7s %s\n",
        'DATE', 'BEGIN', 'END', 'DURATION', 'RATIO(T+D/I)', 'TRACE', 'STARTUP', 'RUNNING', 'CLUSTER', 'FILE';

    my $previous_date = '';
    for my $row (@items) {
        my ($begin_date, $begin_time) = split_timestamp($row->{begin});
        my ($end_date, $end_time)     = split_timestamp($row->{end});
        my $display_date = ($begin_date ne '' && $begin_date ne $previous_date) ? $begin_date : '';
        $previous_date = $begin_date if $begin_date ne '';

        my $display_end = $end_time || 'N/A';
        $display_end = "$end_date T $end_time" if ($end_date ne '' && $begin_date ne '' && $end_date ne $begin_date);

        printf "%-10s %-12s %-23s %-15s %-13.2f %-5s %-7s %-7s %-7s %s",
            $display_date,
            $begin_time || 'N/A',
            $display_end,
            format_duration_verbose($row->{duration_ms}),
            $row->{trace_ratio} || 0,
            $row->{trace} ? 'YES' : 'NO',
            $row->{startup} ? 'YES' : 'NO',
            $row->{running} ? 'YES' : 'NO',
            cluster_code($row->{cluster}),
            $row->{file};

        print " [$row->{status}]" if $row->{status} ne 'OK';
        print "\n";
    }
}

sub print_details_summary {
    my @items = @_;
    my ($total_files, $trace_enabled, $non_trace) = (scalar @items, 0, 0);
    my ($total_trace, $total_debug, $total_info) = (0, 0, 0);

    for my $row (@items) {
        $total_trace += $row->{trace_count} || 0;
        $total_debug += $row->{debug_count} || 0;
        $total_info  += $row->{info_count}  || 0;
        $row->{trace} ? $trace_enabled++ : $non_trace++;
    }

    print "\nTRACE determination summary\n";
    print "Files analyzed: $total_files | TRACE-enabled: $trace_enabled | Not TRACE-enabled: $non_trace\n";
    print "Observed sample counts: TRACE=$total_trace, DEBUG=$total_debug, INFO=$total_info\n\n";

    for my $row (@items) {
        printf "%-40s %-18s cluster=%-10s trace=%d debug=%d info=%d ratio=%.2f\n",
            $row->{file},
            ($row->{trace} ? 'TRACE_ENABLED' : 'NOT_TRACE_ENABLED'),
            cluster_code($row->{cluster}),
            $row->{trace_count} || 0,
            $row->{debug_count} || 0,
            $row->{info_count} || 0,
            $row->{trace_ratio} || 0;
    }
    print "\n";
}
