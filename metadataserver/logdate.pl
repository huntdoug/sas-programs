#!/usr/bin/env perl
#
# logdate
#
# Fast SAS Metadata Server log timeline utility.
#
# Author: Douglas Hunt (SAS domain expertise)
# Developed with GitHub Copilot assistance
#
# Verbose output is the default. Use -c for compact output.
#
# Usage:
#   logdate [options] LOGFILE...
#   logdate -d SASMeta*.log
#   logdate -c SASMeta*.log
#   logdate --version
#
# The program reads SAS Metadata Server log files, finds the first and last
# timestamps, and summarizes whether the log appears to be in a TRACE-enabled
# state. TRACE is considered enabled only when the sampled log window contains
# more TRACE+DEBUG records than INFO records.
#
# This is a heuristic used to discriminate meaningful diagnostic logging from
# a log that is mostly informational chatter.
#
# The script is intentionally conservative: a log with INFO dominating the
# sampled window is treated as not TRACE-enabled even if a few TRACE records
# appear.
#
# Author: Douglas Hunt (SAS domain expertise)
# Developed with GitHub Copilot assistance
#
use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use Time::Local qw(timegm);

our $VERSION = '2.2.9';

# Details is the default. Use --compact to suppress the detailed report.
my $details = 1;
my $help = 0;
my $version = 0;

# Filesystem block used when looking for first and last timestamps.
my $block_size = 1024 * 1024;

# Initial bytes examined for TRACE, STARTUP, and RUNNING markers.
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

# SAS timestamp at the start of a physical line.
my $TIMESTAMP_RE = qr{
    ^
    (
        \d{4}-\d{2}-\d{2}
        T
        \d{2}:\d{2}:\d{2},
        \d{3}
    )
}mx;

my %seen;
my @rows;

# Remove duplicate filenames while retaining command-line order.
for my $file (grep { !$seen{$_}++ } @ARGV) {
    if (!-f $file) {
        warn "logdate: warning: not a regular file: $file\n";
        next;
    }

    push @rows, analyze_file($file);
}

usage(1, 'no readable log files supplied') unless @rows;

# Sort by BEGIN, then END, then filename.
@rows = sort {
       ($a->{begin} // '9999') cmp ($b->{begin} // '9999')
    || ($a->{end}   // '9999') cmp ($b->{end}   // '9999')
    || $a->{file} cmp $b->{file}
} @rows;

if ($details) {
    print_details_summary(@rows);
    print_verbose(@rows);
}
else {
    print_compact(@rows);
}

exit 0;

sub usage
{
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

Purpose:
  This utility inspects one or more SAS Metadata Server log files and reports
  the first and last timestamp, elapsed duration, startup state, running state,
  and whether the sampled log window suggests TRACE or DEBUG activity is active.

  The file name and the first log line normally include the hostname. The script
  normalizes that hostname to its short lowercase form so it can compare it with
  the target hostname found in cluster redirect messages.

  If the target hostname matches the current node after normalization, the
  redirect is self-directed and simply means this is a single metadata server,
  not a clustered node. If the redirect target is different, that is strong
  evidence this node is acting as the primary/master metadata server.

  The cluster column therefore reports:
    PRI = primary/master
    2   = secondary
    3   = tertiary
    NO  = no cluster / single metadata server

  6. If there is no cluster marker and no remote redirect, the node is treated
     as a single metadata server and shown as 'NO'.

Flags in the detailed output:
  T / TRACE     TRACE+DEBUG exceeds INFO in the sampled window
  S / STARTUP   SAH011001I State, starting found
  R / RUNNING   SAH011999I State, running found
  CLUSTER       PRI = primary/master, 2 = secondary, 3 = tertiary, NO = no cluster

Status values:
  OK             Normal analysis
  NO_BEGIN       No usable begin timestamp found
  NO_END         No usable end timestamp found
  END_BEFORE_BEGIN  End timestamp precedes the begin timestamp
  BAD_TIMESTAMP  Invalid or unparsable timestamp format
  OPEN_ERROR     File could not be opened
  STAT_ERROR     File size/stat failure

The detailed view prints the per-file decision using the rule above and also
includes the count of TRACE, DEBUG, and INFO records observed in the sample.
USAGE

    exit $status;
}

sub analyze_file
{
    my ($file) = @_;

    my %row = (
        file        => $file,
        begin       => undef,
        end         => undef,
        duration_ms => undef,
        trace       => 0,
        trace_count => 0,
        debug_count => 0,
        info_count  => 0,
        trace_ratio => 0,
        cluster     => 'UNKNOWN',
        startup     => 0,
        running     => 0,
        status      => 'OK',
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
    $row{end} = find_end($fh, $size);

    my $sample_size = $size < $marker_bytes ? $size : $marker_bytes;

    if ($sample_size > 0 && defined sysseek($fh, 0, 0)) {
        my $sample = read_exact($fh, $sample_size);

        my $trace_count = () = $sample =~ /^\d{4}-.*?\bTRACE\b/mg;
        my $debug_count = () = $sample =~ /^\d{4}-.*?\bDEBUG\b/mg;
        my $info_count  = () = $sample =~ /^\d{4}-.*?\bINFO\b/mg;

        my $signal = $trace_count + $debug_count;
        my $noise  = $info_count;

        $row{trace_count} = $trace_count;
        $row{debug_count} = $debug_count;
        $row{info_count}  = $info_count;
        $row{trace_ratio} = $signal / ($noise + 1);
        $row{trace} = ($signal > 0 && $signal > $noise) ? 1 : 0;

        if ($sample =~ /\b(?:master|primary)\b/i) {
            $row{cluster} = 'PRIMARY';
        }
        elsif ($sample =~ /\b(?:slave|secondary|backup|standby)\b/i) {
            $row{cluster} = 'SECONDARY';
        }
        elsif ($sample =~ /\b(?:third|tertiary|node\s*3|3rd\s+node)\b/i) {
            $row{cluster} = 'TERTIARY';
        }
        elsif ($sample =~ /Cluster\s+_NoCluster_/i) {
            $row{cluster} = 'NO';
        }
        elsif ($sample =~ /\bcluster\b/i) {
            $row{cluster} = 'NO';
        }
        else {
            $row{cluster} = classify_cluster($sample);
        }

        $row{startup} =
            $sample =~ /\bSAH011001I\b.*?\bState,\s*starting\b/i
            ? 1 : 0;

        $row{running} =
            $sample =~ /\bSAH011999I\b.*?\bState,\s*running\b/i
            ? 1 : 0;
    }

    close($fh);

    if (!defined $row{begin}) {
        $row{status} = 'NO_BEGIN';
        return \%row;
    }

    if (!defined $row{end}) {
        $row{status} = 'NO_END';
        return \%row;
    }

    my $begin_ms = timestamp_ms($row{begin});
    my $end_ms = timestamp_ms($row{end});

    if (!defined $begin_ms || !defined $end_ms) {
        $row{status} = 'BAD_TIMESTAMP';
        return \%row;
    }

    $row{duration_ms} = $end_ms - $begin_ms;

    if ($row{duration_ms} < 0) {
        $row{status} = 'END_BEFORE_BEGIN';
    }

    return \%row;
}

sub read_exact
{
    my ($fh, $length) = @_;

    my $buffer = '';
    my $offset = 0;

    while ($offset < $length) {
        my $count = sysread(
            $fh,
            $buffer,
            $length - $offset,
            $offset
        );

        last if !defined $count;
        last if $count == 0;

        $offset += $count;
    }

    return $buffer;
}

sub find_begin
{
    my ($fh, $size) = @_;

    my $offset = 0;
    my $carry = '';

    while ($offset < $size) {
        my $remaining = $size - $offset;
        my $length =
            $remaining < $block_size ? $remaining : $block_size;

        return undef unless defined sysseek($fh, $offset, 0);

        my $block = read_exact($fh, $length);
        last if $block eq '';

        my $data = $carry . $block;

        if ($data =~ /$TIMESTAMP_RE/) {
            return $1;
        }

        $carry =
            length($data) > 128 ? substr($data, -128) : $data;

        $offset += length($block);
    }

    return undef;
}

sub find_end
{
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

        if (@timestamps) {
            return $timestamps[-1];
        }

        $carry =
            length($data) > 128 ? substr($data, 0, 128) : $data;

        $offset = $start;
    }

    return undef;
}

sub timestamp_ms
{
    my ($timestamp) = @_;

    return undef unless defined $timestamp;

    return undef unless $timestamp =~ m{
        ^
        (\d{4})-(\d{2})-(\d{2})
        T
        (\d{2}):(\d{2}):(\d{2})
        ,
        (\d{3})
        $
    }x;

    my ($year, $month, $day, $hour, $minute, $second, $millisecond) =
        ($1, $2, $3, $4, $5, $6, $7);

    my $epoch;

    eval {
        $epoch = timegm(
            $second,
            $minute,
            $hour,
            $day,
            $month - 1,
            $year
        );
    };

    return undef if $@;

    return $epoch * 1000 + $millisecond;
}

sub format_duration_compact
{
    my ($milliseconds) = @_;

    return 'N/A' unless defined $milliseconds;
    return 'INVALID' if $milliseconds < 0;

    my $total_minutes = int($milliseconds / 60000);
    my $hours = int($total_minutes / 60);
    my $minutes = $total_minutes % 60;

    return sprintf('%02d:%02d', $hours, $minutes);
}

sub format_duration_verbose
{
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

    my $clock = sprintf(
        '%02d:%02d:%02d.%03d',
        $hours,
        $minutes,
        $seconds,
        $millis
    );

    return $days ? "$days+$clock" : $clock;
}

sub split_timestamp
{
    my ($timestamp) = @_;

    return ('', '') unless defined $timestamp;

    if ($timestamp =~ /^(\d{4}-\d{2}-\d{2})T(.+)$/) {
        return ($1, $2);
    }

    return ('', $timestamp);
}

sub short_time
{
    my ($time) = @_;

    return 'N/A' unless defined $time && length $time;

    if ($time =~ /^(\d{2}:\d{2})/) {
        return $1;
    }

    return $time;
}

sub normalize_host
{
    my ($host) = @_;
    return '' unless defined $host;
    $host =~ s/^['"]//;
    $host =~ s/['"]$//;
    $host =~ s/\s+$//;
    $host = lc($host);
    $host =~ s/\..*$//;
    $host =~ s/.*_// if $host =~ /_\w+$/;
    return $host;
}

sub classify_cluster
{
    my ($sample) = @_;
    return 'NO' unless defined $sample && length $sample;

    my $local_host = '';
    if ($sample =~ /Host:\s*'([^']+)'/i) {
        $local_host = normalize_host($1);
    }
    elsif ($sample =~ /([A-Z][A-Z0-9]+_\d{8}_[A-Z0-9]+)\.log/i) {
        my $from_name = $1;
        $from_name =~ s/^.*_//;
        $from_name =~ s/_[0-9]{8}.*$//;
        $local_host = lc($from_name);
    }

    my $self_redirect = 0;
    my $remote_redirect = 0;

    while ($sample =~ /redirect(?:ing)?[^\n]{0,200}?\bto\s+([A-Za-z0-9._-]+)/ig) {
        my $target = normalize_host($1);
        next unless length $target;
        if (length $local_host && $target eq $local_host) {
            $self_redirect = 1;
        }
        else {
            $remote_redirect = 1;
        }
    }

    if ($remote_redirect) {
        return 'PRI';
    }

    if ($sample =~ /(?:Setting the master|Changing the master|the master node|master node)/i) {
        return 'PRI';
    }

    if ($sample =~ /(?:secondary|slave|standby|backup)/i) {
        return '2';
    }

    if ($sample =~ /(?:third|tertiary|3rd node|node 3)/i) {
        return '3';
    }

    if ($sample =~ /Cluster\s+_NoCluster_/i) {
        return 'NO';
    }

    if ($sample =~ /\bcluster\b/i) {
        return 'NO';
    }

    return 'NO';
}

sub cluster_code
{
    my ($cluster) = @_;

    return 'PRI' if defined $cluster && $cluster =~ /^PRIMARY$/i;
    return '2'   if defined $cluster && $cluster =~ /^SECONDARY$/i;
    return '3'   if defined $cluster && $cluster =~ /^TERTIARY$/i;
    return 'NO'  if defined $cluster && $cluster =~ /^(?:NO_CLUSTER|NO|UNKNOWN|SINGLE|-)$/i;
    return 'CL'  if defined $cluster && $cluster =~ /^CLUSTERED$/i;
    return 'PRI' if defined $cluster && $cluster =~ /^PRI$/i;
    return '2'   if defined $cluster && $cluster =~ /^2$/i;
    return '3'   if defined $cluster && $cluster =~ /^3$/i;
    return 'NO'  if defined $cluster && $cluster =~ /^NO$/i;
    return 'CL'  if defined $cluster && $cluster =~ /^CL$/i;
    return 'NO';
}

sub print_compact
{
    my @items = @_;

    printf "%-10s %-12s %-12s %-12s %-10s %-1s %-1s %-1s %-5s %s\n",
        'DATE',
        'BEGIN',
        'END',
        'DUR',
        'RATIO(T+D/I)',
        'T',
        'S',
        'R',
        'CLUSTER',
        'FILE';

    my $previous_date = '';

    for my $row (@items) {

        my ($begin_date, $begin_time) =
            split_timestamp($row->{begin});

        my ($end_date, $end_time) =
            split_timestamp($row->{end});

        my $display_date = '';

        if (
            $begin_date ne ''
            && $begin_date ne $previous_date
        ) {
            $display_date = $begin_date;
        }

        $previous_date = $begin_date
            if $begin_date ne '';

        my $display_end = $end_time || 'N/A';

        # Retain END date only when the file crosses to another date.
        if (
            $end_date ne ''
            && $begin_date ne ''
            && $end_date ne $begin_date
        ) {
            $display_end = $end_date . 'T' . $end_time;
        }

        my $ratio = $row->{trace_ratio} || 0;
        my $cluster = cluster_code($row->{cluster});

        printf "%-10s %-12s %-12s %-12s %-10.2f %-1s %-1s %-1s %-5s %s",
            $display_date,
            $begin_time || 'N/A',
            $display_end,
            format_duration_verbose(
                $row->{duration_ms}
            ),
            $ratio,
            $row->{trace}
                ? 'Y'
                : '-',
            $row->{startup}
                ? 'Y'
                : '-',
            $row->{running}
                ? 'Y'
                : '-',
            $cluster,
            $row->{file};

        if ($row->{status} ne 'OK') {
            print " [$row->{status}]";
        }

        print "\n";
    }
}

sub print_verbose
{
    my @items = @_;

    printf "%-10s %-12s %-22s %-15s %-10s %-5s %-7s %-7s %-5s %s\n",
        'DATE',
        'BEGIN',
        'END',
        'DURATION',
        'RATIO(T+D/I)',
        'TRACE',
        'STARTUP',
        'RUNNING',
        'CLUSTER',
        'FILE';

    my $previous_date = '';

    for my $row (@items) {
        my ($begin_date, $begin_time) = split_timestamp($row->{begin});
        my ($end_date, $end_time) = split_timestamp($row->{end});
        my $display_date = '';

        if ($begin_date ne '' && $begin_date ne $previous_date) {
            $display_date = $begin_date;
        }

        $previous_date = $begin_date if $begin_date ne '';

        my $display_end = $end_time || 'N/A';

        # Retain END date only when the file crosses to another date.
        if (
            $end_date ne ''
            && $begin_date ne ''
            && $end_date ne $begin_date
        ) {
            $display_end = $end_date . 'T' . $end_time;
        }

        my $ratio = $row->{trace_ratio} || 0;
        my $cluster = cluster_code($row->{cluster});

        printf "%-10s %-12s %-22s %-15s %-10.2f %-5s %-7s %-7s %-5s %s",
            $display_date,
            $begin_time || 'N/A',
            $display_end,
            format_duration_verbose($row->{duration_ms}),
            $ratio,
            $row->{trace} ? 'YES' : 'NO',
            $row->{startup} ? 'YES' : 'NO',
            $row->{running} ? 'YES' : 'NO',
            $cluster,
            $row->{file};

        if ($row->{status} ne 'OK') {
            print " [$row->{status}]";
        }

        print "\n";
    }
}

sub print_details_summary
{
    my @items = @_;

    my $total_files = scalar @items;
    my $trace_enabled = 0;
    my $non_trace = 0;
    my $total_trace = 0;
    my $total_debug = 0;
    my $total_info = 0;

    for my $row (@items) {
        $total_trace += $row->{trace_count} || 0;
        $total_debug += $row->{debug_count} || 0;
        $total_info  += $row->{info_count} || 0;

        if ($row->{trace}) {
            $trace_enabled++;
        }
        else {
            $non_trace++;
        }
    }

    print "\nTRACE determination summary\n";
    print "Rule: TRACE is enabled only when TRACE + DEBUG > INFO in the sampled log window.\n";
    print "Ratio = (TRACE + DEBUG) / INFO. >1.0 means TRACE/DEBUG dominates; <=1.0 means INFO dominates.\n";
    print "Files analyzed: $total_files\n";
    print "TRACE-enabled logs: $trace_enabled\n";
    print "Not TRACE-enabled: $non_trace\n";
    print "Observed sample counts: TRACE=$total_trace, DEBUG=$total_debug, INFO=$total_info\n\n";

    for my $row (@items) {
        my $ratio = $row->{trace_ratio} || 0;
        my $status = $row->{trace} ? 'TRACE_ENABLED' : 'NOT_TRACE_ENABLED';
        my $cluster = $row->{cluster} || 'UNKNOWN';
        my $cluster_code = cluster_code($cluster);
        printf "%-40s %-18s cluster=%-10s trace=%d debug=%d info=%d ratio=%.2f\n",
            $row->{file},
            $status,
            $cluster_code,
            $row->{trace_count} || 0,
            $row->{debug_count} || 0,
            $row->{info_count} || 0,
            $ratio;
    }

    print "\n";
}
