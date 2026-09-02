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
# Flags:
#   TRACE   Timestamped TRACE record found near the start of the log
#   STARTUP SAH011001I ... State, starting found
#   RUNNING SAH011999I ... State, running found
#
# Usage:
#   logdate SASMeta*.log
#   logdate -c SASMeta*.log
#   logdate --version
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use Time::Local qw(timegm);

our $VERSION = '2.2.2';

# Verbose is the default.
my $verbose = 1;
my $help = 0;
my $version = 0;

# Filesystem block used when looking for first and last timestamps.
my $block_size = 1024 * 1024;

# Initial bytes examined for TRACE, STARTUP, and RUNNING markers.
my $marker_bytes = 4 * 1024 * 1024;

GetOptions(
    'verbose|v'      => sub { $verbose = 1 },
    'compact|c'      => sub { $verbose = 0 },
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

if ($verbose) {
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
Usage:
  logdate [options] LOGFILE...

Options:
  -v, --verbose          Verbose output. This is the default.
  -c, --compact          Compact output.
  -V, --version          Show the program version.
  -h, --help             Show this help.

      --block-size N     Seek/read block size.
                         Default: 1048576 bytes.

      --marker-bytes N   Initial bytes inspected for TRACE,
                         startup, and running markers.
                         Default: 4194304 bytes.

Examples:
  logdate SASMeta*.log
  logdate -c SASMeta_MetadataServer_*.log
  logdate file1.log file2.log

Flags:
  T / TRACE     Timestamped TRACE record found
  S / STARTUP   SAH011001I State, starting found
  R / RUNNING   SAH011999I State, running found
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

sub print_compact
{
    my @items = @_;

    printf "%-10s %-12s %-12s %-12s %-1s %-1s %-1s %s\n",
        'DATE',
        'BEGIN',
        'END',
        'DUR',
        'T',
        'S',
        'R',
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

        my $display_end =
            $end_time || 'N/A';

        if (
            $end_date ne ''
            && $begin_date ne ''
            && $end_date ne $begin_date
        ) {
            $display_end =
                $end_date
                . 'T'
                . $end_time;
        }

        printf "%-10s %-12s %-12s %-12s %-1s %-1s %-1s %s",
            $display_date,
            ($begin_time || 'N/A'),
            $display_end,
            format_duration_verbose(
                $row->{duration_ms}
            ),
            $row->{trace}
                ? 'Y'
                : '-',
            $row->{startup}
                ? 'Y'
                : '-',
            $row->{running}
                ? 'Y'
                : '-',
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

    printf "%-10s %-12s %-22s %-15s %-5s %-7s %-7s %s\n",
        'DATE',
        'BEGIN',
        'END',
        'DURATION',
        'TRACE',
        'STARTUP',
        'RUNNING',
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

        printf "%-10s %-12s %-22s %-15s %-5s %-7s %-7s %s",
            $display_date,
            $begin_time || 'N/A',
            $display_end,
            format_duration_verbose($row->{duration_ms}),
            $row->{trace} ? 'YES' : 'NO',
            $row->{startup} ? 'YES' : 'NO',
            $row->{running} ? 'YES' : 'NO',
            $row->{file};

        if ($row->{status} ne 'OK') {
            print " [$row->{status}]";
        }

        print "\n";
    }
}
