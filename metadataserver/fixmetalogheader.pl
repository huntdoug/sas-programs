#!/usr/bin/env perl
#
# fixmetalogheader 1.2.0
#
# Author: Douglas Hunt (SAS domain expertise)
# Developed with GitHub Copilot assistance
#
# Repairs a SAS Metadata Server continuation log by prepending a startup
# section taken from a complete TRACE-level donor startup log.
#
# Workflow:
#   1. Prompt for a complete donor startup log.
#   2. Prompt for the incomplete target log.
#   3. Run logdate against both input files.
#   4. Validate that the donor contains TRACE, STARTING, and RUNNING.
#   5. Prompt for the replacement YYYY-MM-DDTHH:MM:SS,mmm timestamp.
#   6. Copy the donor from its first line through its first RUNNING marker.
#   7. Replace each line-leading donor timestamp with the supplied timestamp.
#   8. Remove the first two lines from the incomplete target log.
#   9. Append the remaining target log to create the repaired log.
#  10. Run logdate against the repaired log.
#
# The final repaired log contains no warning, provenance, or explanatory
# banner. The donor and target input files are never modified.
#
# Default repaired filename:
#   target.log.orig  -> target.log
#   target.log       -> target.repaired.log
#

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use File::Spec;
use Time::Local qw(timegm);
use POSIX qw(strftime);

our $VERSION = '1.2.0';

my $output_option;
my $logdate_option;
my $marker_bytes = 4 * 1024 * 1024;
my $help = 0;
my $version = 0;

GetOptions(
    'output|o=s'     => \$output_option,
    'logdate=s'      => \$logdate_option,
    'marker-bytes=i' => \$marker_bytes,
    'version|V'      => \$version,
    'help|h'         => \$help,
) or usage(2);

if ($version) {
    print "fixmetalogheader $VERSION\n";
    exit 0;
}

usage(0) if $help;

die "fixmetalogheader: --marker-bytes must be at least 4096\n"
    if $marker_bytes < 4096;

print "fixmetalogheader $VERSION\n\n";

my $donor = prompt_filename(
    'Enter complete TRACE-level startup donor log'
);

my $target = prompt_filename(
    'Enter incomplete target log'
);

if (same_file($donor, $target)) {
    die "fixmetalogheader: donor and target must be different files\n";
}

my $logdate = find_logdate($logdate_option);

print "\nInput logdate results\n";
print "---------------------\n";
run_logdate($logdate, $donor, $target);

my $donor_info = inspect_donor($donor, $marker_bytes);

print "\nDonor validation\n";
print "----------------\n";
printf "TRACE   : %s\n", $donor_info->{trace}   ? 'YES' : 'NO';
printf "STARTUP : %s\n", $donor_info->{startup} ? 'YES' : 'NO';
printf "RUNNING : %s\n", $donor_info->{running} ? 'YES' : 'NO';

if (
    !$donor_info->{trace}
    || !$donor_info->{startup}
    || !$donor_info->{running}
) {
    print STDERR <<'ERROR_MESSAGE';

No repaired log was created.

The selected donor is not a complete TRACE-level Metadata Server
startup/running log.

A valid donor must contain:

  TRACE-level log records
  SAH011001I ... State, starting
  SAH011999I ... State, running

The donor should preferably come from the same environment, SAS release,
operating system, and configuration as the incomplete target log.

Without a complete donor TRACE startup/running log, fixmetalogheader will
not construct a repaired log.
ERROR_MESSAGE
    exit 1;
}

print "\nValid donor startup log.\n";

my $target_begin = find_first_timestamp($target);

defined $target_begin
    or die "fixmetalogheader: no timestamp found in target log: $target\n";

my $suggested_timestamp = subtract_one_millisecond($target_begin);
my $timestamp = prompt_timestamp($target_begin, $suggested_timestamp);
my $output = defined $output_option
    ? $output_option
    : derive_output_name($target);

if (same_path($output, $donor) || same_path($output, $target)) {
    die "fixmetalogheader: output must not replace the donor or target input\n";
}

if (-e $output) {
    print "\n$output already exists. Overwrite it? [y/N]: ";
    my $answer = <STDIN>;
    defined $answer
        or die "fixmetalogheader: input ended before overwrite response\n";
    chomp $answer;

    if ($answer !~ /^y(?:es)?$/i) {
        print "No repaired log was created.\n";
        exit 1;
    }
}

create_repaired_log(
    output      => $output,
    target      => $target,
    timestamp   => $timestamp,
    donor_lines => $donor_info->{lines},
);

print "\nRepaired log created: $output\n";
print "Donor log preserved : $donor\n";
print "Target log preserved: $target\n";
print "Replacement time    : $timestamp\n";
print "Target lines removed: 2\n";
print "\nNo warning or provenance header was inserted into the repaired log.\n";

print "\nRepaired logdate check\n";
print "----------------------\n";
run_logdate($logdate, $output);

exit 0;

sub prompt_filename
{
    my ($label) = @_;

    while (1) {
        print "$label:\n> ";

        my $value = <STDIN>;
        defined $value
            or die "fixmetalogheader: input ended while reading filename\n";

        chomp $value;
        $value =~ s/^\s+//;
        $value =~ s/\s+$//;

        if ($value eq '') {
            print "A filename is required.\n\n";
            next;
        }

        if (!-f $value) {
            print "Not a regular file: $value\n\n";
            next;
        }

        if (!-r $value) {
            print "File is not readable: $value\n\n";
            next;
        }

        return $value;
    }
}

sub prompt_timestamp
{
    my ($target_begin, $suggested) = @_;

    while (1) {
        print "\nTarget BEGIN timestamp : $target_begin\n";
        print "Suggested header time  : $suggested\n";
        print "Press ENTER to accept the suggestion, or enter another\n";
        print "timestamp [YYYY-MM-DDTHH:MM:SS,mmm].\n";
        print "Timestamp [$suggested]: ";

        my $value = <STDIN>;
        defined $value
            or die "fixmetalogheader: input ended while reading timestamp\n";

        chomp $value;
        $value =~ s/^\s+//;
        $value =~ s/\s+$//;

        $value = $suggested if $value eq '';

        return $value if valid_timestamp($value);

        print "Invalid timestamp. Example: 2026-08-30T00:00:01,624\n";
    }
}

sub find_first_timestamp
{
    my ($file) = @_;

    open(my $fh, '<', $file)
        or die "fixmetalogheader: cannot open $file: $!\n";

    while (my $line = <$fh>) {
        if ($line =~ /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})/) {
            my $timestamp = $1;
            close($fh);
            return $timestamp;
        }
    }

    close($fh);
    return undef;
}

sub subtract_one_millisecond
{
    my ($timestamp) = @_;
    return milliseconds_to_timestamp(timestamp_to_milliseconds($timestamp) - 1);
}

sub timestamp_to_milliseconds
{
    my ($timestamp) = @_;

    $timestamp =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}),(\d{3})$/
        or die "fixmetalogheader: invalid timestamp: $timestamp\n";

    my ($year, $month, $day, $hour, $minute, $second, $millisecond) =
        ($1, $2, $3, $4, $5, $6, $7);

    my $epoch = timegm(
        $second,
        $minute,
        $hour,
        $day,
        $month - 1,
        $year
    );

    return $epoch * 1000 + $millisecond;
}

sub milliseconds_to_timestamp
{
    my ($milliseconds) = @_;

    my $seconds = int($milliseconds / 1000);
    my $millisecond = $milliseconds % 1000;

    if ($millisecond < 0) {
        $millisecond += 1000;
        $seconds--;
    }

    return strftime('%Y-%m-%dT%H:%M:%S', gmtime($seconds))
        . sprintf(',%03d', $millisecond);
}

sub valid_timestamp
{
    my ($value) = @_;

    return 0 unless $value =~ m{
        ^
        (\d{4})-(\d{2})-(\d{2})
        T
        (\d{2}):(\d{2}):(\d{2})
        ,
        (\d{3})
        $
    }x;

    my ($year, $month, $day, $hour, $minute, $second) =
        ($1, $2, $3, $4, $5, $6);

    return 0 if $year < 1;
    return 0 if $month < 1 || $month > 12;
    return 0 if $day < 1 || $day > days_in_month($year, $month);
    return 0 if $hour > 23;
    return 0 if $minute > 59;
    return 0 if $second > 59;

    return 1;
}

sub days_in_month
{
    my ($year, $month) = @_;

    return 31 if $month == 1 || $month == 3 || $month == 5
        || $month == 7 || $month == 8 || $month == 10 || $month == 12;
    return 30 if $month == 4 || $month == 6 || $month == 9
        || $month == 11;

    my $leap =
        ($year % 400 == 0)
        || ($year % 4 == 0 && $year % 100 != 0);

    return $leap ? 29 : 28;
}

sub inspect_donor
{
    my ($file, $sample_limit) = @_;

    open(my $fh, '<', $file)
        or die "fixmetalogheader: cannot open $file: $!\n";

    my @lines;
    my $trace = 0;
    my $startup = 0;
    my $running = 0;
    my $bytes_seen = 0;

    while (my $line = <$fh>) {
        push @lines, $line;
        $bytes_seen += length($line);

        if ($bytes_seen <= $sample_limit) {
            $trace = 1
                if $line =~
                /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3}\s+TRACE\b/;
        }

        $startup = 1
            if $line =~
            /\bSAH011001I\b.*?\bState,\s*starting\b/i;

        if ($line =~ /\bSAH011999I\b.*?\bState,\s*running\b/i) {
            $running = 1;
            last;
        }
    }

    close($fh);

    return {
        trace   => $trace,
        startup => $startup,
        running => $running,
        lines   => \@lines,
    };
}

sub create_repaired_log
{
    my (%args) = @_;

    my $output = $args{output};
    my $target = $args{target};
    my $timestamp = $args{timestamp};
    my $donor_lines = $args{donor_lines};

    open(my $out, '>', $output)
        or die "fixmetalogheader: cannot create $output: $!\n";

    # Write the donor startup section with every line-leading donor
    # timestamp replaced by the requested target timestamp.
    for my $original_line (@{$donor_lines}) {
        my $line = $original_line;

        $line =~ s{
            ^
            \d{4}-\d{2}-\d{2}
            T
            \d{2}:\d{2}:\d{2},\d{3}
        }{$timestamp}x;

        print {$out} $line
            or die "fixmetalogheader: write failed for $output: $!\n";
    }

    open(my $in, '<', $target)
        or die "fixmetalogheader: cannot open $target: $!\n";

    # Remove exactly the first two physical lines from the target:
    #   1. Host/version line
    #   2. Log continued from ... line
    scalar <$in>;
    scalar <$in>;

    while (my $line = <$in>) {
        print {$out} $line
            or die "fixmetalogheader: write failed for $output: $!\n";
    }

    close($in)
        or die "fixmetalogheader: error closing $target: $!\n";
    close($out)
        or die "fixmetalogheader: error closing $output: $!\n";
}

sub derive_output_name
{
    my ($target) = @_;

    my $output = $target;

    if ($output =~ s/\.orig$//) {
        return $output;
    }

    if ($output =~ s/\.log$/.repaired.log/i) {
        return $output;
    }

    return $output . '.repaired.log';
}

sub run_logdate
{
    my ($logdate, @files) = @_;

    my $status = system($logdate, @files);

    if ($status == -1) {
        die "fixmetalogheader: unable to run $logdate: $!\n";
    }

    if ($status & 127) {
        my $signal = $status & 127;
        die "fixmetalogheader: logdate terminated by signal $signal\n";
    }

    my $exit_code = $status >> 8;

    die "fixmetalogheader: logdate exited with status $exit_code\n"
        if $exit_code != 0;
}

sub find_logdate
{
    my ($requested) = @_;

    return validate_executable($requested) if defined $requested;

    # Prefer logdate in the same directory as fixmetalogheader.
    my ($volume, $directory, undef) = File::Spec->splitpath($0);
    my $beside = File::Spec->catpath($volume, $directory, 'logdate');

    if ($beside ne '' && -f $beside && -x $beside) {
        return $beside;
    }

    # Otherwise search PATH.
    for my $directory_name (File::Spec->path()) {
        my $candidate = File::Spec->catfile($directory_name, 'logdate');
        return $candidate if -f $candidate && -x $candidate;
    }

    die <<'NO_LOGDATE';
fixmetalogheader: cannot find an executable logdate program.

Place logdate in the same directory as fixmetalogheader, add logdate to
PATH, or specify it explicitly:

  fixmetalogheader --logdate /path/to/logdate
NO_LOGDATE
}

sub validate_executable
{
    my ($file) = @_;

    -f $file
        or die "fixmetalogheader: logdate is not a regular file: $file\n";
    -x $file
        or die "fixmetalogheader: logdate is not executable: $file\n";

    return $file;
}

sub same_file
{
    my ($left, $right) = @_;

    my @left_stat = stat($left);
    my @right_stat = stat($right);

    return 0 unless @left_stat && @right_stat;

    return $left_stat[0] == $right_stat[0]
        && $left_stat[1] == $right_stat[1];
}

sub same_path
{
    my ($left, $right) = @_;

    my $left_abs = File::Spec->rel2abs($left);
    my $right_abs = File::Spec->rel2abs($right);

    return $left_abs eq $right_abs;
}

sub usage
{
    my ($status) = @_;
    my $fh = $status ? *STDERR : *STDOUT;

    print {$fh} <<'USAGE';
Usage:
  fixmetalogheader [options]

Interactive workflow:
  1. Prompt for a complete TRACE-level startup donor log.
  2. Prompt for the incomplete target log.
  3. Run logdate for both input logs.
  4. Validate donor TRACE, STARTING, and RUNNING markers.
  5. Suggest target BEGIN minus one millisecond; ENTER accepts it.
  6. Prepend the adjusted donor startup section.
  7. Remove the first two lines from the target log.
  8. Append the remainder of the target log.
  9. Run logdate against the repaired log.

Options:
  -o, --output FILE       Repaired output filename
      --logdate FILE      Explicit path to logdate
      --marker-bytes N    Initial donor bytes checked for TRACE
                          Default: 4194304
  -V, --version           Show version
  -h, --help              Show help

Default output naming:
  target.log.orig  becomes target.log
  target.log       becomes target.repaired.log

The final repaired log contains no warning or provenance banner.
The donor and target input files are never modified.
USAGE

    exit $status;
}
