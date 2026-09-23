#!/usr/bin/env perl
#
# logdate - SAS Metadata Server timeline and cluster incident analyzer
#
# Author: Douglas Hunt (SAS domain expertise)
# Developed with GitHub Copilot assistance
#
use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Time::Local qw(timegm);
use Time::HiRes qw(time);

Getopt::Long::Configure('no_ignore_case');

our $VERSION = '2.2.51';

my ($details, $verbose, $help, $show_version) = (1, 0, 0, 0);
my $block_size = 1024 * 1024;
my $marker_bytes = 4 * 1024 * 1024;
my $singleton_threshold = 10;
my $favorites_file = 'logdate.favorite.strings';
my $suppress_file = 'logdate.suppress.strings';
my $write_pattern_files = 0;

GetOptions(
    'details|d'             => sub { $details = 1; $verbose = 0 },
    'verbose|v'             => sub { $details = 1; $verbose = 1 },
    'compact|c'             => sub { $details = 0; $verbose = 0 },
    'version|V'             => \$show_version,
    'help|h'                => \$help,
    'block-size=i'          => \$block_size,
    'marker-bytes=i'        => \$marker_bytes,
    'singleton-threshold=i' => \$singleton_threshold,
    'favorites=s'           => \$favorites_file,
    'suppress=s'            => \$suppress_file,
    'write-pattern-files'   => \$write_pattern_files,
) or usage(2);

if ($show_version) { print "logdate $VERSION\n"; exit 0; }
usage(0) if $help;
die "logdate: --block-size must be at least 4096\n" if $block_size < 4096;
die "logdate: --marker-bytes must be at least 4096\n" if $marker_bytes < 4096;
die "logdate: --singleton-threshold must be at least 3\n" if $singleton_threshold < 3;

write_default_pattern_files() if $write_pattern_files;
usage(2, 'no log files supplied') unless @ARGV;

my @favorite_patterns = load_patterns($favorites_file);
my @suppress_patterns = load_patterns($suppress_file);
my $TIMESTAMP_RE = qr{^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})}m;
my $started = time();
my (%seen, @files, @rows);
my ($progress_total, $progress_completed, $progress_file, $progress_last_tick, $progress_ticks) = (0, 0, '', 0, 0);

for my $file (grep { !$seen{$_}++ } @ARGV) {
    if (!-f $file) { warn "logdate: warning: not a regular file: $file\n"; next; }
    push @files, $file;
}

print "logdate $VERSION\n";
$progress_total = scalar @files;
print_progress(0, $progress_total, 0, 0, 'Starting') if $progress_total > 1;
for my $index (0 .. $#files) {
    $progress_completed = $index;
    $progress_file = $files[$index];
    print_progress($index, $progress_total, time() - $started, 0, 'Scanning') if $progress_total > 1;
    push @rows, analyze_file($files[$index]);
    $progress_completed = $index + 1;
    print_progress($progress_completed, $progress_total, time() - $started, 0, 'Complete') if $progress_completed == $progress_total && $progress_total > 1;
}

assign_node_numbers(@rows);
$_->{role} = cluster_role($_) for @rows;

@rows = sort {
       ($a->{begin} // '9999') cmp ($b->{begin} // '9999')
    || ($a->{end}   // '9999') cmp ($b->{end}   // '9999')
    || $a->{file} cmp $b->{file}
} @rows;

my $elapsed = time() - $started;
$elapsed = 0.000001 if $elapsed <= 0;
$details ? print_header($elapsed, @rows) : print "\n";
print_node_table(@rows);
print "\n";
if ($details) {
    print_marker_summary(@rows);
    print "\n";
}
print_table(@rows);
print "\n";
print_cluster_state_report(@rows) if $details;
print_cluster_timeline(@rows) if $details;

print_cluster_findings(@rows) if $details;
exit 0;

sub usage {
    my ($status, $message) = @_;
    warn "logdate: $message\n" if defined $message;
    my $fh = $status ? *STDERR : *STDOUT;
    print $fh <<'USAGE';
logdate - SAS Metadata Server timeline and cluster incident analyzer.

Usage:
  logdate [options] LOGFILE...
  logdate -c SASMeta*.log
  logdate -d SASMeta*.log
  logdate -v SASMeta*.log

Options:
  -c, --compact                 Fast output. Non-TRACE logs receive a full
                                redirect-count scan; TRACE logs use a sample.
  -d, --details                 Full default analysis.
  -v, --verbose                 Default analysis plus every incident event.
      --singleton-threshold N   Suppress N or more consecutive one-event
                                redirect ranges. Default: 10.
      --favorites FILE          Optional favorite regex file.
      --suppress FILE           Optional suppression regex file.
      --write-pattern-files     Create starter pattern files.
  -V, --version
  -h, --help
USAGE
    exit $status;
}

sub default_favorites {
    return (
        'The outcall request did not complete in the time allotted',
        'Lost contact with the server when calling an IOM interface',
        'could not send update to peer', 'Disconnecting server',
        'Connecting server', 'Setting the master', 'Changing the master',
        'lost quorum', 'achieved quorum', 'New out call client connection',
        'SAH011001I', 'SAH011999I',
        'Attempts to synchronize the metadata on this node.*failed',
        'most recent update on the connecting server.*not one of the updates',
        'failed to redirect', 'Balance algorithm timed out',
        '\bERROR\b', '\bFATAL\b',
    );
}

sub default_suppressions {
    return (
        'Load Balancing interface call failed',
        'The peer application did not start SSL negotiations as expected',
        'MetadataServerBackupManifest', '\bLockedBy\b', '\bisLockedOut=0\b',
        'The Bridge Protocol Engine Socket Access Method lost contact with a peer',
    );
}

sub write_default_pattern_files {
    write_pattern_file($favorites_file, 'Favorite SAS Metadata Server patterns', [default_favorites()]);
    write_pattern_file($suppress_file, 'Suppressed/noisy patterns', [default_suppressions()]);
    print "Created $favorites_file and $suppress_file\n";
}

sub write_pattern_file {
    my ($file, $title, $patterns) = @_;
    return if -e $file;
    open(my $fh, '>', $file) or die "logdate: cannot create $file: $!\n";
    print $fh "# $title\n# One Perl-compatible regex per line.\n\n";
    print $fh "$_\n" for @$patterns;
    close($fh);
}

sub load_patterns {
    my ($file) = @_;
    return () unless defined $file && -f $file;
    open(my $fh, '<', $file) or do { warn "logdate: cannot read $file: $!\n"; return () };
    my @patterns;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+$//;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        my $ok = eval { qr/$line/i; 1 };
        $ok ? push(@patterns, $line) : warn "logdate: invalid regex ignored: $line\n";
    }
    close($fh);
    return @patterns;
}

sub analyze_file {
    my ($file) = @_;
    my %r = (
        file=>$file, size=>(-s $file || 0), begin=>undef, end=>undef,
        duration_ms=>undef, host=>'', ip=>'', ipv6_loopback=>0, ipv6_listen=>0, peer_ips=>[], norm_host=>'', name_host=>'', norm_name=>'',
        os=>'', release=>'', sas_version=>'', command=>'', trace=>0,
        trace_count=>0, debug_count=>0, info_count=>0, trace_ratio=>0,
        startup=>0, running=>0, stopped=>0, clustered=>0, not_master=>0, backup_completed=>0, normal=>0, no_cluster=>0, recover=>0,
        node=>'', node_number=>undef, master_node=>undef,
        lifecycle=>[], sample_redirect_count=>0,
        redirects=>[], redirect_count=>0, redirect_hosts=>'', norm_redirects=>'',
        ranges=>[], events=>[], favorites=>[], suppressed=>{},
        role=>'UNKNOWN', status=>'OK',
    );

    open(my $fh, '<', $file) or do { $r{status}="OPEN_ERROR: $!"; return \%r };
    binmode($fh);
    $r{begin}=find_begin($fh,$r{size});
    $r{end}=find_end($fh,$r{size});
    my $sample_size=$r{size}<$marker_bytes?$r{size}:$marker_bytes;
    analyze_sample(\%r,read_exact($fh,$sample_size),$file)
        if $sample_size>0 && defined sysseek($fh,0,0);

    my $tail_size=$r{size}<$marker_bytes?$r{size}:$marker_bytes;
    if (!$r{stopped} && $tail_size>0 && defined sysseek($fh,$r{size}-$tail_size,0)) {
        $r{stopped}=1 if read_exact($fh,$tail_size)=~/\bState,\s*stopped\b/i;
    }

    if ($details) {
        apply_scan(\%r,scan_log($fh,$file,1));
        $r{role}=cluster_role(\%r);
        $r{ranges}=build_ranges(\%r);
    } elsif (!$r{trace}) {
        apply_scan(\%r,scan_log($fh,$file,0));
        $r{role}=cluster_role(\%r);
    } else {
        $r{redirect_count}=$r{sample_redirect_count};
        $r{role}=cluster_role(\%r);
    }
    close($fh);

    if (defined $r{begin} && defined $r{end}) {
        my($b,$e)=(timestamp_ms($r{begin}),timestamp_ms($r{end}));
        if(defined$b&&defined$e){$r{duration_ms}=$e-$b;$r{status}='END_BEFORE_BEGIN' if$r{duration_ms}<0}
        else{$r{status}='BAD_TIMESTAMP'}
    }
    return \%r;
}

sub analyze_sample {
    my($r,$s,$file)=@_;
    $s =~ s/^\x{FEFF}//;
    if($s=~/Host:\s*'([^']+)'\s*,\s*OS:\s*'([^']*)'\s*,\s*Release:\s*'([^']*)'\s*,\s*SAS Version:\s*'([^']*)'\s*,\s*Command:\s*'([^']*)'/is){
        ($r->{host},$r->{os},$r->{release},$r->{sas_version},$r->{command})=($1,$2,$3,$4,$5);$r->{norm_host}=normalize_host($1)
    }elsif($s=~/Host:\s*'([^']+)'/i){$r->{host}=$1;$r->{norm_host}=normalize_host($1)}
    $r->{ip}=$1 if $s=~/Server is executing on host\s+[^\s]+\s+\(([0-9.]+)\)/i;
    $r->{ipv6_loopback}=1 if $s=~/Also known as:[\s\S]{0,500}?^\d{4}-.*?\s+::1\s*$/m;
    $r->{ipv6_listen}=1 if $s=~/Reserved IPv6 port 8561 for server listen/i;
    if($file=~/SASMeta_MetadataServer_[0-9T-]+_([A-Z0-9]+)_/i){$r->{name_host}=$1;$r->{norm_name}=normalize_host($1)}
    my $local_host = $r->{norm_host} || $r->{norm_name};
    my @sample_redirects = ($s =~ /redirect(?:ing)?[^\n]{0,500}?\bat\s+([A-Za-z0-9._-]+)/ig);
    $r->{sample_redirect_count} = scalar grep { !length($local_host) || normalize_host($_) ne $local_host } @sample_redirects;
    $r->{trace_count}=()=$s=~/^\d{4}-.*?\bTRACE\b/mg;
    $r->{debug_count}=()=$s=~/^\d{4}-.*?\bDEBUG\b/mg;
    $r->{info_count}=()=$s=~/^\d{4}-.*?\bINFO\b/mg;
    $r->{stopped}=1 if $s=~/\bState,\s*stopped\b/i;
    $r->{clustered}=1 if $s=~/\bCluster\s+SASMeta\s*-\s*Logical Metadata Server\b/i ||
                          $s=~/\bConnecting server\b.*?\bto cluster\b/i ||
                          $s=~/\bThe cluster has (?:achieved|lost) quorum\b/i;
    $r->{master_node}=$1 if $s=~/\bSetting the master node to\b.*?\bNode\s+(\d+)\b/i;
    $r->{not_master}=1 if $s=~/scheduled backup was not run.*not the master node/i;
    $r->{backup_completed}=1 if $s=~/The Backup has completed successfully/i;
    $r->{no_cluster}=1 if $s=~/\bstartNoCluster\b/i;
    $r->{recover}=1 if $r->{command}=~/\B-recover\b/i || $s=~/\B-recover\b/i;
    my$signal=$r->{trace_count}+$r->{debug_count};$r->{trace_ratio}=$signal/($r->{info_count}+1);
    $r->{trace}=($signal>0&&$signal>$r->{info_count})?1:0;
}

sub scan_log {
    my($fh,$file,$collect)=@_;
    my(@redirects,@events,@favorites,@lifecycle,%suppressed,%peer_seen,$node_number,$master_node);
    return{redirects=>[],events=>[],favorites=>[],lifecycle=>[],suppressed=>{}}
        unless defined sysseek($fh,0,0);
    my($ts,$seq)=(undef,0);
    while(my$line=<$fh>){
        $ts=$1 if$line=~/$TIMESTAMP_RE/;
        progress_scan_tick($fh, $file);
        next unless defined$ts;

        if($line=~/redirect(?:ing)?[^\n]{0,500}?\bat\s+([A-Za-z0-9._-]+)/i){
            my($target,$norm)=($1,normalize_host($1));
            my($node_number)=$line=~/\bNode\s+(\d+)\b[^\n]{0,200}?\bat\s+[A-Za-z0-9._-]+/i;
            push@redirects,{timestamp=>$ts,target=>$target,norm_target=>$norm,node_number=>$node_number,sequence=>$seq++,raw=>clean_line($line)} if length$norm;
        }

        if($line=~/\bSAH011001I\b.*?\bState,\s*starting\b/i){
            push@lifecycle,{timestamp=>$ts,type=>'STARTING',code=>'SAH011001I',sequence=>$seq++};
        }
        if($line=~/\bSAH011999I\b.*?\bState,\s*running\b/i){
            push@lifecycle,{timestamp=>$ts,type=>'RUNNING',code=>'SAH011999I',sequence=>$seq++};
        }
        if ($line =~ /Peer IP address and port are\s+\[(?:::ffff:)?([0-9.]+)\]:(\d+)/i) {
            my ($peer_ip, $peer_port) = ($1, $2);
            $peer_seen{$peer_ip} = 1 if $peer_port == 8561 || $line =~ /APPNAME=SAS Metadata Server/i;
        }
        $master_node=$1 if $line=~/\bSetting the master node to\b.*?\bNode\s+(\d+)\b/i;

        next unless$collect;
        my$event=classify_event($ts,$line,$seq++);push@events,$event if$event;
        my$suppressed_by=matches_any($line,@suppress_patterns ? @suppress_patterns : default_suppressions());
        $suppressed{$suppressed_by}++ if $suppressed_by;
        my$favorite=matches_any($line,@favorite_patterns ? @favorite_patterns : default_favorites());
        push@favorites,{timestamp=>$ts,pattern=>$favorite,text=>clean_line($line),sequence=>$seq++} if$favorite;
    }
    return{redirects=>\@redirects,events=>\@events,favorites=>\@favorites,lifecycle=>\@lifecycle,suppressed=>\%suppressed,peer_ips=>[sort keys%peer_seen],node_number=>$node_number,master_node=>$master_node};
}

sub matches_any { my($line,@patterns)=@_;for my$p(@patterns){return$p if eval{$line=~/$p/i}}return'' }

sub classify_event {
    my($ts,$line,$seq)=@_;my($type,$detail,$peer)=('','','');
    if($line=~/The outcall request did not complete in the time allotted/i){($type,$detail)=('OUTCALL_TIMEOUT','The outcall request did not complete in the time allotted.')}
    elsif($line=~/Lost contact with the server when calling an IOM interface/i){($type,$detail)=('IOM_CONTACT_LOST','Lost contact with the server when calling an IOM interface.')}
    elsif($line=~/could not send update to peer\s*\((?:[^)]*?\@)?([^\s)]+)/i){($type,$peer,$detail)=('PEER_UPDATE_FAILURE',normalize_host($1),'Could not send update to peer.')}
    elsif($line=~/Load Balancing interface call failed/i){($type,$detail)=('LOAD_BALANCER_WRAPPER','Generic Load Balancing failure wrapper.')}
    elsif($line=~/Disconnecting server\s+(.+?)\s+from cluster/i){($type,$peer,$detail)=('PEER_DISCONNECT',clean_value($1),'Server disconnected from cluster.')}
    elsif($line=~/Connecting server\s+(.+?)\s+to cluster/i){($type,$peer,$detail)=('PEER_CONNECT',clean_value($1),'Server connecting to cluster.')}
    elsif($line=~/Setting the master node to\s+(.+?)\.?\s*$/i){($type,$peer,$detail)=('MASTER_CHANGE',clean_value($1),'Setting the master node.')}
    elsif($line=~/Changing the master/i){($type,$detail)=('CHANGING_MASTER','Changing the master.')}
    elsif($line=~/cluster has lost quorum.*OFFLINE/i){($type,$detail)=('LOST_QUORUM','Cluster lost quorum and is now OFFLINE.')}
    elsif($line=~/cluster has achieved quorum.*ONLINE/i){($type,$detail)=('ACHIEVED_QUORUM','Cluster achieved quorum and is now ONLINE.')}
    elsif($line=~/The Backup has completed successfully/i){($type,$detail)=('BACKUP_COMPLETED','Scheduled backup completed successfully.')}
    elsif($line=~/scheduled backup was not run.*not the master node/i){($type,$detail)=('NOT_MASTER_BACKUP','Scheduled backup skipped because this node is not master.')}
    elsif($line=~/New out call client connection/i){($type,$detail)=('NEW_OUTCALL_CONNECTION','New peer out-call connection.')}
    elsif($line=~/Some updates are needed to make the metadata on server.*current/i){($type,$detail)=('SYNC_NEEDED','Metadata synchronization is required.')}
    elsif($line=~/Attempts to synchronize the metadata on this node.*failed/i){($type,$detail)=('SYNC_FAILURE','Metadata synchronization failed.')}
    elsif($line=~/most recent update on the connecting server.*not one of the updates/i){($type,$detail)=('REPOSITORY_MISMATCH','Connecting server update does not match cluster.')}
    elsif($line=~/failed to redirect/i){($type,$detail)=('FAILED_REDIRECT','Client redirect failed.')}
    else{return undef}
    my$identity=$1 if$line=~/\]\s+([^\s]+)\s+-/;
    return{timestamp=>$ts,type=>$type,detail=>$detail,peer=>$peer,identity=>($identity||''),sequence=>$seq,raw=>clean_line($line)};
}

sub apply_scan {
    my($r,$scan)=@_;
    my $local_host = $r->{norm_host} || $r->{norm_name};
    my @redirects = grep { !length($local_host) || $_->{norm_target} ne $local_host } @{$scan->{redirects}};
    $r->{redirects}=\@redirects;$r->{redirect_count}=scalar@redirects;
    $r->{events}=$scan->{events};$r->{favorites}=$scan->{favorites};
    $r->{lifecycle}=$scan->{lifecycle};$r->{suppressed}=$scan->{suppressed};
    $r->{peer_ips}=$scan->{peer_ips};
    $r->{master_node}=$scan->{master_node} if defined $scan->{master_node};
    $r->{not_master}=1 if grep { $_->{type} eq 'NOT_MASTER_BACKUP' } @{$r->{events}};
    $r->{backup_completed}=1 if grep { $_->{type} eq 'BACKUP_COMPLETED' } @{$r->{events}};
    $r->{clustered}=1 if defined $r->{master_node} || $r->{not_master};
    $r->{normal}=1 if $r->{backup_completed} && !$r->{not_master} && !$r->{redirect_count} && !$r->{clustered};
    $r->{startup}=scalar(grep{$_->{type}eq'STARTING'}@{$r->{lifecycle}})?1:0;
    $r->{running}=scalar(grep{$_->{type}eq'RUNNING'}@{$r->{lifecycle}})?1:0;
    my(%seen,@raw,@norm);for my$e(@{$r->{redirects}}){next if$seen{$e->{norm_target}}++;push@raw,$e->{target};push@norm,$e->{norm_target}}
    $r->{redirect_hosts}=join(', ',@raw)if@raw;$r->{norm_redirects}=join(', ',@norm)if@norm;
}

sub cluster_role { my($row)=@_;return'N'if$row->{normal}||$row->{no_cluster}||!$row->{clustered};return'S'if$row->{not_master};return'M'if defined$row->{node}&&length$row->{node}&&defined$row->{master_node}&&length$row->{master_node}&&$row->{node}==$row->{master_node};return'S' }

sub assign_node_numbers {
    my @rows = @_;
    my $summaries = host_summaries(@rows);
    for my $row (@rows) {
        my $host = host_key($row);
        $row->{node} = $summaries->{$host}{node};
    }
}

sub host_summaries {
    my @rows = @_;
    my %summaries;
    for my $row (@rows) {
        my $host = host_key($row);
        my $summary = $summaries{$host} //= {
            row => $row, logs => 0, clustered => 0, node_numbers => {}, node_source => '',
        };
        $summary->{logs}++;
        $summary->{clustered} ||= $row->{clustered};
        $summary->{row} = $row if !$summary->{row}{host} && $row->{host};
    }
    for my $row (@rows) {
        for my $redirect (@{$row->{redirects}}) {
            next unless defined $redirect->{node_number} && exists $summaries{$redirect->{norm_target}};
            $summaries{$redirect->{norm_target}}{node_numbers}{$redirect->{node_number}} = 1;
            $summaries{$redirect->{norm_target}}{node_source} = 'REDIRECT';
        }
    }
    for my $summary (values %summaries) {
        my @nodes = sort { $a <=> $b } keys %{$summary->{node_numbers}};
        $summary->{node} = $nodes[0] if @nodes == 1;
        $summary->{node_conflict} = @nodes > 1 ? 1 : 0;
    }
    my @cluster_hosts = grep { $summaries{$_}{clustered} && !$summaries{$_}{node_conflict} } keys %summaries;
    my @unmapped = sort grep { !defined $summaries{$_}{node} } @cluster_hosts;
    my %used_nodes = map { ($summaries{$_}{node} => 1) } grep { defined $summaries{$_}{node} } @cluster_hosts;
    my @available = grep { !$used_nodes{$_} } 1 .. 3;
    if (@cluster_hosts == 3 && @unmapped == @available) {
        for my $index (0 .. $#unmapped) {
            $summaries{$unmapped[$index]}{node} = $available[$index];
            $summaries{$unmapped[$index]}{node_source} = 'INFERRED';
        }
    }
    return \%summaries;
}

sub host_key { my($row)=@_;return$row->{norm_host}||$row->{norm_name}||$row->{file} }

sub build_ranges {
    my($r)=@_;my@e=sort{$a->{timestamp}cmp$b->{timestamp}||$a->{sequence}<=>$b->{sequence}}@{$r->{redirects}};return[]unless@e;
    my@effective;for my$x(@e){if(@effective&&$effective[-1]{timestamp}eq$x->{timestamp}){$effective[-1]=$x}else{push@effective,$x}}
    my@ranges;for my$x(@effective){if(@ranges&&$ranges[-1]{norm_target}eq$x->{norm_target}){$ranges[-1]{events}++;next}push@ranges,{start=>$x->{timestamp},norm_target=>$x->{norm_target},events=>1}}
    $ranges[0]{start}=$r->{begin}if defined$r->{begin};for my$i(0..$#ranges){$ranges[$i]{end}=$i<$#ranges?$ranges[$i+1]{start}:$r->{end}}return\@ranges;
}

sub print_server_lifecycle {
    my($r)=@_;
    print "\n  Server Lifecycle\n  ----------------\n";
    if(!@{$r->{lifecycle}}){print "  No SAH lifecycle markers found.\n";return}
    for my$e(sort{$a->{timestamp}cmp$b->{timestamp}||$a->{sequence}<=>$b->{sequence}}@{$r->{lifecycle}}){
        printf "  %-12s %-10s %s\n",time_only($e->{timestamp}),$e->{type},$e->{code};
    }
    my($starting)=grep{$_->{type}eq'STARTING'}@{$r->{lifecycle}};
    my($running)=grep{$_->{type}eq'RUNNING'}@{$r->{lifecycle}};
    if($starting&&$running){my$ms=timestamp_ms($running->{timestamp})-timestamp_ms($starting->{timestamp});print "  Startup Duration: ".format_duration($ms)."\n" if$ms>=0}
    elsif($starting&&!$running){print "  WARNING: Server started but never reached RUNNING state.\n"}
}

sub print_redirect_summary {
    my($r)=@_;print"\n  Redirect Activity Summary\n  BEGIN        END          ROLE      REDIRECTS TO         EVENTS\n  ------------ ------------ --------- -------------------- ------\n";
    my@x=@{$r->{ranges}};my$i=0;while($i<@x){if($x[$i]{events}==1){my$s=$i;$i++while$i<@x&&$x[$i]{events}==1;my$n=$i-$s;if($n>=$singleton_threshold){print_range($x[$s]);print_range($x[$s+1])if$n>1;my%t;$t{node_name($x[$_]{norm_target})}++for$s..$i-1;my$sum=join(', ',map{"$_=$t{$_}"}sort keys%t);printf"  ... %d repetitive single-event ranges suppressed (%s) ...\n",$n-3,$sum;print_range($x[$i-1])if$n>2}else{print_range($x[$_])for$s..$i-1}}else{print_range($x[$i]);$i++}}
}
sub print_range { my($x)=@_;printf"  %-12s %-12s %-9s %-20s %6d\n",time_only($x->{start}),time_only($x->{end}),'MASTER',node_name($x->{norm_target}),$x->{events} }

sub print_easy_incident_summary {
    my($r)=@_;my@e=grep{$_->{type}ne'LOAD_BALANCER_WRAPPER'}sort{$a->{timestamp}cmp$b->{timestamp}||$a->{sequence}<=>$b->{sequence}}@{$r->{events}};return unless@e;
    my(%count,%identities,%peers,%first);for my$x(@e){$count{$x->{type}}++;$first{$x->{type}}||=$x;$identities{$x->{identity}}=1 if$x->{identity};$peers{$x->{peer}}=1 if$x->{peer}}
    print"\n  Cluster Incident Summary\n  ------------------------\n";
    if($first{OUTCALL_TIMEOUT}){
        print"\n  *** FIRST FAILURE DETECTED ***\n\n";
        printf"  %s  OUTCALL TIMEOUT\n",time_only($first{OUTCALL_TIMEOUT}{timestamp});
        print"  The outcall request did not complete in the time allotted.\n";
        print"  This is the first indication that peer communication stopped responding.\n";
    }
    printf"\n  Window: %s -> %s\n",time_only($e[0]{timestamp}),time_only($e[-1]{timestamp});
    printf"  %-28s %6d\n",event_label($_),$count{$_}for grep{$count{$_}}qw(OUTCALL_TIMEOUT IOM_CONTACT_LOST PEER_UPDATE_FAILURE PEER_DISCONNECT MASTER_CHANGE LOST_QUORUM NEW_OUTCALL_CONNECTION PEER_CONNECT ACHIEVED_QUORUM SYNC_FAILURE REPOSITORY_MISMATCH FAILED_REDIRECT);
    print"  Peers: ".join(', ',sort keys%peers)."\n"if%peers;
    print"  Affected identities: ".join(', ',sort keys%identities)."\n"if%identities;
    print"\n  Reason Chain\n  ------------\n";
    my@order=qw(OUTCALL_TIMEOUT IOM_CONTACT_LOST PEER_UPDATE_FAILURE PEER_DISCONNECT MASTER_CHANGE LOST_QUORUM NEW_OUTCALL_CONNECTION PEER_CONNECT ACHIEVED_QUORUM);
    my@chain=grep{$first{$_}}@order;
    for my$i(0..$#chain){printf"  %-12s %s",time_only($first{$chain[$i]}{timestamp}),event_label($chain[$i]);print" ($count{$chain[$i]} related)"if$count{$chain[$i]}>1;print"\n";print"               |\n               v\n"if$i<$#chain}
    print"\n  Assessment\n  ----------\n";
    if($first{OUTCALL_TIMEOUT}){print"  Cluster communication exceeded the allotted response time.\n"}
    if($first{PEER_UPDATE_FAILURE}){print"  The cluster could not send updates to $first{PEER_UPDATE_FAILURE}{peer}.\n"}
    if($first{PEER_DISCONNECT}){print"  A peer was disconnected from the cluster.\n"}
    if($first{LOST_QUORUM}){print"  The cluster lost quorum and transitioned OFFLINE.\n"}
    if($first{ACHIEVED_QUORUM}){print"  The cluster later achieved quorum and returned ONLINE.\n"}
}

sub print_interesting_events {
    my($r)=@_;return unless@{$r->{favorites}}||%{$r->{suppressed}};
    print"\n  Interesting Log Events\n  ----------------------\n";
    my%group;for my$f(@{$r->{favorites}}){my$key=$f->{pattern};$group{$key}{count}++;$group{$key}{first}||=$f->{timestamp};$group{$key}{last}=$f->{timestamp}}
    for my$p(sort{$group{$a}{first}cmp$group{$b}{first}}keys%group){printf"  %-12s %-12s %6d  %s\n",time_only($group{$p}{first}),time_only($group{$p}{last}),$group{$p}{count},$p}
    if(%{$r->{suppressed}}){print"\n  Suppressed/Compacted Pattern Counts\n  -----------------------------------\n";printf"  %-6d %s\n",$r->{suppressed}{$_},$_ for sort keys%{$r->{suppressed}}}
}

sub print_verbose_events {
    my($r)=@_;return unless@{$r->{events}};print"\n  Verbose Cluster Events\n  ----------------------\n";
    for my$e(sort{$a->{timestamp}cmp$b->{timestamp}||$a->{sequence}<=>$b->{sequence}}@{$r->{events}}){printf"  %-12s %-24s %s\n",time_only($e->{timestamp}),$e->{type},$e->{detail};print"               Peer=$e->{peer}\n"if$e->{peer};print"               Identity=$e->{identity}\n"if$e->{identity};print"               $e->{raw}\n"}
}

sub print_cluster_findings {
    my @rows = @_;
    my %master_nodes;
    my $redirects = 0;
    for my $row (@rows) {
        $master_nodes{$row->{master_node}} = 1 if defined $row->{master_node} && length $row->{master_node};
        $redirects += $row->{redirect_count};
    }
    print "=== Cluster Findings ===\n";
    if (keys %master_nodes == 1) {
        my ($master) = keys %master_nodes;
        my ($master_row) = grep { defined $_->{node} && $_->{node} == $master } @rows;
        my $host = $master_row ? ($master_row->{host} || $master_row->{name_host}) : '?';
        print "Resolved master: " . node_label($master) . " ($host)\n";
    }
    elsif (keys %master_nodes > 1) {
        print "WARNING: Conflicting explicit master-node references: " . join(', ', map { node_label($_) } sort { $a <=> $b } keys %master_nodes) . "\n";
    }
    else {
        print "No explicit master-node reference found.\n";
    }
    print "Redirects observed: $redirects (client routing; not master-election evidence)\n\n";
}

sub print_split_brain_evidence {
    my ($first, $second, $start, $end) = @_;
    my @evidence;
    for my $candidate ($first, $second) {
        my $row = $candidate->{row};
        my $source = $candidate->{source};
        push @evidence, map {
            { timestamp => $_->{timestamp}, sequence => $_->{sequence}, source => $source, text => $_->{raw} }
        } grep { $_->{timestamp} ge $start && $_->{timestamp} le $end } @{$row->{events}};
        push @evidence, map {
            { timestamp => $_->{timestamp}, sequence => $_->{sequence}, source => $source, text => $_->{raw} || "Redirect to $_->{target}" }
        } grep { $_->{timestamp} ge $start && $_->{timestamp} le $end } @{$row->{redirects}};
    }
    return unless @evidence;

    print "  Relevant messages:\n";
    for my $entry (sort {
           $a->{timestamp} cmp $b->{timestamp}
        || $a->{sequence} <=> $b->{sequence}
        || $a->{source} cmp $b->{source}
    } @evidence) {
        printf "    %-23s %-18s %s\n", display_timestamp($entry->{timestamp}), $entry->{source}, $entry->{text};
    }
}

sub print_header {
    my($elapsed,@rows)=@_;my($bytes,$redirects,$events,$masters,$slaves,$standalone,$trace)=(0,0,0,0,0,0,0);for my$r(@rows){$bytes+=$r->{size};$redirects+=$r->{redirect_count};$events+=scalar@{$r->{events}};$trace+=$r->{trace};$r->{role}eq'M'?$masters++:$r->{role}eq'S'?$slaves++:$standalone++}my$mb=$bytes/1048576;
    printf"Analyzed %d logs | %.1f MB | %d redirects | %d cluster events | %.2f sec\n\n",scalar(@rows),$mb,$redirects,$events,$elapsed;
    print"========================================================================\nSAS Metadata Server Cluster Timeline Analysis\n========================================================================\n";
    printf"Mode                : %s\n",$verbose?'Verbose':'Detailed';
    printf"MASTER Nodes        : %d\nSLAVE Nodes         : %d\nSTANDALONE Nodes    : %d\nTRACE Logs          : %d\n",$masters,$slaves,$standalone,$trace;
    print"SAH Lifecycle       : ENABLED\nFirst Failure       : OUTCALL TIMEOUT PRIORITIZED\nLoad Balancing      : WRAPPER COMPACTED\n";
    printf"Elapsed Time        : %.2f sec\nMB / Second         : %.2f\n",$elapsed,$mb/$elapsed;
    print"========================================================================\n\n";
}

sub print_table {
    my@rows=@_;my$p='';my$prefix=$details?'':common_prefix(map{$_->{file}}@rows);
    printf"%-4s %-10s %-8s %-18s %-12s %-5s %-5s %-3s %-4s %-4s %-4s %s\n",'NODE','DATE','BEGIN','END','DURATION','TRACE','START','RUN','STOP','ROLE','RDIR','FILE';
    for my$r(@rows){my($bd,$bt)=split_timestamp($r->{begin});my($ed,$et)=split_timestamp($r->{end});my$d=($bd ne''&&$bd ne$p)?display_table_date($bd):'';$p=$bd if$bd ne'';my$end=$et||'N/A';$end="$ed T $et"if$ed ne''&&$bd ne''&&$ed ne$bd;my$file=$r->{file};$file=substr($file,length$prefix)if length$prefix;printf"%-4s %-10s %-8s %-18s %-12s %-5s %-5s %-3s %-4s %-4s %-4d %s",node_label($r->{node}),$d,table_time($bt),table_time($end),format_duration($r->{duration_ms}),$r->{trace}?'YES':'NO',$r->{startup}?'YES':'NO',$r->{running}?'YES':'NO',$r->{stopped}?'YES':'NO',$r->{role},$r->{redirect_count},$file;print" [$r->{status}]"if$r->{status}ne'OK';print"\n"}
}

sub print_node_table {
    my @rows = @_;
    my $summaries = host_summaries(@rows);
    my %ip_hosts;
    $ip_hosts{$_->{ip}} //= ($_->{host} || $_->{name_host} || 'N/A') for grep { $_->{ip} } @rows;

    print "=== Server Information ===\n";
    printf "%-4s %-4s %-8s %-20s %-15s %-6s %-4s %-14s %-34s %s\n", 'NODE', 'ROLE', 'MODE', 'HOST', 'IPV4', 'IPV6', 'OS', 'SAS', 'KERNEL', 'COMMAND';
    for my $summary (sort {
           node_sort_key($a->{node_conflict} ? 'conflict' : $a->{node} // 'unknown') <=> node_sort_key($b->{node_conflict} ? 'conflict' : $b->{node} // 'unknown')
        || host_key($a->{row}) cmp host_key($b->{row})
    } values %$summaries) {
        my $row = $summary->{row};
        my @host_rows = grep { host_key($_) eq host_key($summary->{row}) } @rows;
        printf "%-4s %-4s %-8s %-20s %-15s %-6s %-4s %-14s %-34s %s\n",
            node_label($summary->{node_conflict} ? undef : $summary->{node}),
            host_role($summary, @rows),
            host_mode($summary, @rows),
            $row->{host} || $row->{name_host} || 'N/A',
            host_value($summary, \@rows, 'ip') || 'N/A',
            (grep { $_->{ipv6_loopback} } @host_rows) ? '::1' : '-',
            short_os($row->{os}),
            short_sas($row->{sas_version}),
            $row->{release} || 'N/A',
            short_command($row->{command});
    }
}

sub print_marker_summary {
    my @rows = @_;
    my %ip_hosts;
    $ip_hosts{$_->{ip}} //= ($_->{host} || $_->{name_host} || 'N/A') for grep { $_->{ip} } @rows;

    print "=== Cluster Markers ===\n";
    printf "%-4s %-20s %3s %3s %4s %4s %3s %3s %3s %4s %4s %4s %4s %4s %s\n",
        'NODE', 'HOST', 'ST', 'RUN', 'JOIN', 'LEFT', 'MST', 'Q+', 'Q-', 'RDIR', 'SYNC', 'LB', 'BKP', 'BOK', 'METADATA PEERS';

    for my $summary (sort {
           node_sort_key($a->{node_conflict} ? 'conflict' : $a->{node} // 'unknown') <=> node_sort_key($b->{node_conflict} ? 'conflict' : $b->{node} // 'unknown')
        || host_key($a->{row}) cmp host_key($b->{row})
    } values %{host_summaries(@rows)}) {
        my @host_rows = grep { host_key($_) eq host_key($summary->{row}) } @rows;
        my (%counts, %peers);
        for my $row (@host_rows) {
            $counts{ST} += scalar grep { $_->{type} eq 'STARTING' } @{$row->{lifecycle}};
            $counts{RUN} += scalar grep { $_->{type} eq 'RUNNING' } @{$row->{lifecycle}};
            for my $event (@{$row->{events}}) {
                $counts{JOIN} += $event->{type} eq 'PEER_CONNECT';
                $counts{LEFT} += $event->{type} eq 'PEER_DISCONNECT';
                $counts{MST}  += $event->{type} eq 'MASTER_CHANGE';
                $counts{'Q+'} += $event->{type} eq 'ACHIEVED_QUORUM';
                $counts{'Q-'} += $event->{type} eq 'LOST_QUORUM';
                $counts{SYNC} += $event->{type} eq 'SYNC_NEEDED' || $event->{type} eq 'SYNC_FAILURE';
                $counts{LB}   += $event->{type} eq 'LOAD_BALANCER_WRAPPER';
                $counts{BKP}  += $event->{type} eq 'NOT_MASTER_BACKUP';
                $counts{BOK}  += $event->{type} eq 'BACKUP_COMPLETED';
            }
            $counts{RDIR} += $row->{redirect_count};
            $peers{$ip_hosts{$_} || $_} = 1 for @{$row->{peer_ips}};
        }
        printf "%-4s %-20s %3d %3d %4d %4d %3d %3d %3d %4d %4d %4d %4d %4d %s\n",
            $summary->{node_conflict} ? '?' : $summary->{node} // '-',
            $summary->{row}{host} || $summary->{row}{name_host} || 'N/A',
            (map { $counts{$_} || 0 } qw(ST RUN JOIN LEFT MST Q+ Q- RDIR SYNC LB BKP BOK)),
            join(', ', sort keys %peers) || '-';
    }
}

sub print_cluster_state_report {
    my @rows = @_;
    my @entries = cluster_state_entries(@rows);
    return unless @entries;

    my (%state, %claimed_master, @snapshots, @stale_redirects);
    my ($master, $quorum) = ('', 'UNKNOWN');
    my @groups;
    for my $entry (@entries) {
        my $time = short_timestamp($entry->{timestamp});
        if (!@groups || $groups[-1]{time} ne $time) {
            push @groups, { time => $time, entries => [] };
        }
        push @{$groups[-1]{entries}}, $entry;
    }

    print "=== Cluster State ===\n";
    for my $group (@groups) {
        my (%labels, $changed);
        for my $entry (@{$group->{entries}}) {
            my $row = $entry->{row};
            my $node = $row->{node};
            my $type = $entry->{type};
            my $label = '';

            if ($type eq 'STARTING') {
                $state{$node} = 'J' if defined $node;
                $label = node_label($node) . ' starting';
                $changed = 1;
            }
            elsif ($type eq 'RUNNING') {
                $state{$node} = 'O' if defined $node;
                $label = node_label($node) . ' running';
                $changed = 1;
            }
            elsif ($type eq 'PEER_CONNECT') {
                $state{$node} = 'O' if defined $node;
                $label = node_label($node) . ' joined';
                $changed = 1;
            }
            elsif ($type eq 'PEER_DISCONNECT') {
                $state{$node} = 'X' if defined $node;
                $label = node_label($node) . ' left';
                $changed = 1;
            }
            elsif ($type eq 'MASTER_CHANGE') {
                my $next_master = master_for_event($row, $entry->{event});
                if (defined $next_master) {
                    my $master_changed = !length($master) || $master != $next_master;
                    $master = $next_master;
                    $claimed_master{$node} = $next_master if defined $node;
                    $label = 'master=' . node_label($next_master) if $master_changed;
                    $changed ||= $master_changed;
                }
            }
            elsif ($type eq 'ACHIEVED_QUORUM' || $type eq 'LOST_QUORUM') {
                my $next_quorum = $type eq 'ACHIEVED_QUORUM' ? 'ONLINE' : 'OFFLINE';
                my $quorum_changed = $quorum ne $next_quorum;
                $quorum = $next_quorum;
                $label = 'quorum ' . $quorum if $quorum_changed;
                $changed ||= $quorum_changed;
            }
            elsif ($type eq 'SYNC_NEEDED') {
                $label = node_label($node) . ' synchronization needed';
            }
            elsif ($type eq 'SYNC_FAILURE') {
                $label = node_label($node) . ' synchronization failed';
            }
            elsif ($type eq 'LOAD_BALANCER_WRAPPER') {
                $label = node_label($node) . ' load-balancing failure';
            }
            elsif ($type eq 'NOT_MASTER_BACKUP') {
                $label = node_label($node) . ' backup skipped (not master)';
            }
            elsif ($type eq 'BACKUP_COMPLETED') {
                $label = node_label($node) . ' backup completed';
            }
            elsif ($type eq 'REDIRECT') {
                my $target = $entry->{redirect}{node_number};
                if (defined $node && defined $target && defined $master && length $master && $node != $master && $claimed_master{$node} && $claimed_master{$node} == $node && $quorum eq 'ONLINE') {
                    push @stale_redirects, { timestamp => $entry->{timestamp}, source => $node, target => $target };
                }
                next;
            }
            $labels{$label} = 1 if length $label;
        }

        print "  $group->{time}  " . join('; ', sort keys %labels) . "\n" if %labels;
        if ($changed) {
            push @snapshots, {
                time => $group->{time}, master => $master, quorum => $quorum,
                state => { %state },
            };
        }
    }
    print "\n";
    print_cluster_state_graph(\@snapshots, \@rows);
    print_stale_redirect_warnings(@stale_redirects);
}

sub cluster_state_entries {
    my @rows = @_;
    my %types = map { $_ => 1 } qw(PEER_CONNECT PEER_DISCONNECT MASTER_CHANGE ACHIEVED_QUORUM LOST_QUORUM SYNC_NEEDED SYNC_FAILURE LOAD_BALANCER_WRAPPER NOT_MASTER_BACKUP BACKUP_COMPLETED);
    my @entries;
    for my $row (@rows) {
        push @entries, map { { timestamp => $_->{timestamp}, sequence => $_->{sequence}, type => $_->{type}, event => $_, row => $row } } @{$row->{lifecycle}};
        push @entries, map { { timestamp => $_->{timestamp}, sequence => $_->{sequence}, type => $_->{type}, event => $_, row => $row } }
            grep { $types{$_->{type}} } @{$row->{events}};
        push @entries, map { { timestamp => $_->{timestamp}, sequence => $_->{sequence}, type => 'REDIRECT', redirect => $_, row => $row } }
            @{$row->{redirects}};
    }
    return sort {
           $a->{timestamp} cmp $b->{timestamp}
        || $a->{sequence} <=> $b->{sequence}
        || $a->{row}{file} cmp $b->{row}{file}
    } @entries;
}

sub print_cluster_state_graph {
    my ($snapshots, $rows) = @_;
    return unless @$snapshots;
    my @display = @$snapshots;
    my $omitted = @display > 8 ? @display - 8 : 0;
    @display = (@display[0 .. 3], @display[-4 .. -1]) if $omitted;
    my @nodes = sort { $a <=> $b } grep { defined } map { $_->{node} } @$rows;
    my %node_seen;
    @nodes = grep { !$node_seen{$_}++ } @nodes;

    print "=== Cluster State Graph ===\n";
    printf "%-8s", 'TIME';
    printf " %-9s", graph_time($_->{time}) for @display;
    print "\n";
    for my $node (@nodes) {
        printf "N%-7s", $node;
        printf " %-9s", $_->{state}{$node} || '.' for @display;
        print "\n";
    }
    printf "%-8s", 'QUORUM';
    printf " %-9s", $_->{quorum} eq 'UNKNOWN' ? '?' : $_->{quorum} for @display;
    print "\n";
    printf "%-8s", 'MASTER';
    printf " %-9s", length $_->{master} ? node_label($_->{master}) : '-' for @display;
    print "\n";
    print "  J=starting O=joined/running X=left/offline .=no state observed\n";
    print "  ... $omitted intermediate state changes omitted\n" if $omitted;
    print "\n";
}

sub print_stale_redirect_warnings {
    my @warnings = @_;
    return unless @warnings;
    print "=== Stale Master Redirects ===\n";
    for my $warning (@warnings) {
        printf "  %s  %s redirected clients to %s while another master held quorum\n",
            short_timestamp($warning->{timestamp}), node_label($warning->{source}), node_label($warning->{target});
    }
    print "\n";
}

sub print_cluster_timeline {
    my @rows = @_;
    my %node_hosts;
    my @entries;
    my %timeline_types = map { $_ => 1 } qw(
        PEER_CONNECT PEER_DISCONNECT MASTER_CHANGE LOST_QUORUM ACHIEVED_QUORUM
        SYNC_NEEDED SYNC_FAILURE REPOSITORY_MISMATCH FAILED_REDIRECT
    );

    for my $row (@rows) {
        my $host = $row->{host} || $row->{name_host} || 'N/A';
        $node_hosts{$row->{node}} //= $host if defined $row->{node};
        push @entries, map { { row => $row, event => $_ } }
            grep { $timeline_types{$_->{type}} } @{$row->{events}};
    }
    return unless @entries;

    @entries = sort {
           $a->{event}{timestamp} cmp $b->{event}{timestamp}
        || $a->{event}{sequence} <=> $b->{event}{sequence}
        || $a->{row}{file} cmp $b->{row}{file}
    } @entries;

    print "=== Cluster Timeline ===\n";
    printf "%-19s %-4s %-20s %-24s %-7s\n", 'TIME', 'NODE', 'EVENT', 'MASTER', 'QUORUM';

    my ($master_node, $quorum) = ('', '');
    for my $entry (@entries) {
        my $row = $entry->{row};
        my $event = $entry->{event};
        if ($event->{type} eq 'MASTER_CHANGE') {
            my $node = node_from_text($event->{peer});
            $master_node = $node if defined $node;
        }
        $quorum = 'ONLINE'  if $event->{type} eq 'ACHIEVED_QUORUM';
        $quorum = 'OFFLINE' if $event->{type} eq 'LOST_QUORUM';

        my $master = defined $master_node && length $master_node
            ? 'N' . $master_node . ' (' . ($node_hosts{$master_node} || '?') . ')'
            : '-';
        printf "%-19s %-4s %-20s %-24s %-7s\n",
            timeline_time($event->{timestamp}),
            defined $row->{node} ? 'N' . $row->{node} : 'N?',
            timeline_label($event->{type}),
            $master,
            $quorum || '-';
    }
    print "\n";
}

sub print_cluster_visual {
    my @rows = @_;
    my %lanes;
    my %hosts;
    my %timeline_types = map { $_ => 1 } qw(
        PEER_CONNECT PEER_DISCONNECT MASTER_CHANGE LOST_QUORUM ACHIEVED_QUORUM
        SYNC_NEEDED SYNC_FAILURE REPOSITORY_MISMATCH FAILED_REDIRECT
    );

    for my $row (@rows) {
        my $node = defined $row->{node} ? $row->{node} : 'unknown';
        $hosts{$node} //= $row->{host} || $row->{name_host} || 'N/A';
        push @{$lanes{$node}}, grep { $timeline_types{$_->{type}} } @{$row->{events}};
    }
    return unless keys %lanes;

    print "=== Cluster Visual ===\n";
    for my $node (sort { $a eq 'unknown' ? 1 : $b eq 'unknown' ? -1 : $a <=> $b } keys %lanes) {
        my @events = sort {
               $a->{timestamp} cmp $b->{timestamp}
            || $a->{sequence} <=> $b->{sequence}
        } @{$lanes{$node}};
        next unless @events;
        my $omitted = @events > 8 ? @events - 8 : 0;
        @events = @events[0 .. 7] if $omitted;
        my @steps = map { visual_event($_) } @events;
        push @steps, "+$omitted events" if $omitted;
        printf "N%-3s %-20s %s\n", $node eq 'unknown' ? '?' : $node, $hosts{$node}, join(' -> ', @steps);
    }
    print "\n";
}

sub node_from_text { my($text)=@_;return undef unless defined$text;return$1 if$text=~/\bNode\s+(\d+)\b/i;return undef }
sub node_label { my($node)=@_;return defined $node ? "N$node" : 'N?' }
sub host_value {
    my ($summary, $rows, $field) = @_;
    for my $row (grep { host_key($_) eq host_key($summary->{row}) } @$rows) {
        return $row->{$field} if defined $row->{$field} && length $row->{$field};
    }
    return '';
}
sub host_role {
    my ($summary, @rows) = @_;
    my @host_rows = grep { host_key($_) eq host_key($summary->{row}) } @rows;
    return 'M' if grep { $_->{role} eq 'M' } @host_rows;
    return 'S' if grep { $_->{role} eq 'S' } @host_rows;
    return 'N';
}
sub host_mode {
    my ($summary, @rows) = @_;
    my @host_rows = grep { host_key($_) eq host_key($summary->{row}) } @rows;
    return 'SINGLE' if grep { $_->{no_cluster} } @host_rows;
    return 'RECOVER' if grep { $_->{recover} } @host_rows;
    return $summary->{clustered} ? 'CLUSTER' : 'NORMAL';
}
sub host_flags {
    my ($summary, @host_rows) = @_;
    my @flags;
    push @flags, 'RECOVER' if grep { $_->{recover} } @host_rows;
    push @flags, 'SINGLE' if grep { $_->{no_cluster} } @host_rows;
    my %lifecycle;
    $lifecycle{$_->{type}} = 1 for map { @{$_->{lifecycle}} } @host_rows;
    push @flags, 'SAH:START' if $lifecycle{STARTING};
    push @flags, 'SAH:RUN' if $lifecycle{RUNNING};
    push @flags, 'SAH:STOP' if grep { $_->{stopped} } @host_rows;
    return @flags;
}
sub short_os { my($value)=@_;return'N/A'unless defined$value&&length$value;$value=~s/\s.*$//;return$value }
sub short_sas { my($value)=@_;return'N/A'unless defined$value&&length$value;$value=~s/^9\.04\.01M/94M/;return$value }
sub short_command { my($value)=@_;return'N/A'unless defined$value&&length$value;$value=~s/^['"]|['"]$//g;return$1 if$value=~m{\b(sasexe/sas\b.*)$};return$value }
sub master_for_event { my($row,$event)=@_;return node_from_text($event->{peer}) // $row->{master_node} // $row->{node} }
sub short_timestamp { my($timestamp)=@_;return'N/A'unless defined$timestamp;$timestamp=~s/^\d{4}-//;$timestamp=~s/T/ /;$timestamp=~s/,\d{3}$//;return$timestamp }
sub graph_time { my($timestamp)=@_;return'N/A'unless defined$timestamp;$timestamp=~s/^\d{2}-\d{2}\s+//;return$timestamp }
sub node_sort_key { my($node)=@_;return$node if$node=~/^\d+$/;return 9998 if$node eq'conflict';return 9999 }
sub timeline_time { my($timestamp)=@_;return'N/A'unless defined$timestamp;$timestamp=~s/T/ /;$timestamp=~s/,\d{3}$//;return$timestamp }
sub timeline_label { my($type)=@_;my%labels=(PEER_CONNECT=>'JOIN CLUSTER',PEER_DISCONNECT=>'LEAVE CLUSTER',MASTER_CHANGE=>'MASTER CHANGE',LOST_QUORUM=>'QUORUM LOST',ACHIEVED_QUORUM=>'QUORUM ONLINE',SYNC_NEEDED=>'SYNC NEEDED',SYNC_FAILURE=>'SYNC FAILURE',REPOSITORY_MISMATCH=>'REPOSITORY MISMATCH',FAILED_REDIRECT=>'REDIRECT FAILED');return$labels{$type}||event_label($type) }
sub visual_event { my($event)=@_;my$label=timeline_label($event->{type});if($event->{type}eq'MASTER_CHANGE'){my$node=node_from_text($event->{peer});$label=defined$node?"MASTER=N$node":$label}my$time=timeline_time($event->{timestamp});$time=~s/^\d{4}-\d{2}-\d{2}\s+//;return"$time $label" }

sub print_progress {
    my ($completed, $total, $elapsed, $fraction, $activity) = @_;
    my $overall = ($completed + $fraction) / $total;
    $overall = 1 if $overall > 1;
    my $percent = int($overall * 100);
    my $eta = $completed ? format_eta(($elapsed / $completed) * ($total - $completed)) : 'calculating';
    my @spinner = ('*', '+', 'x', '+');
    my $spin = $spinner[$progress_ticks++ % @spinner];
    my $width = 16;
    my $filled = int($overall * $width);
    my $bar = '#' x $filled . '.' x ($width - $filled);
    my $detail = $activity eq 'Complete' ? 'Complete' : "$activity " . progress_name($progress_file);
    printf STDERR "\r%-78s", "$spin [$bar] $completed/$total $percent% ETA $eta $detail";
    print STDERR "\n" if $completed == $total;
}

sub progress_scan_tick {
    my ($fh, $file) = @_;
    return unless $progress_total > 1;
    my $now = time();
    return if $now - $progress_last_tick < 0.5;
    $progress_last_tick = $now;
    my $size = -s $file || 1;
    my $position = tell($fh);
    my $fraction = defined $position && $position > 0 ? $position / $size : 0;
    print_progress($progress_completed, $progress_total, $now - $started, $fraction, 'Scanning');
}

sub progress_name { my($file)=@_;$file=~s{.*[\\/]}{};$file=substr($file,0,28).'...' if length$file>31;return$file }

sub format_eta { my($seconds)=@_;$seconds=int($seconds+0.5);my$hours=int($seconds/3600);$seconds%=3600;my$minutes=int($seconds/60);$seconds%=60;return sprintf'%02d:%02d:%02d',$hours,$minutes,$seconds }

sub table_time { my($value)=@_;return'N/A'unless defined$value&&length$value;$value=~s/,\d{3}\b//;return$value }
sub display_table_date { my($date)=@_;return''unless defined$date;my$current_year=(localtime)[5]+1900;return$date=~s/^$current_year-//r }
sub common_prefix { my@values=@_;return''unless@values;my$prefix=shift@values;for my$value(@values){my$length=length$prefix<length$value?length$prefix:length$value;my$index=0;$index++while$index<$length&&substr($prefix,$index,1)eq substr($value,$index,1);$prefix=substr($prefix,0,$index);last unless length$prefix}$prefix=~s/[^_\\\/]*$//;return$prefix }

sub read_exact { my($fh,$n)=@_;my($b,$o)=('',0);while($o<$n){my$c=sysread($fh,$b,$n-$o,$o);last if!defined$c||$c==0;$o+=$c}return$b }
sub find_begin { my($fh,$size)=@_;my($o,$c)=(0,'');while($o<$size){my$r=$size-$o;my$l=$r<$block_size?$r:$block_size;return undef unless defined sysseek($fh,$o,0);my$b=read_exact($fh,$l);last if$b eq'';my$d=$c.$b;return$1 if$d=~/$TIMESTAMP_RE/;$c=length($d)>128?substr($d,-128):$d;$o+=length$b}return undef }
sub find_end { my($fh,$size)=@_;my($o,$c)=($size,'');while($o>0){my$l=$o<$block_size?$o:$block_size;my$s=$o-$l;return undef unless defined sysseek($fh,$s,0);my$b=read_exact($fh,$l);last if$b eq'';my$d=$b.$c;my@t=($d=~/$TIMESTAMP_RE/g);return$t[-1]if@t;$c=length($d)>128?substr($d,0,128):$d;$o=$s}return undef }
sub timestamp_ms { my($t)=@_;return undef unless defined$t&&$t=~/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}),(\d{3})$/;my$e;eval{$e=timegm($6,$5,$4,$3,$2-1,$1)};return undef if$@;return$e*1000+$7 }
sub format_duration { my($m)=@_;return'N/A'unless defined$m;return'END<BEGIN'if$m<0;my$d=int($m/86400000);$m%=86400000;my$h=int($m/3600000);$m%=3600000;my$n=int($m/60000);$m%=60000;my$s=int($m/1000);my$x=$m%1000;my$c=sprintf'%02d:%02d:%02d.%03d',$h,$n,$s,$x;return$d?"$d+$c":$c }
sub split_timestamp { my($t)=@_;return('','')unless defined$t;return($1,$2)if$t=~/^(\d{4}-\d{2}-\d{2})T(.+)$/;return('',$t) }
sub normalize_host { my($h)=@_;return''unless defined$h;$h=~s/^['"]|['"]$//g;$h=~s/\s+$//;$h=lc$h;$h=~s/\..*$//;return$h }
sub time_only { my($t)=@_;return'N/A'unless defined$t;my(undef,$x)=split_timestamp($t);$x=~tr/,/./ if defined$x;return$x||'N/A' }
sub display_timestamp { my($t)=@_;return'N/A'unless defined$t;$t=~tr/,/./;return$t }
sub node_name { my($h)=@_;return'None'unless defined$h&&length$h;if($h=~/(\d+)$/){my$n=0+$1;return"Node $n"if$n>=1&&$n<=3}return$h }
sub clean_line { my($s)=@_;$s=~s/[\r\n]+$//;$s=~s/^\s+|\s+$//g;return$s }
sub clean_value { my($s)=@_;$s=clean_line($s);$s=~s/[.]$//;return$s }
sub event_label { my($s)=@_;$s=~s/_/ /g;return$s }
