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

our $VERSION = '2.2.31';

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
my (%seen, @rows);

for my $file (grep { !$seen{$_}++ } @ARGV) {
    if (!-f $file) { warn "logdate: warning: not a regular file: $file\n"; next; }
    push @rows, analyze_file($file);
}
usage(1, 'no readable log files supplied') unless @rows;

@rows = sort {
       ($a->{begin} // '9999') cmp ($b->{begin} // '9999')
    || ($a->{end}   // '9999') cmp ($b->{end}   // '9999')
    || $a->{file} cmp $b->{file}
} @rows;

my $elapsed = time() - $started;
$elapsed = 0.000001 if $elapsed <= 0;
$details ? print_header($elapsed, @rows) : print "logdate $VERSION\n\n";
print_table(@rows);
print "\n";
print_node_table(@rows);
print "\n";

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
        duration_ms=>undef, host=>'', norm_host=>'', name_host=>'', norm_name=>'',
        os=>'', release=>'', sas_version=>'', command=>'', trace=>0,
        trace_count=>0, debug_count=>0, info_count=>0, trace_ratio=>0,
        startup=>0, running=>0, stopped=>0, lifecycle=>[], sample_redirect_count=>0,
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
        $r{role}=$r{redirect_count}?'MASTER':'SLAVE';
        $r{ranges}=build_ranges(\%r);
    } elsif (!$r{trace}) {
        apply_scan(\%r,scan_log($fh,$file,0));
        $r{role}=$r{redirect_count}?'MASTER':'SLAVE';
    } else {
        $r{redirect_count}=$r{sample_redirect_count};
        $r{role}=$r{redirect_count}?'MASTER-LIKELY':'UNKNOWN';
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
    if($file=~/SASMeta_MetadataServer_[0-9T-]+_([A-Z0-9]+)_/i){$r->{name_host}=$1;$r->{norm_name}=normalize_host($1)}
    $r->{sample_redirect_count}=()=$s=~/redirect(?:ing)?[^\n]{0,500}?\bat\s+[A-Za-z0-9._-]+/ig;
    $r->{trace_count}=()=$s=~/^\d{4}-.*?\bTRACE\b/mg;
    $r->{debug_count}=()=$s=~/^\d{4}-.*?\bDEBUG\b/mg;
    $r->{info_count}=()=$s=~/^\d{4}-.*?\bINFO\b/mg;
    $r->{stopped}=1 if $s=~/\bState,\s*stopped\b/i;
    my$signal=$r->{trace_count}+$r->{debug_count};$r->{trace_ratio}=$signal/($r->{info_count}+1);
    $r->{trace}=($signal>0&&$signal>$r->{info_count})?1:0;
}

sub scan_log {
    my($fh,$file,$collect)=@_;
    my(@redirects,@events,@favorites,@lifecycle,%suppressed);
    return{redirects=>[],events=>[],favorites=>[],lifecycle=>[],suppressed=>{}}
        unless defined sysseek($fh,0,0);
    my($ts,$seq)=(undef,0);
    while(my$line=<$fh>){
        $ts=$1 if$line=~/$TIMESTAMP_RE/;
        next unless defined$ts;

        if($line=~/redirect(?:ing)?[^\n]{0,500}?\bat\s+([A-Za-z0-9._-]+)/i){
            my($target,$norm)=($1,normalize_host($1));
            push@redirects,{timestamp=>$ts,target=>$target,norm_target=>$norm,sequence=>$seq++} if length$norm;
        }

        if($line=~/\bSAH011001I\b.*?\bState,\s*starting\b/i){
            push@lifecycle,{timestamp=>$ts,type=>'STARTING',code=>'SAH011001I',sequence=>$seq++};
        }
        if($line=~/\bSAH011999I\b.*?\bState,\s*running\b/i){
            push@lifecycle,{timestamp=>$ts,type=>'RUNNING',code=>'SAH011999I',sequence=>$seq++};
        }

        next unless$collect;
        my$event=classify_event($ts,$line,$seq++);push@events,$event if$event;
        my$suppressed_by=matches_any($line,@suppress_patterns ? @suppress_patterns : default_suppressions());
        $suppressed{$suppressed_by}++ if $suppressed_by;
        my$favorite=matches_any($line,@favorite_patterns ? @favorite_patterns : default_favorites());
        push@favorites,{timestamp=>$ts,pattern=>$favorite,text=>clean_line($line),sequence=>$seq++} if$favorite;
    }
    return{redirects=>\@redirects,events=>\@events,favorites=>\@favorites,lifecycle=>\@lifecycle,suppressed=>\%suppressed};
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
    elsif($line=~/New out call client connection/i){($type,$detail)=('NEW_OUTCALL_CONNECTION','New peer out-call connection.')}
    elsif($line=~/Attempts to synchronize the metadata on this node.*failed/i){($type,$detail)=('SYNC_FAILURE','Metadata synchronization failed.')}
    elsif($line=~/most recent update on the connecting server.*not one of the updates/i){($type,$detail)=('REPOSITORY_MISMATCH','Connecting server update does not match cluster.')}
    elsif($line=~/failed to redirect/i){($type,$detail)=('FAILED_REDIRECT','Client redirect failed.')}
    else{return undef}
    my$identity=$1 if$line=~/\]\s+([^\s]+)\s+-/;
    return{timestamp=>$ts,type=>$type,detail=>$detail,peer=>$peer,identity=>($identity||''),sequence=>$seq,raw=>clean_line($line)};
}

sub apply_scan {
    my($r,$scan)=@_;
    $r->{redirects}=$scan->{redirects};$r->{redirect_count}=scalar@{$scan->{redirects}};
    $r->{events}=$scan->{events};$r->{favorites}=$scan->{favorites};
    $r->{lifecycle}=$scan->{lifecycle};$r->{suppressed}=$scan->{suppressed};
    $r->{startup}=scalar(grep{$_->{type}eq'STARTING'}@{$r->{lifecycle}})?1:0;
    $r->{running}=scalar(grep{$_->{type}eq'RUNNING'}@{$r->{lifecycle}})?1:0;
    my(%seen,@raw,@norm);for my$e(@{$r->{redirects}}){next if$seen{$e->{norm_target}}++;push@raw,$e->{target};push@norm,$e->{norm_target}}
    $r->{redirect_hosts}=join(', ',@raw)if@raw;$r->{norm_redirects}=join(', ',@norm)if@norm;
}

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
    my@rows=@_;print"=== Cluster Findings ===\n";my@masters;for my$r(@rows){my$source=$r->{norm_host}||$r->{norm_name}||$r->{file};push@masters,map{+{%$_,source=>$source}}@{$r->{ranges}}}
    my$reported=0;OUTER:for my$i(0..$#masters-1){for my$j($i+1..$#masters){my($a,$b)=($masters[$i],$masters[$j]);next if$a->{source}eq$b->{source};my$s=$a->{start}gt$b->{start}?$a->{start}:$b->{start};my$e=$a->{end}lt$b->{end}?$a->{end}:$b->{end};next unless defined$s&&defined$e&&$s lt$e;print"WARNING: MASTER - SPLIT BRAIN POSSIBLE\n  Overlap: ".display_timestamp($s)." -> ".display_timestamp($e)."\n  MASTER: $a->{source}\n  MASTER: $b->{source}\n  ... additional split-brain overlaps suppressed\n\n";$reported=1;last OUTER}}
    print"No overlapping MASTER time ranges detected.\n\n"unless$reported;
}

sub print_header {
    my($elapsed,@rows)=@_;my($bytes,$redirects,$events,$masters,$slaves,$trace)=(0,0,0,0,0,0);for my$r(@rows){$bytes+=$r->{size};$redirects+=$r->{redirect_count};$events+=scalar@{$r->{events}};$trace+=$r->{trace};$r->{role}eq'MASTER'?$masters++:$slaves++}my$mb=$bytes/1048576;
    print"logdate $VERSION\n";printf"Analyzed %d logs | %.1f MB | %d redirects | %d cluster events | %.2f sec\n\n",scalar(@rows),$mb,$redirects,$events,$elapsed;
    print"========================================================================\nSAS Metadata Server Cluster Timeline Analysis\n========================================================================\n";
    printf"Mode                : %s\n",$verbose?'Verbose':'Detailed';
    printf"MASTER Nodes        : %d\nSLAVE Nodes         : %d\nTRACE Logs          : %d\n",$masters,$slaves,$trace;
    print"SAH Lifecycle       : ENABLED\nFirst Failure       : OUTCALL TIMEOUT PRIORITIZED\nLoad Balancing      : WRAPPER COMPACTED\n";
    printf"Elapsed Time        : %.2f sec\nMB / Second         : %.2f\n",$elapsed,$mb/$elapsed;
    print"========================================================================\n\n";
}

sub print_table {
    my@rows=@_;my$p='';my$prefix=$details?'':common_prefix(map{$_->{file}}@rows);
    printf"%-10s %-8s %-18s %-15s %-5s %-7s %-7s %-8s %-13s %-7s %s\n",'DATE','BEGIN','END','DURATION','TRACE','START','RUN','STOPPED','ROLE','RDIR','FILE';
    for my$r(@rows){my($bd,$bt)=split_timestamp($r->{begin});my($ed,$et)=split_timestamp($r->{end});my$d=($bd ne''&&$bd ne$p)?display_table_date($bd):'';$p=$bd if$bd ne'';my$end=$et||'N/A';$end="$ed T $et"if$ed ne''&&$bd ne''&&$ed ne$bd;my$file=$r->{file};$file=substr($file,length$prefix)if length$prefix;printf"%-10s %-8s %-18s %-15s %-5s %-7s %-7s %-8s %-13s %-7d %s",$d,table_time($bt),table_time($end),format_duration($r->{duration_ms}),$r->{trace}?'YES':'NO',$r->{startup}?'YES':'NO',$r->{running}?'YES':'NO',$r->{stopped}?'YES':'NO',$r->{role},$r->{redirect_count},$file;print" [$r->{status}]"if$r->{status}ne'OK';print"\n"}
}

sub print_node_table {
    my @rows = @_;
    print "=== Server Information ===\n";
    printf "%-20s %-12s %-34s %-20s %s\n", 'HOST', 'OS', 'KERN', 'SAS VERSION', 'COMMAND';
    for my $row (@rows) {
        printf "%-20s %-12s %-34s %-20s %s\n",
            $row->{host} || $row->{name_host} || 'N/A',
            $row->{os} || 'N/A',
            $row->{release} || 'N/A',
            $row->{sas_version} || 'N/A',
            $row->{command} || 'N/A';
    }
}

sub table_time { my($value)=@_;return'N/A'unless defined$value&&length$value;$value=~s/,\d{3}\b//;return$value }
sub display_table_date { my($date)=@_;return''unless defined$date;my$current_year=(localtime)[5]+1900;return$date=~s/^$current_year-//r }
sub common_prefix { my@values=@_;return''unless@values;my$prefix=shift@values;for my$value(@values){my$length=length$prefix<length$value?length$prefix:length$value;my$index=0;$index++while$index<$length&&substr($prefix,$index,1)eq substr($value,$index,1);$prefix=substr($prefix,0,$index);last unless length$prefix}return$prefix }

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
