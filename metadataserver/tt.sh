#!/bin/bash
# Date originally written: 07/18/2018
# Douglas Hunt
# 
# program name: tt
# Why did I call it 'tt'?  I don't know but I'm going to say it's short for 'Til Tomorrow' cause it sounds cool.
#
# arguments: 
# -t threshold in seconds
# -l lines per dot
# filename (ie: SASMetadataServer*.log)
# 
#---------------------------------------
#
thisyear=`date +%Y`
defaultfline=00:00:00,000
epoch='1970-01-01T'
threshold=30
linecounter=10
verbose=0
x=0
y=0
z=0

if (($# != 0)); then
while getopts ":t:l:v:" opt; do
case $opt in
  t)
	threshold=$OPTARG
    ;;
  l)
	linecounter=$OPTARG
    ;;
  v)
	verbose=1
    ;;
  \?)
    echo "Invalid option: -$OPTARG" >&2
    exit 1
    ;;
  :)
    echo "Option -$OPTARG requires an argument." >&2
    exit 1
    ;;
esac
done
shift $((OPTIND-1))   # remove parsed options and args from $@ list
fi

if [ "$1" == "" ]; then
	echo 
	echo 'Til Tommorrow (tt)'
	echo ------------------
        echo `basename $0` "[options] filename"
	echo
	echo ie: SASMeta_MetadataServer_2018-07-15_TheHost_16386.log required
	echo
	echo Options:
	echo "-t #  threshold_in_seconds default=$threshold"
	echo "-l #  prints . (dots) for number of lines between gaps.  lines_per_dot=$linecounter"
	echo "-v 1  for verbose of all the small out of orders default=0"
	echo
	echo '
If the log contains the date time format of YYYY-MM-DDTHH:MM:SS,mss ,like many SAS logs do,
this program will calculate the time difference between adjacent lines. 
If the difference (gap range) is above the threshold of seconds (-t seconds) it will print "LineN to LineN+1 gap (seconds)"
else the program prints dot(s) indicating groups of lines (-l linecounter) that do not have a gap.

It is possible for the SAS logger to print lines out of order.  If this happens a lot the concern is that something is stuck or underpowered. 
If the out of order magnitude is less than negative 1 second I count those being mostly concerned by the larger negative values.
If there are a lot of out of orders you maybe more concerned rather than just a few.
'
echo 
	echo Example:
	echo 2019-10-02T04:46:24,029 INFO ...
	echo 2019-10-02T04:46:29,053 INFO ...
	echo 2019-10-02T04:46:29,432 INFO ...
echo
echo '$ tt -t 5 -l 1000 SASMeta_MetadataServer_2019-10-02_n1_44807.log
-----
SASMeta_MetadataServer_2019-10-02_n1_44807.log
Lines per printed dot (.): 1000
Start time: 00:00:03,794 End time: 23:59:59,811
Threshold=5 seconds

.................04:46:24,029 to 04:46:29,053 gap (5.024)
04:46:49,017 to 04:46:54,019 gap (5.002)
04:46:54,019 to 04:46:49,422 out of order! (-4.597)
................................................
65441 Total lines with time.
1 were significant Out of order (<-1 second)! (1 out of order were between 0 to -1 second.)
2 Incidents of adjacent lines exceeded the 5 second threshold.
-----'
	echo
	exit 1
fi

metadatalog=$1
thisyear=`head -3 $1| tail -1 | awk -F\- '{ print $1}'`
if [ $thisyear -lt 1999 ] ; then exit 1; fi
while shift; do

if [ ! -f $metadatalog ] ; then 
	echo $metadatalog Metadata Server log not found
	exit 1
fi

x=0
y=0
z=0
oo=0
maxgap=0

echo
echo -----
echo $metadatalog


filename=$metadatalog.times

/bin/awk 'BEGIN{IGNORECASE=1} ($0>=from&&$0<=to)' from="$thisyear-01-01" to="$thisyear-12-31" $metadatalog|\
/bin/awk -F\T '$2!=""{print $2}'|\
/bin/awk '{print $1}' > $filename

fline=`head -1 $filename`
eline=`tail -1 $filename`

echo 'Lines per printed dot (.): '$linecounter
echo Start time:  $fline     End time: $eline
echo Threshold=$threshold  seconds  
echo

/bin/awk '
BEGIN { woo=0;oo=0;y=0;totallines=0;prev=0;maxgap=0;maxdiff=0}

function timetomin(time) {
  split(time ,a,":");
  split(a[3],subsec,",");
#  manyseconds=a[1]*3600 + a[2]*60 + subsec[1] + subsec[2]*.001;
#printf("a[1]=%s a[2]=%s a[3]=%s subsec1=%s subsec2=%s\n",a[1],a[2],a[3],subsec[1],subsec[2]);
#printf("input=%s  output=%s\n",time, manyseconds);
#return(manyseconds);
return sprintf("%.3f\n",a[1] * 60 * 60 + a[2] * 60 + subsec[1] + subsec[2]*.001);
}

{ 
if ($0=="") exit;

     # save current for later using
     longcurr=$0;
     curr=timetomin(longcurr);

     # do something
	if (prev!=0) {diff=curr-prev;}

if (diff > -1 && diff<0 ) {
	woo++;
	if (1=='"${verbose}"') { printf("%s to %s out of order! (%s)\n",longprev,longcurr,diff);};
  } else  {
	if (diff<0) {oo++;printf("%s to %s out of order! (%s)\n",longprev,longcurr,diff);};
  }

if (diff>maxdiff) {maxdiff=diff};

if (diff>'"${threshold}"') {
	y++;printf("%s to %s gap (%s)\n",longprev,longcurr,diff);
#	if (diff>maxgap) {maxgap=diff;};
};
if (x=='"${linecounter}"') {printf(".");x=0};

     # and return current line
     prev=curr;
     longprev=longcurr;

x++
totallines++
}
END { printf "\n%s Total lines with time.\n%s were significant Out of order (<-1 second)!\
 (%s out of order were between 0 to -1 second.)\n%s Incidents of adjacent lines exceeded the '"${threshold}"' second threshold.\
 \nMaximum gap is %s seconds\n",totallines,oo,woo,y,maxdiff;}' \
< $filename

rm $filename
echo -----
echo

metadatalog=$1

done

exit

