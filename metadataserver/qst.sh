#!/bin/sh
# cd to the Logs directory
#
# 10/16/2017 Douglas Hunt
# 06/13/2025 major update using searchstring files for egrep but originating from this single script.
#
# Random thoughts, other strings to search for:
#  WAIT_LITTLE_HAMMER_DONE and 
# grep ' maximum decompressed entry size' *.log|awk -F: '{ print $6}’|sort -n|uniq 
# Encryption run-time execution error 
# Load Balancing interface call failed with exception:
# Invalid object specified to bridge protocol engine.
# Lost contact with the server when calling an IOM interface.
# The outcall request did not complete in the time allotted.
# 2020-01-28T06:03:54,722 WARN  [00034963] :sassrv - The load balancing processor could not send update to peer (A5LXCWOC.AY000002_@m3.sas.com)
# 2020-01-28T06:03:57,563 ERROR [00034963] :sassrv - The Balance algorithm timed out before a server could be found.
#########################################################################################################################
MYTMPDIR=.
TESTFILE=$MYTMPDIR/me
SEARCHSTRINGSPATH=$MYTMPDIR/my.favorite.strings
EXCLUDESTRINGS=$MYTMPDIR/my.least.favorite.strings
FNEXT=qst

mkdirtmp ()
{
	#if the directory exists try to create/touch a file - me
	if [ -d  $MYTMPDIR ] ; then 
		touch $TESTFILE
		if [ $? -ne 0 ]; then 
			echo Unable to create test file in $TESTFILE
			exit 1
		fi
	fi
	if [ ! -s $TESTFILE ] ; then rm -f $TESTFILE ; fi 
	
}
	
write_search_strings ()
{
if [ ! -f $SEARCHSTRINGSPATH ] ; then
echo writing: The list of keywords to search the $file is found in $SEARCHSTRINGSPATH
# So this means that you could edit the file if it exists for adding/removing searching strings
cat << EOF > $SEARCHSTRINGSPATH
A Backup has been started
AccessViolation
achieved quorum
An ALERT EMAIL was sent to
analyze and repair
APPNAME=SAS Metadata Server
Attempts to synchronize the metadata on this node with the cluster have failed
Backup has completed
Backup Thread
Bad file descriptor
Balance algorithm timed out
== Begin Import ==
bkAuthenticate failed
Broken pipe
Changing the master
CheckClusterHealth
- Cluster _NoCluster_ 
Connecting server
cookie jar
corrupted
critical
CRITICAL ERROR
damage
Disconnecting
disk is full
== End Import ==
End of file
failed to redirect
FATAL
flushes ID
FOMS
Hammer
HashPasswords=
ImportMetadata
in-flight updates
Insufficient 
internal error
INTERNAL ERROR
INTERNAL WARNING
Invalid Request to Authentication Server
i/o
iom:
Journal commit task is now terminating
Journal Entry
Journal Reload complete
Load Balancing interface call failed
load balancing processor could not send update to peer
locked
Lost contact
lost quorum
missing
most recent update on the connecting server is not one of the updates on the rest of the cluster
Negotiation
New out call client
piface
record-lev
Recover has 
REORG option was specified
RepairMetadataFiles
rewind
SAH011999I
SAH019999I
SAS Version: 
server deadlock
Server is executing on host
Server started with -recover
Setting the master
SHA256-10000
Some updates are needed
Some updates are needed to make the metadata
TCP\/IP
the master node
Thread wait timed out
Too many files are open
transaction has been journalled but will not be applied to the permanent repository
transferdata
unavailable
violation
EOF
fi
}

write_exclude_strings ()
{
if [ ! -f $EXCLUDESTRINGS ] ; then
echo writing: The list of keywords to exclude from the $file is found in $EXCLUDESTRINGS
cat << EOF > $EXCLUDESTRINGS
The peer application did not start SSL negotiations as expected.
MetadataServerBackupManifest
LockedBy
isLockedOut=0
The Bridge Protocol Engine Socket Access Method lost contact with a peer
EOF
fi
}

grepping()
{
#clean up previous run; we are overwriting.
if [ -f $file.qst ] ; then rm -f $file.qst ; fi

# write file name to top of qst file.
if [ -f "$file" ]; then
	echo "FILE: "$file > $file.qst
else
	echo "The file $file not found."
	exit 1
fi


egrep -if $SEARCHSTRINGSPATH $file |\
egrep -vif $EXCLUDESTRINGS  >> $file.qst
cat $file.qst

echo "'|egrep -v 'New client|New out' " 
echo
echo "Append the above line to end of of commandline, trying to minimize clutter"
egrep 'ERROR|WARN|FATAL' $file > $file.errorlist
echo writing out $file.errorlist 
echo writing out $file.qst
echo
}

# 1 time run
# Remember to check ulimits?  The Manifest errors are just usually ugly to look at.  
echo Reminders: check ulimits -a
echo We are going to egrep my favorite interesting strings.  As we learn more we add more strings to this program.
echo We are going to suppress some of my least favorite strings too.
echo

mkdirtmp

echo creating search and exception lists if none exists externally in a file.  Once created you can modify search criteria.
write_search_strings
write_exclude_strings

file=$1
while shift; do

# There is where we are egrepping and egrep notting using a file that was created from this script originally.
# You could modify the search files and make your own criteria.
# main program 
grepping

# shift the argument filename if multiples fn were given and loop back to the do/done loop.
file=$1

done

