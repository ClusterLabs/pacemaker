#!/bin/sh


### main script

pid=$1

logdir=/root
now=$(date '+%Y%m%d_%H%M%S')
log=$logdir/ra-debug_${now}.log

exec > $log
exec 2>&1

echo "Started: $(date '+%s.%N')"
echo "Passed pid $pid"

ps -o uid,ruid,pid,ppid,pgid,sess,state,tty,psr,pcpu,etimes,cputime,wchan,args  -He

for p in $(pgrep -g $pid)
do
         echo "======================"
         echo "Getting user stack for pid $p $(</proc/$p/comm)"
         gstack $p
         echo "Getting kernel stack for pid $p"
         cat /proc/$p/stack
done

echo "Finished: $(date '+%s.%N')"
exit 0

