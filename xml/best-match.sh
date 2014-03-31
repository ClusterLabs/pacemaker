#!/bin/bash

base=$1; shift
target=$1; shift
best="0.0"
candidates=$(ls -1 ${base}-*.rng 2>/dev/null)
for rng in $candidates; do
    case $rng in
	${base}-${target}.rng)
	    echo $rng
	    exit
	    ;;
	*next*)
	    : skipping $rng
	    ;;
	*) 
	    v=$(echo $rng | sed -e "s/${base}-//" -e 's/.rng//')
	    : comparing $v with $target

	    rc=$(echo "$v > ${best}" | bc)
	    if [ $rc = 1 ]; then
		: $v beats the previous ${best} for $target
		if [ ${target} = next ]; then
		    best=$v
		else
		    rc=$(echo "$v < ${target}" | bc)
		    if [ $rc = 1 ]; then
			: $v is still less than $target, using
			best=$v
		    fi
		fi
	    fi
	    ;;
    esac
done
if [ "x${best}" != "x0.0" ]; then
    echo ${base}-${best}.rng
else
    echo "empty.rng"
fi
