#!/usr/bin/perl

 # Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

$in_exp=0;
$in_err_exp=0;
$match_all=0;
$max_lines=0;
$log_file="/var/log/messages";
$start_pos=-1;

@search_for = ();
@errors     = ();

while ( $_ = @ARGV[0], /^-/ ) {
    shift;
    if ( /^--search/ ) {
	$do_search = 1 ;

    } elsif ( /^-p/ ) {
	$start_pos = $ARGV[0];
	shift;

    } elsif ( /^-m/ ) {
	$max_lines = $ARGV[0];
	shift;

    } elsif ( /^-l/ ) {
	$log_file = $ARGV[0];
	shift;

    } elsif (  /^-a/ ) {
	$match_all = 1;

    } elsif ( /^-s/ ) {
	$this_exp="";
	while( @ARGV ) {
	    last if $ARGV[0] =~ /^-/;
	    $this_exp=$this_exp." ".$ARGV[0];
	    shift;
	}
	$this_exp=substr($this_exp, 1);
#	print STDOUT "Found search expression: _${this_exp}_\n";
	push @search_for, $this_exp;

    } elsif ( /^-e/ ) {
	$this_exp="";
	while( @ARGV ) {
	    last if $ARGV[0] =~ /^-/;
	    $this_exp=$this_exp." ".$ARGV[0];
	    shift;
	}
	$this_exp=substr($this_exp, 1);
#	print STDOUT "Found error expression: _${this_exp}_\n";
	push @errors, $this_exp;
    } else {
	print STDOUT "huh? $_\n";
    }
}

if( $do_search eq 1 ) {
    $rc=string_search();
    print STDOUT "Search returned: $rc\n";
    exit $rc;
}

sub remote_command() {
    my ($user, $host, @command) = @_;

    my $args = "";

    foreach $arg ( @command ) {
	$args = $args." ".$arg;
    }

    print STDOUT "Running \'".$args."\' as ".$user."@".$host."\n";
    $rc = system "/usr/bin/ssh", "-l", $user, $host, $args;
    return $rc;
}


sub string_search() {

    my %results    = {};
    my $num_lines  = 0;

    open(LOG, $log_file);

    if( $start_pos > 0 ) {
	print STDOUT "Starting search in $log_file from position $start_pos...\n";
	seek LOG, $start_pos, 0
    } else {
	print STDOUT "Starting search in $log_file from EOF...\n";
	seek LOG, 0, 2;
    }

    for(;;)
    {
#	print STDOUT "Checking $log_file for more data...\n";
	for($curpos = tell LOG; $_ = <LOG>; $curpos = tell LOG) 
	{
	    my $lpc = 0;
	    $line = $_;
	    $num_lines = $num_lines + 1;
	    
#	    print STDOUT "Checking line[".$num_lines."]: ".$line;
	    
	    if($max_lines > 0 && $num_lines > $max_lines) {
		return -1000;
	    }
	    
	    foreach $regex (@search_for) {
		$lpc = $lpc +1;
		if ( $line =~ /$regex/ ) {
		    if($match_all eq "0") {
			print STDOUT "Found match for (".$regex."): \n\t".$line;
			return $lpc; 
		    } else {
			if( $results{$regex} ne "" ) {
			    $results{$regex} = $results{$regex} + 1;
			} else {
			    $results{$regex} = 1;
			}
			$found = scalar(keys %results)-1;
			print STDOUT "[line $num_lines]: Found match ".$found." of ".scalar(@search_for)." for (".$regex."): \n\t".$line;

			if(scalar(@search_for) < scalar(keys %results)) {
			    
			    foreach $key (sort keys %results) {
				print STDOUT "Found key \'".$key."\' ".$results{$key}." times.\n" if $results{$key} ne "";
			    }
			    return 0;
			}
		    }
		}
	    }
	    
	    $lpc = 0;
	    foreach $regex ( @errors ) {
		$lpc = $lpc +1;
		if ( $line =~ /$regex/ ) {
		    print STDOUT "Found ERROR match for (".$regex."): ".$line;
		    return 0-$lpc;
		}
	    }
	}
	sleep 3;
	seek LOG, $curpos, 0;
    }
#    print STDOUT "No more lines\n";
    return -2000;
}

