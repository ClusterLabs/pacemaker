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


if ( $ARGV[0] =~ /--search/ ) {

    shift;
    print STDOUT "Result: ".string_search(@ARGV)."\n";

} elsif ( $ARGV[0] =~ /--command/ ) {
    shift;
    print STDOUT "Result: ".remote_command(@ARGV)."\n";

} else {
    print STDOUT "Unknown action:".$ARGV[0]."\n"

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

    my ($_search, $find_all, $max_lines, $_errors) = @_;

    my @search_for = split(/,/,$_search);
    my @errors     = split(/,/,$_errors);

    my %results    = {};
    my $num_lines  = 0;

    if($find_all eq "") {
	$find_all = 0;
    }
    if($max_lines eq "") {
	$max_lines = 0;
    }


    print STDOUT "findall: ".$find_all.", max: ".$max_lines."\n";

    foreach $line (<STDIN>)	
    {
	my $lpc = 0;
	$num_lines = $num_lines + 1;

#	print STDOUT "Checking line[".$num_lines."]: ".$line;

	if($max_lines > 0 && $num_lines > $max_lines) {
	    return -1000;
	}

	foreach $regex (@search_for) {
	    $lpc = $lpc +1;
	    if ( $line =~ /$regex/ ) {
		print STDOUT "Found match for (".$regex."): ".$line;
		if($find_all eq "0") {
		    return $lpc; 
		} else {
		    if( $results{$regex} ne "" ) {
			$results{$regex} = $results{$regex} + 1;
		    } else {
			$results{$regex} = 1;
		    }
		    $found = scalar(keys %results)-1;
#		    print STDOUT "Found ".$found." keys of ".scalar(@search_for)."\n";
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
#    print STDOUT "No more lines\n";
    return -2000;
}

