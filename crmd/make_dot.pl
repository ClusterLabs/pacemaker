#!/bin/perl
 
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

# generates a transition graph based on the crmd_fsa_state array in 
# fsa_matrix.h and an actions graph of sorts based on the crmd_fsa_actions
# array also in fsa_matrix.h.

$do_links2self=1;

$input_file = $ARGV[0];
$output_dir = $ARGV[1];
make_inputs_dot($input_file, $output_dir."/fsa_inputs.dot", "const enum crmd_fsa_state crmd_fsa_state", "const long long crmd_fsa_actions");

make_actions_dot($input_file, $output_dir."/fsa_actions_by_state.dot", $output_dir."/fsa_inputs_by_action.dot", "const long long crmd_fsa_actions", "ELSEIF_INVOKE_FSA_ACTION");

sub make_inputs_dot
{
    my ($input, $output, $start, $stop) = @_;

    my $duplicate_edges;
    my $self_links;
    my $illegal_links;
    my $nothing_links;
    my $warn_links;

    my $filename=$input;
    my $filedesc=INPUT_FD;
    unless (open($filedesc, $filename)) {
	print STDERR "Can't open $filename: $!\n";
    }
    
    my $seen_start = 0;
    my $input = "";
    my @lines = <INPUT_FD>;
    my %HoH = {};
    
    my $intro = 'digraph "g" {
	size = "30,30"
	graph [
		fontsize = "12"
		fontcolor = "black"
		bb = "0,0,398.922306,478.927856"
		color = "black"
	]
	node [
		fontsize = "12"
		fontcolor = "black"
		shape = "ellipse"
		color = "black"
	]
	edge [
		fontsize = "12"
		fontcolor = "black"
		color = "black"
	]
// special nodes
	"Any State" [ fontcolor="white" fillcolor="black" style="filled" ]
	"S_PENDING" [ color = "blue" fontcolor = "blue" ]
	"S_TERMINATE" [ color = "red" fillcolor = "red" style="filled" ]
	"S_STOPPING" [ color = "red" fillcolor = "red" style="filled" ]
	"S_RECOVERY" [ color = "orange" fillcolor = "orange" style="filled" ]
	"S_HALT" [ color = "#eeee55" fillcolor = "#eeee55" style="filled" ]
	"S_ELECTION" [ color = "purple" fillcolor = "purple" style="filled" ]
	"S_RELEASE_DC" [ color = "grey" fillcolor = "grey" style="filled" ]

// DC only nodes
	"S_INTEGRATION" [ fillcolor = "#33dd33" style="filled" ]
	"S_FINALIZE_JOIN" [ fillcolor = "#33dd33" style="filled" ]
	"S_POLICY_ENGINE" [ color = "royalblue" fillcolor = "royalblue" style="filled" ]
	"S_TRANSITION_ENGINE" [ fillcolor = "#33dd33" style="filled" ]
	"S_IDLE" [ fillcolor = "#33dd33" style="filled" ]
';

    
    $outro = '}
';
    
    
    $filename=$output;
    $filedesc=DOT_FD;
    
    unless (open($filedesc, '>',$filename)) {
	print STDERR "Can't open $filename: $!\n";
    }
    print DOT_FD $intro;
    
    
    foreach $line (@lines)	
    {
	$seen_start=1 if($line =~ /$start/);
	$seen_start=0 if($line =~ /$stop/);
	
	
	if($seen_start == 1)
	{
	    my $is_input = 0;
	    my $is_transition = 0;
	    
	    $is_input = 1 if($line =~ / Got an I_/);
	    $is_transition = 1 if($line =~ /==\>/);
	    
	    if($is_input == 1)
	    {
		$input = $line;
		$input =~ s/.*Got an //;
		$input =~ s/\ \*\///;
		chop($input);
	    }
	    
	    if($is_transition == 1)
	    {
		@bits = split(/\s/, $line);
		
		$state1 = @bits[3];
		$state2 = @bits[7];
		
		if("$state2" eq "")
		{
		    # for some reason it ends up in @bits[6] sometimes
		    $state2 = @bits[6]; 
		}
		
		chop($state2);

		if($do_links2self && $state1 eq $state2)
		{
		    $self_links = $self_links+1;
		}
		else
		{
		    if( $state1 eq $state2 )
		    {
			$self_links = $self_links+1;
		    }

		    if( $input eq "I_TERMINATE" ) 
		    {
		    } 
		    elsif( $input eq "I_STOP" )
		    {
		    } 
		    elsif( $input eq "I_RELEASE_FAIL" )
		    {
		    } 
		    elsif( exists($HoH{$state1}) )
		    {
			$rec = $HoH{$state1};

			if( $HoH{$state1}{$state2} ne "" )
			{
			    $oldval = $HoH{$state1}{$state2};
			    $rec->{$state2} = $oldval.",\\n".$input;
			    $duplicate_edges = $duplicate_edges + 1;
			}
			else
			{
			    $rec->{$state2} = $input;
			}
		    }
		    else
		    {
			$rec = {};
			$HoH{$state1} = $rec;
			$rec->{$state2} = $input;
		    }
		}
	    }
	    
	}
    }


# print the whole thing  somewhat sorted
    foreach $state_from ( sort keys %HoH ) {
#     print "$state_from: { ";
	for $state_to ( sort keys %{ $HoH{$state_from} } ) {
	    
	    $color="black";
	    $color="red"       if $state_to =~ /STOPPING/;
	    $color="red"       if $state_to =~ /TERMINATE/;
	    $color="orange"    if $state_to =~ /RECOVERY/;
	    $color="#eeee55"    if $state_to =~ /HALT/;
	    $color="blue"      if $state_to =~ /PENDING/;
	    $color="purple"    if $state_to =~ /ELECTION/;
	    $color="royalblue" if $state_to =~ /POLICY/;
	    $color="gray"      if $state_to =~ /RELEASE/;


	    print DOT_FD "\"".$state_from."\" -> \"".$state_to."\" [ color=\"$color\" fontcolor=\"$color\" label = \"$HoH{$state_from}{$state_to}\" ]\n";    

#	    print DOT_FD "\"".$state_from."\" -> \"".$state_to."\" [ label = \"$HoH{$state_from}{$state_to}\" ]\n";    
#         print "$state_to=$HoH{$state_from}{$state_to} ";
	}
#     print "}\n";
    }

    $color="red";
    print DOT_FD "\"Any State\" -> \"S_STOPPING\" [ color=\"$color\" fontcolor=\"$color\" label = \"I_STOP\" ]\n";    
    print DOT_FD "\"Any State\" -> \"S_STOPPING\" [ color=\"$color\" fontcolor=\"$color\" label = \"I_RELEASE_FAIL\" ]\n";    
    print DOT_FD "\"Any State\" -> \"S_TERMINATE\" [ color=\"$color\" fontcolor=\"$color\" label = \"I_TERMINATE\" ]\n";    
    

    print DOT_FD $outro;

    close(DOT_FD);
    close(INPUT_FD);

    print "\n$output Done...\n";
    print "Saved $duplicate_edges duplicate edges\n";
    print "Saved $self_links links to self\n";
}


sub make_actions_dot
{
    my ($input, $output1, $output2, $start, $stop) = @_;

    my $duplicate_edges;
    my $self_links;
    my $illegal_links;
    my $nothing_links;
    my $warn_links;

    my $filename=$input;
    my $filedesc=INPUT_FD;
    unless (open($filedesc, $filename)) {
	print STDERR "Can't open $filename: $!\n";
    }
     
    my $seen_start = 0;
    my $input = "";
    my @lines = <INPUT_FD>;
    my %HoH = {};
    my %HoH2 = {};
    
    my $intro = 'digraph "g" {
	rankdir = LR
//	size = "30,30"
	graph [
		fontsize = "12"
		fontname = "Times-Roman"
		fontcolor = "black"
		bb = "0,0,398.922306,478.927856"
		color = "black"
	]
	node [
		fontsize = "12"
		fontname = "Times-Roman"
		fontcolor = "black"
		shape = "ellipse"
		color = "black"
	]
	edge [
		fontsize = "12"
		fontname = "Times-Roman"
		fontcolor = "black"
		color = "black"
	]

';
    
    $outro = '}
';
    
    
    
    foreach $line (@lines)	
    {
	
	
	$seen_start=1 if($line =~ /$start/);
	$seen_start=0 if($line =~ /$stop/);
	
	
	if($seen_start == 1)
	{
	    my $is_input = 0;
	    my $is_transition = 0;
	    
	    $is_input = 1 if($line =~ / Got an I_/);
	    $is_transition = 1 if($line =~ /==\>/);
	    
	    if($is_input == 1)
	    {
		$input = $line;
		$input =~ s/.*Got an //;
		$input =~ s/\ \*\///;
		chop($input);
	    }
	    
	    if($is_transition == 1)
	    {
		@bits = split(/\s/, $line);
		
		$state1 = @bits[3];
		$state2 = @bits[7];
		
		if("$state2" eq "")
		{
		    # for some reason it ends up in @bits[6] sometimes
		    $state2 = @bits[6]; 
		}

		chop($state2);

		
		
		@actions = split(/\|/, $state2);
		
		foreach $action ( sort @actions )
		{

		    $key1 = $state1;
		    $key2 = $input." {".$state1."}";
		    $value = $action;

		    if( exists($HoH{$key1}) )
		    {
			$rec = $HoH{$key1};
		    }
		    else
		    {
			$rec = {};
			$HoH{$key1} = $rec;
		    }

		    if($action =~ /A_NOTHING/)
		    {
			$nothing_links = $nothing_links + 1;
		    }
		    elsif($action =~ /A_WARN/)
		    {
			$warn_links = $warn_links + 1;
		    }
		    elsif($action =~ /A_LOG/)
		    {
			$log_links = $log_links + 1;
		    }
		    elsif( $HoH{$key1}{$key2} ne "" )
		    {
			$oldval = $HoH{$key1}{$key2};
			$rec->{$key2} = $oldval.",\\n".$value;
			$duplicate_edges = $duplicate_edges + 1;
		    }
		    else
		    {
			$rec->{$key2} = $value;
		    }

		    $key1 = $action;
		    $key2 = $state1." {".$action."}";
		    $value = $input;

		    if( exists($HoH2{$key1}) )
		    {
			$rec = $HoH2{$key1};
		    }
		    else
		    {
			$rec = {};
			$HoH2{$key1} = $rec;
		    }

		    if($action =~ /A_NOTHING/)
		    {
			$nothing_links = $nothing_links + 1;
		    }
		    elsif($action =~ /A_WARN/)
		    {
			$warn_links = $warn_links + 1;
		    }
		    elsif($action =~ /A_LOG/)
		    {
			$log_links = $log_links + 1;
		    }
		    elsif( $HoH2{$key1}{$key2} ne "" )
		    {
			$oldval = $HoH2{$key1}{$key2};
			$rec->{$key2} = $oldval.",\\n".$value;
			$duplicate_edges = $duplicate_edges + 1;
		    }
		    else
		    {
			$rec->{$key2} = $value;
		    }


		}
	    }
	    
	}
    }

    $filename=$output1;
    $filedesc=DOT_FD;
    
    unless (open($filedesc, '>',$filename)) {
	print STDERR "Can't open $filename: $!\n";
    }

    print DOT_FD $intro;
    
# print the whole thing  somewhat sorted
    foreach $family ( sort keys %HoH ) {
#     print "$family: { ";
	for $role ( sort keys %{ $HoH{$family} } ) {

# aid readability
	    $color="black";
	    $color="red"    if $role =~ /TERMINATE/;
	    $color="red"    if $role =~ /STOP/;
	    $color="orange" if $role =~ /ERROR/;
	    $color="orange" if $role =~ /FAIL/;
	    $color="#33dd33"  if $role =~ /ELECTION/;
	    $color="blue"   if $role =~ /RESTART/;
	    $color="cyan"   if $role =~ /TIMEOUT/;
	    $color="gray" if $role =~ /UPDATE/;

	    print DOT_FD "\"".$family."\" -> \"".$role."\" [ color=\"$color\" fontcolor=\"$color\" label = \"$HoH{$family}{$role}\" ]\n";    
#         print "$role=$HoH{$family}{$role} ";
	}
#     print "}\n";
    }
    
    print DOT_FD $outro;

    close(DOT_FD);

    $filename=$output2;
    $filedesc=DOT_FD;
    
    unless (open($filedesc, '>',$filename)) {
	print STDERR "Can't open $filename: $!\n";
    }

    print DOT_FD $intro;
    
# print the whole thing  somewhat sorted
    foreach $family ( sort keys %HoH2 ) {
#     print "$family: { ";
	for $role ( sort keys %{ $HoH2{$family} } ) {

# aid readability
	    $color="black";
	    $color="red"    if $role =~ /TERMINATE/;
	    $color="red"    if $role =~ /STOP/;
	    $color="orange" if $role =~ /ERROR/;
	    $color="orange" if $role =~ /FAIL/;
	    $color="#33dd33"  if $role =~ /ELECTION/;
	    $color="blue"   if $role =~ /RESTART/;
	    $color="cyan"   if $role =~ /TIMEOUT/;
	    $color="gray" if $role =~ /UPDATE/;

	    print DOT_FD "\"".$family."\" -> \"".$role."\" [ color=\"$color\" fontcolor=\"$color\" label = \"$HoH2{$family}{$role}\" ]\n";    
#         print "$role=$HoH{$family}{$role} ";
	}
#     print "}\n";
    }
    
    print DOT_FD $outro;

    close(DOT_FD);

    close(INPUT_FD);

    print "\n$output Done...\n";
    print "Saved $duplicate_edges duplicate edges\n";
    print "Saved $self_links links to self\n";
    print "Saved $nothing_links links to the A_NOTHING action\n";
    print "Saved $warn_links links to the A_WARN action\n";
    print "Saved $log_links links to the A_LOG action\n";
}
