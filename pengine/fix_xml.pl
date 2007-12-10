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

my $filename=@ARGV[0];
my $filedesc=IO_FD;
unless (open($filedesc, $filename)) {
    print STDERR "Can't open $filename: $!\n";
}

my $input = "";
my @lines = <IO_FD>;

close($filedesc);
    
unless (open($filedesc, '>',$filename)) {
    print STDERR "Can't open $filename: $!\n";
}

print $filedesc "<?xml version=\"1.0\"?>\n";
print $filedesc "<!DOCTYPE transition_graph SYSTEM \"crm-1.0.dtd\">\n";

foreach $line (@lines)	
{
    @tags = split />/, $line;

    foreach $tag (@tags)	
    {
	if( $tag =~ /\n/ )
	{
	    next;
	}
	else
	{
	    $tag =~ s/ timestamp="[0-9]+"//g;
	    print $filedesc $tag.">\n";
	}
    }
}
