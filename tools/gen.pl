#!/usr/bin/env perl

use strict;
use warnings;

use Data::Types qw (is_count is_whole);
use File::Basename;
use FindBin;
use List::Util 'shuffle';

# allows require by filename
use lib "$FindBin::Bin/test_modules";

my $IS_OPTIMIZED = 1;

if (exists $ENV{"IS_OPTIMIZED"} && defined $ENV{"IS_OPTIMIZED"})
{
  $IS_OPTIMIZED = $ENV{"IS_OPTIMIZED"};
}

my $TYPE = $ARGV[0];
my $CLEAR = $ARGV[1];
my $INSALT= $ARGV[2];

if (not defined $TYPE)
{
  die "Must specify type\n";
}

if (not defined $CLEAR)
{
  die "Must specify password\n";
}


is_whole ($TYPE) or die "Mode must be a number\n"; 
my $MODULE_FILE = sprintf ("m%05d.pm", $TYPE);

eval { require $MODULE_FILE } or die "Could not load test module: $MODULE_FILE\n$@";

exists &{module_constraints}   or die "Module function 'module_constraints' not found\n";
exists &{module_generate_hash} or die "Module function 'module_generate_hash' not found\n";
exists &{module_verify_hash}   or die "Module function 'module_verify_hash' not found\n";

my $constraints = get_module_constraints ();

my $salt_min = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[0] : $constraints->[1]->[0];
my $salt_max = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[1] : $constraints->[1]->[1];

my $salt;

if (not defined $INSALT)
{
  $salt = random_numeric_string ($salt_max) // "";
}
else
{
  $salt = $INSALT;
}

my $hash = module_generate_hash ($CLEAR,$salt);
printf ($hash."\n");

sub usage_exit
{
  my $f = basename ($0);

  print "\n"
    . "Usage:\n"
    . " $f single      <mode> [length]\n"
    . " $f passthrough <mode>\n"
    . " $f potthrough  <mode>\n"
    . " $f verify      <mode> <hashfile> <cracksfile> <outfile>\n"
    . "\n";

  exit 1;
}

sub get_module_constraints
{
  my $constraints = module_constraints ();
   
  if (($constraints->[0]->[0] == -1) && ($constraints->[0]->[1] == -1))
  {
    # hash-mode doesn't have a pure kernel, use optimized password settings

    $constraints->[0]->[0] = $constraints->[2]->[0];
    $constraints->[0]->[1] = $constraints->[2]->[1];
    $constraints->[1]->[0] = $constraints->[3]->[0];
    $constraints->[1]->[1] = $constraints->[3]->[1];

    $IS_OPTIMIZED = 1;
  }
  elsif (($constraints->[2]->[0] == -1) && ($constraints->[2]->[1] == -1))
  {
    # hash-mode doesn't have a optimized kernel, use pure password settings
 
    $constraints->[2]->[0] = $constraints->[0]->[0];
    $constraints->[2]->[1] = $constraints->[0]->[1];
    $constraints->[3]->[0] = $constraints->[1]->[0];
    $constraints->[3]->[1] = $constraints->[1]->[1];

    $IS_OPTIMIZED = 0;
  }
 
  return $constraints;
}

sub random_numeric_string 
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('0'..'9');

  my $string = "";
 
  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}
