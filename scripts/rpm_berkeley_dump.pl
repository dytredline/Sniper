#!/usr/bin/perl
use strict;
use warnings;

use DB_File;
use Fcntl qw(O_RDONLY);
use JSON::PP;
use MIME::Base64 qw(encode_base64);

@ARGV == 3 or die "usage\n";
my ($database, $max_rows_raw, $max_bytes_raw) = @ARGV;
$database =~ m{\A/[A-Za-z0-9_./+:-]+\z} or die "path\n";
$max_rows_raw =~ /\A[1-9][0-9]{0,6}\z/ or die "rows\n";
$max_bytes_raw =~ /\A[1-9][0-9]{0,9}\z/ or die "bytes\n";
my $max_rows = int($max_rows_raw);
my $max_bytes = int($max_bytes_raw);

tie my %packages, 'DB_File', $database, O_RDONLY, 0, $DB_HASH or die "open\n";
my @records;
my $retained = 0;
while (my ($key, $value) = each %packages) {
    @records < $max_rows or die "row_limit\n";
    length($key) <= 1024 or die "key_limit\n";
    length($value) <= 16 * 1024 * 1024 or die "record_limit\n";
    $retained += length($key) + length($value);
    $retained <= $max_bytes or die "output_limit\n";
    push @records, {
        key => encode_base64($key, ''),
        value => encode_base64($value, ''),
    };
}
untie %packages;

@records = sort { $a->{key} cmp $b->{key} } @records;
my $document = {
    format => 'sniper-rpm-berkeley-dump/1',
    runtime => {
        module => 'DB_File',
        module_version => "$DB_File::VERSION",
        berkeley_db_version => "$DB_File::db_ver",
    },
    records => \@records,
};
print JSON::PP->new->ascii->canonical->encode($document);
