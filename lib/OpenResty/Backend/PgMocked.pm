package OpenResty::Backend::PgMocked;

use strict;
use warnings;

#use Smart::Comments '#####';
use Clone qw(clone);
use JSON::XS;
use base 'OpenResty::Backend::Pg';
use Test::LongString;
#use Encode qw(is_utf8 encode decode);

our ($DataFile, $Data, $TransList);

#$JSON::Syck::SortKeys = 1;

# -------------------
# Recorder routines
# -------------------

my $path = 't/pgmock-data';
unless (-d $path) { mkdir $path }

my $json_xs = JSON::XS->new->utf8->allow_nonref;

sub LoadFile {
    my ($file) = @_;
    open my $in, $file or
        die "Can't open $file for reading: $!";
    my @res;
    while (<$in>) {
        chomp;
        push @res, $json_xs->decode($_);
    }
    close $in;
    return \@res;
}

sub ping { 1; }

sub DumpFile {
    my ($file, $data) = @_;
    open my $out, ">$file" or
        die "Can't open $file for writing: $!";

    #### $data
    for my $elem (@$data) {
        my $json = $json_xs->encode($elem);
    #print $out encode('utf8', $json);
        print $out $json, "\n";
    }
    close $out;
}

sub start_recording_file {
    my $class = shift;
    my $file = shift;
    $DataFile = "$path/$file.json";
    if (!-f $DataFile) {
        $Data = {};
    } else {
        $Data = LoadFile($DataFile) || {};
    }
    $Data = $TransList = [];
}

sub record {
    my ($class, $query, $res, $type) = @_;
    $type ||= 'data';
    if (ref $res && ref $res eq 'die') {
        #use Data::Dumper;
        #warn "HERE!!!! \n", Dumper($res), "\n";
        $res = $$res;
        #warn "RES: $res\n";
        $type = 'die';
    }
    ##### $res
    push @$TransList, ["$query", clone($res), $type];
}

sub stop_recording_file {
    ##### Last: $Data->[-1]
    DumpFile($DataFile, $Data);
    undef $Data;
}

# -------------------
# player routines
# -------------------

sub start_playing_file {
    my ($class, $file) = @_;
    $DataFile = "$path/$file.json";
    $Data = LoadFile($DataFile) or
        die "No hash found in data file $DataFile.\n";
    $TransList = $Data or
        die "No transaction list found for $file.\n";
}

sub play {
    my ($class, $query) = @_;
    ### playing...
    my $cur = shift @$TransList;
    #warn "SQL: $cur->[0]";
    #if ($cur->[0] =~ /select2/) { warn "!!!!!!!! $cur >>>>$query<<<<<" }
    if (!$cur) {
        die "No more expected response for query $query";
    }
    #if (is_utf8($query)) {
        #$query = encode('utf8', $query);
    #}
    #if (is_utf8($cur->[0])) {
    #$cur->[0] = encode('utf8', $cur->[0]);
    #}
    #$query =~ s/'3\.14159'/'3.14158999999999988'/;
    #$query =~ s/'3\.14'/'3.14000000000000012'/;
    $query =~ s/'3\.1415[89]{4,}\d*'/'3.14159'/;
    $query =~ s/'3\.140{4,}\d*'/'3.14'/;
    my $res = $cur->[1];
    if ($cur->[0] ne $query) {
        #is_string($cur->[0], $query);
        die "Unexpected query: ", $OpenResty::Dumper->($query) .
            " (Expecting: ", $OpenResty::Dumper->($cur->[0]), ")\n";
    }
    my $type = $cur->[-1];
    if ($type eq 'die') {
        die $res;
    }

    return $res;
}

sub new {
    my $class = shift;
    ### Creating class: $class
    my $t_file;
    if ($0 =~ m{[^/]+\.t$}) {
        $t_file = $&;
        $class->start_playing_file($t_file);
    } else {
        die "The PgMocked backend is for testing only and it can only work when test_suite.use_http is set to 0.\n";
    }
    return bless {}, $class;
}

sub select {
    my $class = shift;
    $class->play(@_);
}

sub do {
    my $class = shift;
    $class->play(@_);
}

sub state {
    '';
}

sub quote {
    my ($self, $val) = @_;
    if (!defined $val) { return undef }
    $val =~ s/'/''/g;
    $val =~ s{\\}{\\\\}g;
    "'$val'";
}

sub quote_identifier {
    my ($self, $val) = @_;
    if (!defined $val) { return undef }
    $val =~ s/"/""/g;
    $val =~ s{\\}{\\\\}g;
    qq{"$val"};
}

sub add_user {
    1;
}

sub drop_user {
    1;
}

1;
__END__

=head1 NAME

OpenResty::Backend::PgMocked - A mocked-up OpenResty backend for the Pg backend

=head1 INHERITANCE

    OpenResty::Backend::PgMocked
        ISA OpenResty::Backend::Base

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 AUTHOR

Agent Zhang (agentzh) C<< <agentzh@gmail.com >>

=head1 SEE ALSO

L<OpenResty::Backend::Base>, L<OpenResty::Backend::Pg>, L<OpenResty::Backend::PgFarm>, L<OpenResty>.

