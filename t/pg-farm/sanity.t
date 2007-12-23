use strict;
use warnings;

my ($reason, $env);
BEGIN {
    $env = 'OPENAPI_TEST_CLUSTER';
    $reason = "environment $env not set.";
}
use Test::More $ENV{$env} ? 'no_plan' : (skip_all => $reason);

use lib 'lib';
use OpenAPI::Backend::PgFarm;
use Data::Dumper;
use subs 'dump';

my $backend = OpenAPI::Backend::PgFarm->new({ RaiseError => 0 });
ok $backend, "database handle okay";
if ($backend->has_user("agentz")) {
    #    $backend->do("drop table test cascade");
    $backend->drop_user("agentz");
}

my $res = $backend->add_user("agentz");
cmp_ok $res, '>', -1, "user added okay";

$backend->set_user("agentz");

$res = $backend->has_user("agentz");
ok $res, "user has registered!";

$res = $backend->set_user("agentz");
#ok $res, "user switched";

$res = $backend->do("create table test (id serial, body text)");
#ok $res, "table created";
cmp_ok $res, '>', -1;

$res = $backend->do("insert into test (body) values ('hello world')");
#ok $res, "insert a record";
is $res, '1', 'rows affected';

$res = $backend->last_insert_id("test");
ok $res, "get last insert id";
is $res, 1, "last id okay";

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent = 0;
$res = $backend->select('select * from test');
is dump($res), "[['1','hello world']];";

$res = $backend->select('select * from test', { use_hash => 1 });
is dump($res), "[{'body' => 'hello world','id' => '1'}];";

$res = $backend->do("insert into test (body) values ('hello world');\ninsert into test (body) values ('blah');");
ok $res, "insert 2 records";
is $res, '1', 'rows affected';

$res = $backend->do("update test set body=body||'aaa';");
ok $res, "insert 2 records";
is $res, '3', 'rows affected';

$res = $backend->select('select * from test');
is dump($res), "[['1','hello worldaaa'],['2','hello worldaaa'],['3','blahaaa']];";

$res = $backend->select('select * from test', {use_hash => 1});
is dump($res), "[{'body' => 'hello worldaaa','id' => '1'},{'body' => 'hello worldaaa','id' => '2'},{'body' => 'blahaaa','id' => '3'}];";

$res = $backend->do("insert into test (body) values (null);");
ok $res;

$res = $backend->select('select * from test', {use_hash => 1});
is dump($res), "[{'body' => 'hello worldaaa','id' => '1'},{'body' => 'hello worldaaa','id' => '2'},{'body' => 'blahaaa','id' => '3'},{'body' => undef,'id' => '4'}];";

$res = $backend->do("drop table test cascade");
is $res+0, '0', "table dropped";

sub dump {
    my $var = shift;
    my $s = Dumper($var);
    $s =~ s/^\$VAR1\s*=\s*//;
    $s
}

