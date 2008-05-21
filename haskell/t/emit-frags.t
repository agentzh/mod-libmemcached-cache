#!/usr/bin/env perl
# vi:filetype=

use strict;
use warnings;

use IPC::Run3;
use Test::Base;
#use Test::LongString;

plan tests => 2 * blocks();

run {
    my $block = shift;
    my $desc = $block->description;
    my ($stdout, $stderr);
    my $stdin = $block->in;
    run3 [qw< bin/restyscript frags >], \$stdin, \$stdout, \$stderr;
    is $? >> 8, 0, "compiler returns 0 - $desc";
    warn $stderr if $stderr;
    my @ln = split /\n+/, $stdout;
    my $out = $block->out;
    is "$ln[0]\n", $out, "Pg/SQL output ok - $desc";
};

__DATA__

=== TEST 1: basic
--- in
select foo, bar from Bah
--- out
["select \"foo\", \"bar\" from \"Bah\""]



=== TEST 2: select only
--- in
select foo
--- out
["select \"foo\""]



=== TEST 3: spaces around separator (,)
--- in
select id,$name , age from  $Post , Comment
--- out
["select \"id\", ",["name","unknown"],", \"age\" from ",["Post","symbol"],", \"Comment\""]



=== TEST 4: spaces around separator (,)
--- in
select $foo,
$bar ,
$age from  Post , $comment
--- out
["select ",["foo","unknown"],", ",["bar","unknown"],", ",["age","unknown"]," from \"Post\", ",["comment","symbol"]]



=== TEST 5: simple where clause
--- in
select id from Post where a > b
--- out
["select \"id\" from \"Post\" where \"a\" > \"b\""]



=== TEST 6: floating-point numbers
--- in
select id from Post where 00.003 > 3.14 or 3. > .0
--- out
["select \"id\" from \"Post\" where (0.003 > 3.14 or 3.0 > 0.0)"]



=== TEST 7: integral numbers
--- in
select id from Post where 256 > 0
--- out
["select \"id\" from \"Post\" where 256 > 0"]



=== TEST 8: simple or
--- in
select id from Post  where a > b or b <= c
--- out
["select \"id\" from \"Post\" where (\"a\" > \"b\" or \"b\" <= \"c\")"]



=== TEST 9: and in or
--- in
select id from Post where a>b and a like b or b=c and d>=e or e<>d
--- out
["select \"id\" from \"Post\" where (((\"a\" > \"b\" and \"a\" like \"b\") or (\"b\" = \"c\" and \"d\" >= \"e\")) or \"e\" <> \"d\")"]



=== TEST 10: with parens in and/or
--- in
select id from Post where (( a > b ) and ( b < c or c > 1 ))
--- out
["select \"id\" from \"Post\" where (\"a\" > \"b\" and (\"b\" < \"c\" or \"c\" > 1))"]



=== TEST 11: literal strings
--- in
select id from Post where 'a''\'' != 'b\\\n\r\b\a'
--- out
["select \"id\" from \"Post\" where 'a''''' != 'b\\\\\\n\\r\\ba'"]



=== TEST 12: order by
--- in
select id order  by  id
--- out
["select \"id\" order by \"id\" asc"]



=== TEST 13: complicated order by
--- in
select * order by id desc, name , foo  asc
--- out
["select * order by \"id\" desc, \"name\" asc, \"foo\" asc"]



=== TEST 14: group by
--- in
select sum(id) group by id
--- out
["select \"sum\"(\"id\") group by \"id\""]



=== TEST 15: select literals
--- in
 select 3.14 , 25, sum ( 1 ) , * from Post
--- out
["select 3.14, 25, \"sum\"(1), * from \"Post\""]



=== TEST 16: quoted symbols
--- in
select "id", "date_part"("created") from "Post" where "id" = 1
--- out
["select \"id\", \"date_part\"(\"created\") from \"Post\" where \"id\" = 1"]



=== TEST 17: offset and limit
--- in
select id from Post offset 3 limit 5
--- out
["select \"id\" from \"Post\" offset 3 limit 5"]



=== TEST 18: offset and limit (with quoted values)
--- in
select id from Post offset '3' limit '5'
--- out
["select \"id\" from \"Post\" offset '3' limit '5'"]



=== TEST 19: simple variable
--- in
select $var
--- out
["select ",["var","unknown"]]



=== TEST 20: simple variable
--- in
select
$var
from Post
--- out
["select ",["var","unknown"]," from \"Post\""]



=== TEST 21: var in qualified col
--- in
select $table.$col from $table
--- out
["select ",["table","symbol"],".",["col","symbol"]," from ",["table","symbol"]]



=== TEST 22: var in qualified col
--- in
select $table.col from $table
--- out
["select ",["table","symbol"],".\"col\" from ",["table","symbol"]]



=== TEST 23: var in proc call
--- in
select $proc(32)
--- out
["select ",["proc","symbol"],"(32)"]



=== TEST 24: variable as model
--- in
select * from $model_name, $bar
--- out
["select * from ",["model_name","symbol"],", ",["bar","symbol"]]



=== TEST 25: variable in where, offset, limit and group by
--- in
select * from A where $id > 0 offset $off limit $lim group by $foo
--- out
["select * from \"A\" where ",["id","unknown"]," > 0 offset ",["off","literal"]," limit ",["lim","literal"]," group by ",["foo","symbol"]]



=== TEST 26: weird identifiers
--- in
select select, 0.125 from from where where > or or and < and and order > 3.12 order by order, group group by by
--- out
["select \"select\", 0.125 from \"from\" where (\"where\" > \"or\" or (\"and\" < \"and\" and \"order\" > 3.12)) order by \"order\" asc, \"group\" asc group by \"by\""]



=== TEST 27: signed negative numbers
--- in
select -3 , - 3 , -1.25,- .3
--- out
["select -3, -3, -1.25, -0.3"]



=== TEST 28: signed positive numbers
--- in
select +3 , + 3 , +1.25,+ .3 , 1
--- out
["select 3, 3, 1.25, 0.3, 1"]



=== TEST 29: qualified columns
--- in
select Foo.bar , Foo . bar , "Foo" . bar , "Foo"."bar" from Foo
--- out
["select \"Foo\".\"bar\", \"Foo\".\"bar\", \"Foo\".\"bar\", \"Foo\".\"bar\" from \"Foo\""]



=== TEST 30: selected cols with parens
--- in
select (32) , ((5)) as $item
--- out
["select 32, 5 as ",["item","symbol"]]



=== TEST 31: count(*)
--- in
select count(*),
     count ( * )
 from Post
--- out
["select \"count\"(*), \"count\"(*) from \"Post\""]



=== TEST 32: aliased cols
--- in
select id as foo, count(*) as bar
from Post
--- out
["select \"id\" as \"foo\", \"count\"(*) as \"bar\" from \"Post\""]



=== TEST 33: alias for models
--- in
select * from Post as foo
--- out
["select * from \"Post\" as \"foo\""]
--- LAST



=== TEST 34: from proc
--- in
select *
from proc(32, 'hello'), blah() as poo
--- out
select * from "proc"(32, 'hello'), "blah"() as "poo"



=== TEST 35: arith
--- in
select 3+5/3*2 - 36 % 2
--- ast
Query [Select [Arith "-" (Arith "+" (Integer 3) (Arith "*" (Arith "/" (Integer 5) (Integer 3)) (Integer 2))) (Arith "%" (Integer 36) (Integer 2))]]
--- out
select ((3 + ((5 / 3) * 2)) - (36 % 2))



=== TEST 36: arith (with parens)
--- in
select (3+5)/(3*2) - ( 36 % 2 )
--- out
select (((3 + 5) / (3 * 2)) - (36 % 2))



=== TEST 37: string cat ||
--- in
select proc(2) || 'hello' || 5 - 2 + 5
--- out
select (("proc"(2) || 'hello') || ((5 - 2) + 5))



=== TEST 38: ^
--- in
select 3*3*5^6^2
--- out
select ((3 * 3) * ((5 ^ 6) ^ 2))



=== TEST 39: union
--- in
select 2 union select 3
--- ast
SetOp "union" (Query [Select [Integer 2]]) (Query [Select [Integer 3]])
--- out
((select 2) union (select 3))



=== TEST 40: union 2
--- in
(select count(*) from "Post" limit 3) union select sum(1) from "Comment";
--- out
((select "count"(*) from "Post" limit 3) union (select "sum"(1) from "Comment"))



=== TEST 41: chained union
--- in
select 3 union select 2 union select 1;
--- out
((((select 3) union (select 2))) union (select 1))



=== TEST 42: chained union and except
--- in
select 3 union select 2 union select 1 except select 2;
--- out
((((((select 3) union (select 2))) union (select 1))) except (select 2))



=== TEST 43: parens with set ops
--- in
select 3 union (select 2 except select 3)
--- out
((select 3) union (((select 2) except (select 3))))



=== TEST 44: intersect
--- in
(select 2) union (select 3)intersect(select 2)
--- out
((((select 2) union (select 3))) intersect (select 2))



=== TEST 45: intersect
--- in
(select 2) union ((select 3)intersect(select 2))
--- out
((select 2) union (((select 3) intersect (select 2))))



=== TEST 46: union all
--- in
select 2 union all select 2
--- ast
SetOp "union all" (Query [Select [Integer 2]]) (Query [Select [Integer 2]])
--- out
((select 2) union all (select 2))



=== TEST 47: type casting ::
--- in
select 32::float8
--- out
select 32::"float8"



=== TEST 48: more complicated type casting ::
--- in
select ('2003-03' || '-01') :: date
--- out
select ('2003-03' || '-01')::"date"

