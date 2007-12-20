use t::OpenAPI;

plan tests => 3 * blocks();

run_tests;

__DATA__

=== TEST 1: Delete existing models
--- request
DELETE /=/model.js
--- response
{"success":1}



=== TEST 2: drop tables
--- request
POST /=/admin/do
"drop table if exists _books;
drop table if exists _cats;
drop table if exists _books2 cascade;"
--- response
{"success":1}



=== TEST 3: Create a DB table
--- request
POST /=/admin/do
"create table _books (id serial primary key, body text, num integer default 0);
create table _cats (id serial primary key, name text);"
--- response
{"success":1}



=== TEST 4: Insert some records
--- request
POST /=/admin/do
"insert into _books (body) values ('Larry Wall');
insert into _books (body) values ('Audrey Tang');
insert into _cats (name) values ('mimi');"
--- response
{"success":1}



=== TEST 5: Select data
--- request
POST /=/admin/select
"select * from _books"
--- response
[
    {"body":"Larry Wall","num":"0","id":"1"},
    {"body":"Audrey Tang","num":"0","id":"2"}
]



=== TEST 6: CREATE FUNCTION
--- request
POST /=/admin/do
"CREATE OR REPLACE FUNCTION add_child() returns trigger as $$ 
	begin 
		if NEW.id <> 0 then 
			update _books set num=num+1 where id=1; 
		END IF;
		return NEW; 
	end; 
$$ language plpgsql;"
--- response
{"success":1}



=== TEST 7: create tirgger
--- request
POST /=/admin/do
"CREATE TRIGGER add_child_t BEFORE INSERT ON _books FOR EACH ROW EXECUTE PROCEDURE add_child();"
--- response
{"success":1}



=== TEST 8: Insert some records
--- request
POST /=/admin/do
"insert into _books (body) values ('Larry Wall');
insert into _books (body) values ('Audrey Tang');
insert into _cats (name) values ('mimi');"
--- response
{"success":1}



=== TEST 9: Select data
--- request
POST /=/admin/select
"select * from _books where id=1"
--- response
[{"body":"Larry Wall","num":"2","id":"1"}]



=== TEST 10: Create a DB table
--- request
POST /=/admin/do
"create table _books2 (id serial primary key, body text, num integer default 0);
--- response
{"success":1}



=== TEST 11: CREATE PROC
--- request
POST /=/admin/do
"DROP FUNCTION if exists hello_world(int,int);
CREATE OR REPLACE FUNCTION hello_world(i int,j int) RETURNS _books2 AS $Q$
	declare
		tmp _books2%ROWTYPE;
	begin
		select * into tmp from _books where id=i;
	return tmp;
	end;
$Q$LANGUAGE plpgsql;"
--- response
{"success":1}



=== TEST 12: select proc
--- request
GET /=/post/action/Select/lang/minisql?data="select hello_world(1,0)"
--- response
[{"hello_world":"(1,\"Larry Wall\",2)"}]



=== TEST 13 CREATE PROC
--- request
POST /=/admin/do
"DROP FUNCTION if exists hello_world2(int,int);
CREATE OR REPLACE FUNCTION hello_world2(i int,j int) RETURNS setof _books2 AS $Q$
	declare
		tmp _books2%ROWTYPE;
	begin
		for tmp in select * from _books order by id loop
		return next tmp;
		end loop;
	return;
	end;
$Q$LANGUAGE plpgsql;"
--- response
{"success":1}



=== TEST 14: select * from proc() as ....
--- request
GET /=/post/action/Select/lang/minisql?var=sss&data="select * from hello_world2(1,0)"
--- response
var sss=[{"body":"Larry Wall","num":"2","id":"1"},{"body":"Audrey Tang","num":"0","id":"2"},{"body":"Larry Wall","num":"0","id":"3"},{"body":"Audrey Tang","num":"0","id":"4"}];



=== TEST 15: drop tables
--- request
POST /=/admin/do
"drop table if exists _books;
drop table if exists _cats;"
--- response
{"success":1}


