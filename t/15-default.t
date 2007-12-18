use t::OpenAPI;

plan tests => 3 * blocks();

run_tests;

__DATA__

=== TEST 1: Delete existing models
--- request
DELETE /=/model
--- response
{"success":1}



=== TEST 2: default in create model
--- request
POST /=/model/Foo
{
  description:"Foo",
  columns:{name:"title", label: "title", default:"No title"}
}
--- response
{"success":1}



=== TEST 3: Insert a row
--- request
POST /=/model/Foo/~/~
{}
--- response
{"success":1,"rows_affected":1,"last_row":"/=/model/Foo/id/1"}



=== TEST 4: Check that it has the default value
--- request
GET /=/model/Foo/id/1
--- response
{"title":"No title","id":"1"}



