use t::OpenAPI;

plan tests => 2 * blocks();

run_tests;

__DATA__

=== TEST 1: Delete existing models
--- request
DELETE /=/model.js
--- response
{"success":1}



=== TEST 2: Create a new model
--- request
POST /=/model/Human
{ description:"人类",
  columns:
    [ { name: "gender", label: "性别" } ]
}
--- response
{"success":1}



=== TEST 3: Create a model with the same name
--- request
POST /=/model/Human
{ description:"人类",
  columns:
    [ { name: "gender", label: "性别" } ]
}
--- response
{"success":0,"error":"Model \"Human\" already exists."}



=== TEST 4: Create a model with 'name' specified
--- request
POST /=/model/Foo
{
  name: "Blah",
  description:"人类",
  columns:
    [ { name: "gender", label: "性别" } ]
}
--- response
{"success":1,"warning":"name \"Blah\" in POST content ignored."}



=== TEST 5: No description specified
--- request
POST /=/model/Blah
{
  columns:
    [ { name: "gender", label: "性别" } ]
}
--- response
{"success":0,"error":"No 'description' specified for model \"Blah\"."}



=== TEST 6: No label specified for column
--- request
POST /=/model/Blah
{
  description:"人类",
  columns:
    [ { name: "gender" } ]
}
--- response
{"success":0,"error":"No 'label' specified for column \"gender\" in model \"Blah\"."}



=== TEST 7: Create another model
--- request
POST /=/model/Cat
{ description:"猫",
  columns:
    [ { name: "sex", label: "性别" } ]
}
--- response
{"success":1}

