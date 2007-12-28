# vi:filetype=

use t::OpenAPI;

plan tests => 3 * blocks();

run_tests;

__DATA__

=== TEST 1: Delete existing models
--- request
DELETE /=/model/~
--- response
{"success":1}



=== TEST 2: Delete existing views
--- request
DELETE /=/view
--- response
{"success":1}



=== TEST 3: Delete existing roles
--- request
DELETE /=/role
--- response
{"success":1,"warning":"Predefined roles skipped."}



=== TEST 4: Get the role list
--- request
GET /=/role
--- response
[
    {"name":"Admin","description":"Administrator","src":"/=/role/Admin"},
    {"name":"Public","description":"Anonymous","src":"/=/role/Public"}
]



=== TEST 5: Use wildcard to get the role list
--- request
GET /=/role/~
--- response
[
    {"name":"Admin","description":"Administrator","src":"/=/role/Admin"},
    {"name":"Public","description":"Anonymous","src":"/=/role/Public"}
]



=== TEST 6: Get the Admin role
--- request
GET /=/role/Admin
--- response
{
    "name":"Admin",
    "description":"Administrator",
    "login":["password","******"],
    "columns":[
        {"name":"method","type":"text",label:"HTTP method"},
        {"name":"url","type":"text",label:"Resource"}
    ]
}



=== TEST 7: GET the Public role
--- request
GET /=/role/Public
--- response
{
    "name":"Public",
    "description":"Anonymous",
    "login":"anonymous",
    "columns":[
        {"name":"method","type":"text",label:"HTTP method"},
        {"name":"src","type":"text",label:"Resource"}
    ]
}



=== TEST 8: Clear out Public's rules
--- request
DELETE /=/role/Public/~/~
--- response
{"success":1}



=== TEST 9: Get Public's rules
--- request
GET /=/role/Public/~/~
--- response
[]



=== TEST 10: Add a new rule to Public
--- request
POST /=/role/Public/~/~
--- response
[
    {"method":"GET","url":"/=/model"},
    {"method":"POST","url":"/=/model/~"},
    {"method":"POST","url":"/=/model/A/~/~"},
    {"method":"DELETE","url":"/=/model/A/id/~"},
]



=== TEST 11: Switch to the Public role
GET /=/login/tester.Public
--- response
{"success":1}



=== TEST 12: Create model A
--- request
POST /=/model/~
{name:"A",description:"A",columns:{"name":"title",label:"name"}}
--- response
{"success":1}



=== TEST 13: Create model B
--- request
POST /=/model/B
{description:"B",columns:[
    {name:"title",label:"title"},
    {name:"body",label:"body"}
 ]
}
--- response
{"success":1}



=== TEST 14: Get model list
--- request
GET /=/model
--- response
[
    {"src":"/=/model/A","name":"A","description":"A"},
    {"src":"/=/model/B","name":"B","description":"B"}
]



=== TEST 15: Delete the models
--- request
DELETE /=/model
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 16: Put to models
--- request
PUT /=/model
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 17: Get an individual model (not in rules)
--- request
GET /=/model/A
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 18: Use the other form
--- request
GET /=/model/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 19: Read the column
--- request
GET /=/model/A/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 20: Read the column (be explicit)
--- request
GET /=/model/A/title
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 21: Try to remove the column
--- request
DELETE /=/model/A/title
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 22: Insert rows
--- request
POST /=/model/A/~/~
[ {"title":"Audrey"}, {"title":"Larry"}, {"title":"Patrick"} ]
--- response
{"success":1,"row_affected":3,"last_row":"/=/model/A/id/3"}



=== TEST 23: Get the rows
--- request
GET /=/model/A/~/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 24: Get a single row
--- request
GET /=/model/A/id/3
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 25: Delete rows
--- request
DELETE /=/model/A/~/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 26: Delete rows
--- request
DELETE /=/model/A/title/Audrey
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 27: Update a row
--- request
PUT /=/model/A/id/3
{"title":"fglock"}
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 28: Delete a row
--- request
DELETE /=/model/A/id/3
--- response
{"success":1}



=== TEST 29: Delete a row again
--- request
DELETE /=/model/A/id/3
--- response
{"success":1}



=== TEST 30: Delete all the rows
--- request
DELETE /=/model/A/id/~
--- response
{"success":1}



=== TEST 31: Delete all the rows in model B
--- request
DELETE /=/model/B/id/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 32: Add a new column to A
--- request
POST /=/model/A/foo
{"label":"foo"}
--- response
{"success":1}



=== TEST 33: Add a second new column to A
--- request
POST /=/model/A/bar
{"label":"bar"}
--- response
{"success":1}



=== TEST 34: Delete the newly added column
--- request
DELETE /=/model/A/bar
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 35: Get the view list
--- request
GET /=/view
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 36: Try to create a view
--- request
POST /=/view/MyView
{"body":"select * from A"}
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 37: Switch back to the Amin role
--- request
GET /=/login/Admin/test1234
--- response
{"success":1}



=== TEST 38: Switch back to the Amin role
--- request
GET /=/login/Admin/test1234
--- response
{"success":1}



=== TEST 39: Check the records in A
--- request
GET /=/model/A/~/~
--- response
XXX



=== TEST 40: Check the model A
--- request
GET /=/model/A
--- response
XXX



=== TEST 41: Create a new role w/o description
--- request
POST /=/role/Poster
{
    login: ["password","4423037"]
}
--- response
{"success":0,"error":"Field \"description\" missing."}



=== TEST 42: Create a new role w/o login
--- request
POST /=/role/Poster
{
    "description":"Comment poster"
}
--- response
{"success":0,"error":"Field \"login\" missing."}



=== TEST 43: Create a new role w/o password
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["password"]
}
--- response
{"success":0,"error":"Password value required."}



=== TEST 44: Create a new role w/o password
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: "password"
}
--- response
{"success":0,"error":"Password value required."}



=== TEST 45: unknown login method (scalar form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: "blah"
}
--- response
{"success":0,"error":"Unknown login method: \"blah\""}



=== TEST 46: unknown login method (array form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["blah"]
}
--- response
{"success":0,"error":"Unknown login method: \"blah\""}



=== TEST 47: unknown login method (array of arrays form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: [[]]
}
--- response
{"success":0,"error":"Unknown login method: []"}



=== TEST 48: Create a new role in the right way
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["password","4423037"]
}
--- response
{"success":1}



=== TEST 49: Add a rule to read model list
--- request
POST /=/role/Poster/~/~
{"url":"/=/model"}
--- response
{"success":1}



=== TEST 50: Add a rule to insert new rows to A
--- request
POST /=/role/Poster/~/~
{"method":"POST","src":"/=/model/A/~/~"}
--- response
{"success":1}



=== TEST 51: Check the rule list
--- request
GET /=/role/Poster/~/~
--- response
[...]



=== TEST 52: Log into the new role
--- request
GET /=/login/tester.Poster
--- response
{"success":1}



=== TEST 53: Try to do something
--- request
GET /=/model
--- response
