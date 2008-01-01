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



=== TEST 4: Delete existing roles (using wildcard)
--- request
DELETE /=/role/~
--- response
{"success":1,"warning":"Predefined roles skipped."}



=== TEST 5: Get the role list
--- request
GET /=/role
--- response
[
    {"src":"/=/role/Admin","name":"Admin","description":"Administrator"},
    {"src":"/=/role/Public","name":"Public","description":"Anonymous"}
]



=== TEST 6: Use wildcard to get the role list
--- request
GET /=/role/~
--- response
[
    {"src":"/=/role/Admin","name":"Admin","description":"Administrator"},
    {"src":"/=/role/Public","name":"Public","description":"Anonymous"}
]



=== TEST 7: Get the Admin role
--- request
GET /=/role/Admin
--- response
{
    "columns":[
        {"name":"method","label":"HTTP method","type":"text"},
        {"name":"url","label":"Resource","type":"text"}
    ],
    "name":"Admin",
    "description":"Administrator",
    "login":"password"
}



=== TEST 8: GET the Public role
--- request
GET /=/role/Public
--- response
{
  "columns":[
    {"name":"method","label":"HTTP method","type":"text"},
    {"name":"url","label":"Resource","type":"text"}
  ],
  "name":"Public",
  "description":"Anonymous",
  "login":"anonymous"
}



=== TEST 9: Clear out Public's rules
--- request
DELETE /=/role/Public/~/~
--- response
{"success":1}



=== TEST 10: Get Public's rules
--- request
GET /=/role/Public/~/~
--- response
[]



=== TEST 11: Add a new rule to Public
--- request
POST /=/role/Public/~/~
{"method":"GET","url":"/=/model"}
--- response_like
{"success":1,"rows_affected":1,"last_row":"/=/role/Public/id/\d+"}



=== TEST 12: Add more rules
--- request
POST /=/role/Public/~/~
[
    {"method":"POST","url":"/=/model/~"},
    {"method":"POST","url":"/=/model/A/~/~"},
    {"method":"DELETE","url":"/=/model/A/id/~"}
]
--- response_like
{"success":1,"rows_affected":3,"last_row":"/=/role/Public/id/\d+"}



=== TEST 13: Get the access rules
--- request
GET /=/role/Public/~/~
--- response_like
\[
    \{"url":"/=/model","method":"GET","id":"\d+"},
    \{"url":"/=/model/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/~/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/id/~","method":"DELETE","id":"\d+"}
\]



=== TEST 14: Query by method
--- request
GET /=/role/Public/method/~
--- response_like
\[
    \{"url":"/=/model","method":"GET","id":"\d+"},
    \{"url":"/=/model/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/~/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/id/~","method":"DELETE","id":"\d+"}
\]



=== TEST 15: Query by method value
--- request
GET /=/role/Public/method//=/model
--- response
[]



=== TEST 16: Query by method value (don't specify col)
--- request
GET /=/role/Public/~//=/model
--- response_like
\[{"url":"/=/model","method":"GET","id":"\d+"}\]



=== TEST 17: Query by method value (don't specify col)
--- request
GET /=/role/Public/~/model?op=contains
--- response_like
\[
    \{"url":"/=/model","method":"GET","id":"\d+"},
    \{"url":"/=/model/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/~/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/id/~","method":"DELETE","id":"\d+"}
\]



=== TEST 18: use contains op
--- request
GET /=/role/Public/url/A?op=contains
--- response_like
\[
    \{"url":"/=/model/A/~/~","method":"POST","id":"\d+"},
    \{"url":"/=/model/A/id/~","method":"DELETE","id":"\d+"}
\]



=== TEST 19: Query by method value GET
--- request
GET /=/role/Public/method/GET
--- response_like
\[{"url":"/=/model","method":"GET","id":"\d+"}\]



=== TEST 20: Query by method value POST
--- request
GET /=/role/Public/method/POST
--- response_like
\[
    {"url":"/=/model/~","method":"POST","id":"\d+"},
    {"url":"/=/model/A/~/~","method":"POST","id":"\d+"}
\]



=== TEST 21: Query by method value POST
--- request
GET /=/role/Public/~/POST
--- response_like
\[
    {"url":"/=/model/~","method":"POST","id":"\d+"},
    {"url":"/=/model/A/~/~","method":"POST","id":"\d+"}
\]



=== TEST 22: Switch to the Public role
--- request
GET /=/login/tester.Public
--- response
{"success":1}

--- LAST


=== TEST 23: Create model A
--- request
POST /=/model/~
{name:"A",description:"A",columns:{"name":"title",label:"name"}}
--- response
{"success":1}



=== TEST 24: Create model B
--- request
POST /=/model/B
{description:"B",columns:[
    {name:"title",label:"title"},
    {name:"body",label:"body"}
 ]
}
--- response
{"success":1}



=== TEST 25: Get model list
--- request
GET /=/model
--- response
[
    {"src":"/=/model/A","name":"A","description":"A"},
    {"src":"/=/model/B","name":"B","description":"B"}
]



=== TEST 26: Delete the models
--- request
DELETE /=/model
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 27: Put to models
--- request
PUT /=/model
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 28: Get an individual model (not in rules)
--- request
GET /=/model/A
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 29: Use the other form
--- request
GET /=/model/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 30: Read the column
--- request
GET /=/model/A/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 31: Read the column (be explicit)
--- request
GET /=/model/A/title
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 32: Try to remove the column
--- request
DELETE /=/model/A/title
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 33: Insert rows
--- request
POST /=/model/A/~/~
[ {"title":"Audrey"}, {"title":"Larry"}, {"title":"Patrick"} ]
--- response
{"success":1,"row_affected":3,"last_row":"/=/model/A/id/3"}



=== TEST 34: Get the rows
--- request
GET /=/model/A/~/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 35: Get a single row
--- request
GET /=/model/A/id/3
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 36: Delete rows
--- request
DELETE /=/model/A/~/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 37: Delete rows
--- request
DELETE /=/model/A/title/Audrey
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 38: Update a row
--- request
PUT /=/model/A/id/3
{"title":"fglock"}
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 39: Delete a row
--- request
DELETE /=/model/A/id/3
--- response
{"success":1}



=== TEST 40: Delete a row again
--- request
DELETE /=/model/A/id/3
--- response
{"success":1}



=== TEST 41: Delete all the rows
--- request
DELETE /=/model/A/id/~
--- response
{"success":1}



=== TEST 42: Delete all the rows in model B
--- request
DELETE /=/model/B/id/~
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 43: Add a new column to A
--- request
POST /=/model/A/foo
{"label":"foo"}
--- response
{"success":1}



=== TEST 44: Add a second new column to A
--- request
POST /=/model/A/bar
{"label":"bar"}
--- response
{"success":1}



=== TEST 45: Delete the newly added column
--- request
DELETE /=/model/A/bar
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 46: Get the view list
--- request
GET /=/view
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 47: Try to create a view
--- request
POST /=/view/MyView
{"body":"select * from A"}
--- response
{"success":0,"error":"Permission denied for the \"Public\" role."}



=== TEST 48: Switch back to the Amin role
--- request
GET /=/login/Admin/test1234
--- response
{"success":1}



=== TEST 49: Switch back to the Amin role
--- request
GET /=/login/Admin/test1234
--- response
{"success":1}



=== TEST 50: Check the records in A
--- request
GET /=/model/A/~/~
--- response
XXX



=== TEST 51: Check the model A
--- request
GET /=/model/A
--- response
XXX



=== TEST 52: Create a new role w/o description
--- request
POST /=/role/Poster
{
    login: ["password","4423037"]
}
--- response
{"success":0,"error":"Field \"description\" missing."}



=== TEST 53: Create a new role w/o login
--- request
POST /=/role/Poster
{
    "description":"Comment poster"
}
--- response
{"success":0,"error":"Field \"login\" missing."}



=== TEST 54: Create a new role w/o password
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["password"]
}
--- response
{"success":0,"error":"Password value required."}



=== TEST 55: Create a new role w/o password
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: "password"
}
--- response
{"success":0,"error":"Password value required."}



=== TEST 56: unknown login method (scalar form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: "blah"
}
--- response
{"success":0,"error":"Unknown login method: \"blah\""}



=== TEST 57: unknown login method (array form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["blah"]
}
--- response
{"success":0,"error":"Unknown login method: \"blah\""}



=== TEST 58: unknown login method (array of arrays form)
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: [[]]
}
--- response
{"success":0,"error":"Unknown login method: []"}



=== TEST 59: Create a new role in the right way
--- request
POST /=/role/Poster
{
    "description":"Comment poster",
    login: ["password","4423037"]
}
--- response
{"success":1}



=== TEST 60: Add a rule to read model list
--- request
POST /=/role/Poster/~/~
{"url":"/=/model"}
--- response
{"success":1}



=== TEST 61: Add a rule to insert new rows to A
--- request
POST /=/role/Poster/~/~
{"method":"POST","src":"/=/model/A/~/~"}
--- response
{"success":1}



=== TEST 62: Check the rule list
--- request
GET /=/role/Poster/~/~
--- response
[...]



=== TEST 63: Log into the new role
--- request
GET /=/login/tester.Poster
--- response
{"success":1}



=== TEST 64: Try to do something
--- request
GET /=/model
--- response

