use t::OpenAPI;

plan tests => 3 * blocks();

run_tests;

__DATA__

=== TEST 1: Delete existing models
--- request
DELETE /=/model
--- response
{"success":1}



=== TEST 2: Create a model
--- request
POST /=/model/Carrie.js
{
    description: "我的书签",
    columns: [
        { name: "title", label: "标题" },
        { name: "url", label: "网址" },
        { name: "num", label: "num" }
    ]
}
--- response
{"success":1}



=== TEST 3: check the model list again
--- request
GET /=/model.js
--- response
[{"src":"/=/model/Carrie","name":"Carrie","description":"我的书签"}]



=== TEST 4: insert a record 
--- request
POST /=/model/Carrie/~/~.js
{ title:'hello carrie',url:"http://www.carriezh.cn/",num:"10"}
--- response
{"success":1,"rows_affected":1,"last_row":"/=/model/Carrie/id/1"}



=== TEST 5: read a record according to url
--- request
GET /=/model/Carrie/url/http://www.carriezh.cn/.js
--- response
[{"num":"10","url":"http://www.carriezh.cn/","title":"hello carrie","id":"1"}]



=== TEST 6: insert another record
--- request
POST /=/model/Carrie/~/~.js
{ title:'second',url:"http://zhangxiaojue.cn",num:"1"}
--- response
{"success":1,"rows_affected":1,"last_row":"/=/model/Carrie/id/2"}



=== TEST 7: find out two record assign to var hello
--- request
GET /=/model/Carrie/~/~.js?var=hello
--- response
var hello=[{"num":"10","url":"http://www.carriezh.cn/","title":"hello carrie","id":"1"},{"num":"1","url":"http://zhangxiaojue.cn","title":"second","id":"2"}];



=== TEST 8: use MINISQL to find record
--- request
POST /=/action/ModelSearch/lang/minisql
"select * from Carrie where title = 'hello carrie' and num=10;"
--- response
[{"num":"10","url":"http://www.carriezh.cn/","title":"hello carrie","id":"1"}]



=== TEST 9: use minisql through GET & ModelSelect
--- request
GET /=/action/ModelSelect/lang/minisql?var=foo&data="select * from Carrie where title = 'hello carrie' and num=10"
--- response
[{"num":"10","url":"http://www.carriezh.cn/","title":"hello carrie","id":"1"}]
