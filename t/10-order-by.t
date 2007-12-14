use t::OpenAPI;

plan tests => 3 * blocks();

run_tests;

__DATA__

=== TEST 1: Clear the environment
--- request
DELETE /=/model
--- response
{"success":1}



=== TEST 2: Create a model
--- request
POST /=/model/Foo
{
    description:"foo",
    columns:
        [ {name:"name", label:"姓名"},
          {name:"age", label: "年龄", type:"integer"}
        ]
}
--- response
{"success":1}



=== TEST 3: Insert some data
--- request
POST /=/model/Foo/~/~
[
  { name:"Marry", age:21 },
  { name:"Bob", age:32 },
  { name:"Bob", age: 15 },
  { name:"Henry", age: 19 },
  { name:"Henry", age: 23 },
  { name:"Larry", age: 59 },
  { name:"Audrey", age: 17 }
]
--- response
{"success":1,"rows_affected":7,"last_row":"/=/model/Foo/id/7"}



=== TEST 4: no order by
--- request
GET /=/model/Foo/~/~
--- response
[{"name":"Marry","id":"1","age":"21"},{"name":"Bob","id":"2","age":"32"},{"name":"Bob","id":"3","age":"15"},{"name":"Henry","id":"4","age":"19"},{"name":"Henry","id":"5","age":"23"},{"name":"Larry","id":"6","age":"59"},{"name":"Audrey","id":"7","age":"17"}]



=== TEST 5: Order by name (asc by default)
--- request
GET /=/model/Foo/~/~?order_by=name
--- response
[{"name":"Audrey","id":"7","age":"17"},{"name":"Bob","id":"2","age":"32"},{"name":"Bob","id":"3","age":"15"},{"name":"Henry","id":"4","age":"19"},{"name":"Henry","id":"5","age":"23"},{"name":"Larry","id":"6","age":"59"},{"name":"Marry","id":"1","age":"21"}]



=== TEST 6: Order by name (asc by default)
--- request
GET /=/model/Foo/~/~?order_by=name:desc
--- response
[{"name":"Marry","id":"1","age":"21"},{"name":"Larry","id":"6","age":"59"},{"name":"Henry","id":"5","age":"23"},{"name":"Henry","id":"4","age":"19"},{"name":"Bob","id":"3","age":"15"},{"name":"Bob","id":"2","age":"32"},{"name":"Audrey","id":"7","age":"17"}]



=== TEST 7: Order by age (asc by default)
--- request
GET /=/model/Foo/~/~?order_by=age
--- response
[{"name":"Bob","id":"3","age":"15"},{"name":"Audrey","id":"7","age":"17"},{"name":"Henry","id":"4","age":"19"},{"name":"Marry","id":"1","age":"21"},{"name":"Henry","id":"5","age":"23"},{"name":"Bob","id":"2","age":"32"},{"name":"Larry","id":"6","age":"59"}]



=== TEST 8: Order by age desc
--- request
GET /=/model/Foo/~/~?order_by=age:desc
--- response
[{"name":"Larry","id":"6","age":"59"},{"name":"Bob","id":"2","age":"32"},{"name":"Henry","id":"5","age":"23"},{"name":"Marry","id":"1","age":"21"},{"name":"Henry","id":"4","age":"19"},{"name":"Audrey","id":"7","age":"17"},{"name":"Bob","id":"3","age":"15"}]



=== TEST 9: Order by name asc, age desc
--- request
GET /=/model/Foo/~/~?order_by=name:asc,age:desc
--- response
[{"name":"Audrey","id":"7","age":"17"},{"name":"Bob","id":"2","age":"32"},{"name":"Bob","id":"3","age":"15"},{"name":"Henry","id":"5","age":"23"},{"name":"Henry","id":"4","age":"19"},{"name":"Larry","id":"6","age":"59"},{"name":"Marry","id":"1","age":"21"}]



=== TEST 10: where name='Bob' order by age
--- request
GET /=/model/Foo/name/Bob?order_by=age
--- response
[{"name":"Bob","id":"2","age":"15"},{"name":"Bob","id":"2","age":"32"}]



=== TEST 11: where name='Bob' order by age, desc
--- request
GET /=/model/Foo/name/Bob?order_by=age
--- response
[{"name":"Bob","id":"2","age":"32"},{"name":"Bob","id":"2","age":"15"}]
