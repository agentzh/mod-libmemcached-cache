if (typeof window.OpenAPI == "undefined") {

window.undefined = window.undefined;

var OpenAPI = function (params) {
    if (params == undefined) params = {};
    this.callback = params.callback;
    this.server = params.server;
    if (!this.server) throw "No server specified for OpenAPI.new";
    if (!this.callback) throw "No callback specified for OpenAPI.new";
};

OpenAPI.prototype.get = function (url, args) {
    if (!args) args = {};
    if (url.match(/\?/)) throw "URL should not contain '?'.";
    args.rand = Math.random();
    args.callback = this.callback;
    var scriptTag = document.createElement("script");
    scriptTag.id = "openapiScriptTag";
    scriptTag.className = 'openapiScriptTag';
    var arg_list = new Array();
    for (var key in args) {
        arg_list.push(key + "=" + encodeURIComponent(args[key]));
    }
    scriptTag.src = this.server + url + "?" + arg_list.join("&");
    scriptTag.type = "text/javascript";
    var headTag = document.getElementsByTagName('head')[0];
    headTag.appendChild(scriptTag);
};

OpenAPI.purge = function () {
    // document.getElementByClassName('openapiScriptTag').remove();
    var nodes = document.getElementsByTagName('script');
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        if (node.className == 'openapiScriptTag') {
            node.removeNode(false);
        }
    }
};

}

