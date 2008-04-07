var sessionCookie = 'admin_session';
var serverCookie = 'admin_server';
var openresty = null;
var loadingCount = 0;
var waitMessage = null;
var savedAnchor = null;

$(document).ready(init);

function error (msg) {
    alert(msg);
}

function removeCookies () {
    //alert("Hey!");
    $.cookie(serverCookie, null, { path: '/' });
    $.cookie(sessionCookie, null, { path: '/' });
    location = 'login.html';
}

function init () {
    //alert("HERE!");
    var server = $.cookie(serverCookie);
    var session = $.cookie(sessionCookie);
    //alert("server: " + server);
    //alert("session: " + session);
    if (!server || !session) {
        location = 'login.html';
    }
    $("#logout-link").click(removeCookies);

    waitMessage = document.getElementById('wait-message');

    openresty = new OpenResty.Client({server: server});
    openresty.session = session;

    dispatchByAnchor();
    setInterval(dispatchByAnchor, 600);
}

function dispatchByAnchor () {
    var anchor = location.hash;
    anchor = anchor.replace(/^\#/, '');
    if (savedAnchor == anchor)
        return;
    if (anchor == "") {
        anchor = 'models';
        location.hash = 'models';
    }
    savedAnchor = anchor;

    // prevent memory leaks from dynamically created <script> nodes:
    if (loadingCount <= 0) openresty.purge();
    loadingCount = 0;

    if (anchor == 'models') {
        getModels( { cache: false } );
        return;
    }
}

function getModels (opts) {
    setStatus(true, 'getModels');
    if (opts.cache) {
        if (modelList != null) {
            renderModels(modelList);
            return;
        }
    } else {
        modelList = null;
    }
    openresty.callback = renderModels;
    openresty.get('/=/model');
    getModelMenu();
}

function getModelMenu () {
    setStatus(true, 'getModelMenu');
    if (modelList != null) {
        return renderModelMenu(modelList);
    }
    openresty.callback = renderModelMenu;
    openresty.get('/=/model');
}

function renderModels (res) {
    setStatus(false, 'getModels');
    if (!openresty.isSuccess(res)) {
        error("Failed to get model list: " + res.error);
        return;
    }
    $("#main").html(
        Jemplate.process(
            'model-list.tt',
            { models: res }
        )
    );
}

function renderModelMenu (res) {
    setStatus(false, 'getModelMenu');
    if (!openresty.isSuccess(res)) {
        error("Failed to get the model menu: " + res.error);
        return;
    }
    $("#menu").html(
        Jemplate.process(
            'menu.tt',
            { active_item: 'Models', submenu: res }
        )
    );
}

$.fn.postprocess = function (className, options) {
    return this.find("a[@href^='#']").each( function () {
        var anchor = $(this).attr('href').replace(/^\#/, '');
        //debug("Anchor: " + anchor);
        $(this).click( function () {
            //debug(location.hash);
            location.hash = anchor;
            //alert(location.hash);
            if (savedAnchor == anchor) savedAnchor = null;
            dispatchByAnchor();
        } );
    } );
};

function setStatus (isLoading, category) {
    if (isLoading) {
        if (++loadingCount == 1) {
            if (jQuery.browser.opera)
                $(waitMessage).css('top', '2px');
            else
                $(waitMessage).show();
        }
    } else {
        loadingCount--;
        if (loadingCount < 0) loadingCount = 0;
        if (loadingCount == 0) {
            // the reason we use this hack is to work around
            // a rendering bug in Win32 build of Opera
            // (at least 9.25 and 9.26)
            if (jQuery.browser.opera)
                $(waitMessage).css('top', '-200px');
            else
                $(waitMessage).hide();

        }
    }
    //count++;
    //debug("[" + count + "] setStatus: " + category + ": " + loadingCount + "(" + isLoading + ")");
}


/*
var display = function (res) {
    $("#output").text(JSON.stringify(res));
};

function get_model_list (res) {
    //alert("Res: " + JSON.stringify(res));
    if (res) display(res);
    //return;
    openresty.callback = render_model_list;
    openresty.get('/=/model');
}

function delete_model (model) {
    if (confirm("Do you really want to remove model " + model + "?")) {
        //alert("Deleting...");
        openresty.callback = 'get_model_list';
        openresty.del("/=/model/" + model);
    }
}

function render_model_list (data) {
    var html = Jemplate.process('model-list.tt2', { model_list: data });
    //alert(html);
    var model_list = $("#model-list");
    model_list.html(html);
    var links = $("a.del-model", model_list[0]);
    //alert(links.length);
    $(".editModelDesc").editable( function (value, settings) {
        var model_name = $(this).parent()[0].id;
        //alert(model_name);
        //alert(JSON.stringify(this));
        //var old_desc = this.revert;
        var new_desc = value;
        //alert("New desc: " + new_desc);
        //alert(new_desc);
        //alert("Changing model desciption from " + old_desc + " to " + new_desc);
        openresty.callback = 'handle_put_model';
        openresty.purge();
        openresty.put({ description: new_desc }, '/=/model/' + model_name);
        return "Saving...";
    }, {
        //type    : "textarea",
        style   : "display: inline",
        submit  : "Save",
        width : "132",
        height: "26",
        tooltop: "Click to edit"
    });

    $(".editModelName").editable( function (value, settings) {
        //console.log(settings);
        //alert("Renaming model " + old_val + " to " + new_val);
        //alert($(this).html());
        //alert(settings);
        //alert(blah);
        var old_name = this.revert;
        var new_name = value;
        //alert("Changing model name from " + old_name + " to " + new_name);
        openresty.callback = 'handle_put_model';
        openresty.purge();
        openresty.put({ name: new_name }, '/=/model/' + old_name);
        return "Saving...";
    }, {
        //type    : "textarea",
        style   : "display: inline",
        submit  : "Save",
        width : "132",
        height: "26",
        tooltop: "Click to edit"
    });
    //display(data);
}

function handle_put_model (res) {
    display(res);
    //alert("handle put model: " + JSON.stringify(res));
    get_model_list();
}

$(document).ready( function () {
    $("#new_model").submit(function () {
        var name = this.elements[0].value;
        //alert("name: " + name);
        var desc = this.elements[1].value;
        //alert("desc: " + desc);
        var data = {
            name: name,
            description: desc
        };
        openresty.callback = get_model_list;
        openresty.purge();
        openresty.post(data, "/=/model/~");
        return false;
    });
    var host = 'http://10.62.136.86';
    openresty = new OpenResty.Client(
        { server: host, callback: 'display' }
    );
    openresty.formId = 'new_model';
    openresty.callback = init;
    openresty.login('admin', '4423037');
} );

function init (data) {
    //alert("Hey!");
    get_model_list(data);
}
*/

