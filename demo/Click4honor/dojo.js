if(typeof dojo=="undefined"){
(function(){
if(typeof this["djConfig"]=="undefined"){
this.djConfig={};
}
if((!this["console"])||(!console["firebug"])){
this.console={};
}
var cn=["assert","count","debug","dir","dirxml","error","group","groupEnd","info","log","profile","profileEnd","time","timeEnd","trace","warn"];
var i=0,tn;
while((tn=cn[i++])){
if(!console[tn]){
console[tn]=function(){
};
}
}
if(typeof this["dojo"]=="undefined"){
this.dojo={};
}
var d=dojo;
dojo.global=this;
var _5={isDebug:false,libraryScriptUri:"",preventBackButtonFix:true,delayMozLoadingFix:false};
for(var _6 in _5){
if(typeof djConfig[_6]=="undefined"){
djConfig[_6]=_5[_6];
}
}
var _7=["Browser","Rhino","Spidermonkey","Mobile"];
var t;
while(t=_7.shift()){
d["is"+t]=false;
}
dojo.locale=djConfig.locale;
dojo.version={major:1,minor:0,patch:1,flag:"",revision:Number("$Rev: 11616 $".match(/[0-9]+/)[0]),toString:function(){
with(d.version){
return major+"."+minor+"."+patch+flag+" ("+revision+")";
}
}};
if(typeof OpenAjax!="undefined"){
OpenAjax.hub.registerLibrary("dojo","http://dojotoolkit.org",d.version.toString());
}
dojo._mixin=function(_9,_a){
var _b={};
for(var x in _a){
if(_b[x]===undefined||_b[x]!=_a[x]){
_9[x]=_a[x];
}
}
if(d["isIE"]&&_a){
var p=_a.toString;
if(typeof p=="function"&&p!=_9.toString&&p!=_b.toString&&p!="\nfunction toString() {\n    [native code]\n}\n"){
_9.toString=_a.toString;
}
}
return _9;
};
dojo.mixin=function(_e,_f){
for(var i=1,l=arguments.length;i<l;i++){
d._mixin(_e,arguments[i]);
}
return _e;
};
dojo._getProp=function(_12,_13,_14){
var obj=_14||d.global;
for(var i=0,p;obj&&(p=_12[i]);i++){
obj=(p in obj?obj[p]:(_13?obj[p]={}:undefined));
}
return obj;
};
dojo.setObject=function(_18,_19,_1a){
var _1b=_18.split("."),p=_1b.pop(),obj=d._getProp(_1b,true,_1a);
return (obj&&p?(obj[p]=_19):undefined);
};
dojo.getObject=function(_1e,_1f,_20){
return d._getProp(_1e.split("."),_1f,_20);
};
dojo.exists=function(_21,obj){
return !!d.getObject(_21,false,obj);
};
dojo["eval"]=function(_23){
return d.global.eval?d.global.eval(_23):eval(_23);
};
d.deprecated=d.experimental=function(){
};
})();
(function(){
var d=dojo;
dojo.mixin(dojo,{_loadedModules:{},_inFlightCount:0,_hasResource:{},_modulePrefixes:{dojo:{name:"dojo",value:"."},doh:{name:"doh",value:"../util/doh"},tests:{name:"tests",value:"tests"}},_moduleHasPrefix:function(_25){
var mp=this._modulePrefixes;
return !!(mp[_25]&&mp[_25].value);
},_getModulePrefix:function(_27){
var mp=this._modulePrefixes;
if(this._moduleHasPrefix(_27)){
return mp[_27].value;
}
return _27;
},_loadedUrls:[],_postLoad:false,_loaders:[],_unloaders:[],_loadNotifying:false});
dojo._loadPath=function(_29,_2a,cb){
var uri=(((_29.charAt(0)=="/"||_29.match(/^\w+:/)))?"":this.baseUrl)+_29;
if(djConfig.cacheBust&&d.isBrowser){
uri+="?"+String(djConfig.cacheBust).replace(/\W+/g,"");
}
try{
return !_2a?this._loadUri(uri,cb):this._loadUriAndCheck(uri,_2a,cb);
}
catch(e){
console.debug(e);
return false;
}
};
dojo._loadUri=function(uri,cb){
if(this._loadedUrls[uri]){
return true;
}
var _2f=this._getText(uri,true);
if(!_2f){
return false;
}
this._loadedUrls[uri]=true;
this._loadedUrls.push(uri);
if(cb){
_2f="("+_2f+")";
}
var _30=d["eval"](_2f+"\r\n//@ sourceURL="+uri);
if(cb){
cb(_30);
}
return true;
};
dojo._loadUriAndCheck=function(uri,_32,cb){
var ok=false;
try{
ok=this._loadUri(uri,cb);
}
catch(e){
console.debug("failed loading "+uri+" with error: "+e);
}
return Boolean(ok&&this._loadedModules[_32]);
};
dojo.loaded=function(){
this._loadNotifying=true;
this._postLoad=true;
var mll=this._loaders;
this._loaders=[];
for(var x=0;x<mll.length;x++){
mll[x]();
}
this._loadNotifying=false;
if(d._postLoad&&d._inFlightCount==0&&this._loaders.length>0){
d._callLoaded();
}
};
dojo.unloaded=function(){
var mll=this._unloaders;
while(mll.length){
(mll.pop())();
}
};
dojo.addOnLoad=function(obj,_39){
if(arguments.length==1){
d._loaders.push(obj);
}else{
if(arguments.length>1){
d._loaders.push(function(){
obj[_39]();
});
}
}
if(d._postLoad&&d._inFlightCount==0&&!d._loadNotifying){
d._callLoaded();
}
};
dojo.addOnUnload=function(obj,_3b){
if(arguments.length==1){
d._unloaders.push(obj);
}else{
if(arguments.length>1){
d._unloaders.push(function(){
obj[_3b]();
});
}
}
};
dojo._modulesLoaded=function(){
if(d._postLoad){
return;
}
if(d._inFlightCount>0){
console.debug("files still in flight!");
return;
}
d._callLoaded();
};
dojo._callLoaded=function(){
if(typeof setTimeout=="object"||(djConfig["useXDomain"]&&d.isOpera)){
setTimeout("dojo.loaded();",0);
}else{
d.loaded();
}
};
dojo._getModuleSymbols=function(_3c){
var _3d=_3c.split(".");
for(var i=_3d.length;i>0;i--){
var _3f=_3d.slice(0,i).join(".");
if((i==1)&&!this._moduleHasPrefix(_3f)){
_3d[0]="../"+_3d[0];
}else{
var _40=this._getModulePrefix(_3f);
if(_40!=_3f){
_3d.splice(0,i,_40);
break;
}
}
}
return _3d;
};
dojo._global_omit_module_check=false;
dojo._loadModule=dojo.require=function(_41,_42){
_42=this._global_omit_module_check||_42;
var _43=this._loadedModules[_41];
if(_43){
return _43;
}
var _44=this._getModuleSymbols(_41).join("/")+".js";
var _45=(!_42)?_41:null;
var ok=this._loadPath(_44,_45);
if((!ok)&&(!_42)){
throw new Error("Could not load '"+_41+"'; last tried '"+_44+"'");
}
if((!_42)&&(!this["_isXDomain"])){
_43=this._loadedModules[_41];
if(!_43){
throw new Error("symbol '"+_41+"' is not defined after loading '"+_44+"'");
}
}
return _43;
};
dojo.provide=function(_47){
_47=_47+"";
return (d._loadedModules[_47]=d.getObject(_47,true));
};
dojo.platformRequire=function(_48){
var _49=_48["common"]||[];
var _4a=_49.concat(_48[d._name]||_48["default"]||[]);
for(var x=0;x<_4a.length;x++){
var _4c=_4a[x];
if(_4c.constructor==Array){
d._loadModule.apply(d,_4c);
}else{
d._loadModule(_4c);
}
}
};
dojo.requireIf=function(_4d,_4e){
if(_4d===true){
var _4f=[];
for(var i=1;i<arguments.length;i++){
_4f.push(arguments[i]);
}
d.require.apply(d,_4f);
}
};
dojo.requireAfterIf=d.requireIf;
dojo.registerModulePath=function(_51,_52){
d._modulePrefixes[_51]={name:_51,value:_52};
};
dojo.requireLocalization=function(_53,_54,_55,_56){
d.require("dojo.i18n");
d.i18n._requireLocalization.apply(d.hostenv,arguments);
};
var ore=new RegExp("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?$");
var ire=new RegExp("^((([^:]+:)?([^@]+))@)?([^:]*)(:([0-9]+))?$");
dojo._Url=function(){
var n=null;
var _a=arguments;
var uri=_a[0];
for(var i=1;i<_a.length;i++){
if(!_a[i]){
continue;
}
var _5d=new d._Url(_a[i]+"");
var _5e=new d._Url(uri+"");
if((_5d.path=="")&&(!_5d.scheme)&&(!_5d.authority)&&(!_5d.query)){
if(_5d.fragment!=n){
_5e.fragment=_5d.fragment;
}
_5d=_5e;
}else{
if(!_5d.scheme){
_5d.scheme=_5e.scheme;
if(!_5d.authority){
_5d.authority=_5e.authority;
if(_5d.path.charAt(0)!="/"){
var _5f=_5e.path.substring(0,_5e.path.lastIndexOf("/")+1)+_5d.path;
var _60=_5f.split("/");
for(var j=0;j<_60.length;j++){
if(_60[j]=="."){
if(j==_60.length-1){
_60[j]="";
}else{
_60.splice(j,1);
j--;
}
}else{
if(j>0&&!(j==1&&_60[0]=="")&&_60[j]==".."&&_60[j-1]!=".."){
if(j==(_60.length-1)){
_60.splice(j,1);
_60[j-1]="";
}else{
_60.splice(j-1,2);
j-=2;
}
}
}
}
_5d.path=_60.join("/");
}
}
}
}
uri="";
if(_5d.scheme){
uri+=_5d.scheme+":";
}
if(_5d.authority){
uri+="//"+_5d.authority;
}
uri+=_5d.path;
if(_5d.query){
uri+="?"+_5d.query;
}
if(_5d.fragment){
uri+="#"+_5d.fragment;
}
}
this.uri=uri.toString();
var r=this.uri.match(ore);
this.scheme=r[2]||(r[1]?"":n);
this.authority=r[4]||(r[3]?"":n);
this.path=r[5];
this.query=r[7]||(r[6]?"":n);
this.fragment=r[9]||(r[8]?"":n);
if(this.authority!=n){
r=this.authority.match(ire);
this.user=r[3]||n;
this.password=r[4]||n;
this.host=r[5];
this.port=r[7]||n;
}
};
dojo._Url.prototype.toString=function(){
return this.uri;
};
dojo.moduleUrl=function(_63,url){
var loc=dojo._getModuleSymbols(_63).join("/");
if(!loc){
return null;
}
if(loc.lastIndexOf("/")!=loc.length-1){
loc+="/";
}
var _66=loc.indexOf(":");
if(loc.charAt(0)!="/"&&(_66==-1||_66>loc.indexOf("/"))){
loc=d.baseUrl+loc;
}
return new d._Url(loc,url);
};
})();
if(typeof window!="undefined"){
dojo.isBrowser=true;
dojo._name="browser";
(function(){
var d=dojo;
if(document&&document.getElementsByTagName){
var _68=document.getElementsByTagName("script");
var _69=/dojo(\.xd)?\.js([\?\.]|$)/i;
for(var i=0;i<_68.length;i++){
var src=_68[i].getAttribute("src");
if(!src){
continue;
}
var m=src.match(_69);
if(m){
if(!djConfig["baseUrl"]){
djConfig["baseUrl"]=src.substring(0,m.index);
}
var cfg=_68[i].getAttribute("djConfig");
if(cfg){
var _6e=eval("({ "+cfg+" })");
for(var x in _6e){
djConfig[x]=_6e[x];
}
}
break;
}
}
}
d.baseUrl=djConfig["baseUrl"];
var n=navigator;
var dua=n.userAgent;
var dav=n.appVersion;
var tv=parseFloat(dav);
d.isOpera=(dua.indexOf("Opera")>=0)?tv:0;
d.isKhtml=(dav.indexOf("Konqueror")>=0)||(dav.indexOf("Safari")>=0)?tv:0;
if(dav.indexOf("Safari")>=0){
var vi=dav.indexOf("Version/");
d.isSafari=(vi)?parseFloat(dav.substring(vi+8)):2;
}
var _75=dua.indexOf("Gecko");
d.isMozilla=d.isMoz=((_75>=0)&&(!d.isKhtml))?tv:0;
d.isFF=0;
d.isIE=0;
try{
if(d.isMoz){
d.isFF=parseFloat(dua.split("Firefox/")[1].split(" ")[0]);
}
if((document.all)&&(!d.isOpera)){
d.isIE=parseFloat(dav.split("MSIE ")[1].split(";")[0]);
}
}
catch(e){
}
if(dojo.isIE&&(window.location.protocol==="file:")){
djConfig.ieForceActiveXXhr=true;
}
var cm=document["compatMode"];
d.isQuirks=(cm=="BackCompat")||(cm=="QuirksMode")||(d.isIE<6);
d.locale=djConfig.locale||(d.isIE?n.userLanguage:n.language).toLowerCase();
d._println=console.debug;
d._XMLHTTP_PROGIDS=["Msxml2.XMLHTTP","Microsoft.XMLHTTP","Msxml2.XMLHTTP.4.0"];
d._xhrObj=function(){
var _77=null;
var _78=null;
if(!dojo.isIE||!djConfig.ieForceActiveXXhr){
try{
_77=new XMLHttpRequest();
}
catch(e){
}
}
if(!_77){
for(var i=0;i<3;++i){
var _7a=dojo._XMLHTTP_PROGIDS[i];
try{
_77=new ActiveXObject(_7a);
}
catch(e){
_78=e;
}
if(_77){
dojo._XMLHTTP_PROGIDS=[_7a];
break;
}
}
}
if(!_77){
throw new Error("XMLHTTP not available: "+_78);
}
return _77;
};
d._isDocumentOk=function(_7b){
var _7c=_7b.status||0;
return ((_7c>=200)&&(_7c<300))||(_7c==304)||(_7c==1223)||(!_7c&&(location.protocol=="file:"||location.protocol=="chrome:"));
};
var _7d=window.location+"";
var _7e=document.getElementsByTagName("base");
var _7f=(_7e&&_7e.length>0);
d._getText=function(uri,_81){
var _82=this._xhrObj();
if(!_7f&&dojo._Url){
uri=(new dojo._Url(_7d,uri)).toString();
}
_82.open("GET",uri,false);
try{
_82.send(null);
if(!d._isDocumentOk(_82)){
var err=Error("Unable to load "+uri+" status:"+_82.status);
err.status=_82.status;
err.responseText=_82.responseText;
throw err;
}
}
catch(e){
if(_81){
return null;
}
throw e;
}
return _82.responseText;
};
})();
dojo._initFired=false;
dojo._loadInit=function(e){
dojo._initFired=true;
var _85=(e&&e.type)?e.type.toLowerCase():"load";
if(arguments.callee.initialized||(_85!="domcontentloaded"&&_85!="load")){
return;
}
arguments.callee.initialized=true;
if(typeof dojo["_khtmlTimer"]!="undefined"){
clearInterval(dojo._khtmlTimer);
delete dojo._khtmlTimer;
}
if(dojo._inFlightCount==0){
dojo._modulesLoaded();
}
};
if(document.addEventListener){
if(dojo.isOpera||(dojo.isMoz&&(djConfig["enableMozDomContentLoaded"]===true))){
document.addEventListener("DOMContentLoaded",dojo._loadInit,null);
}
window.addEventListener("load",dojo._loadInit,null);
}
if(/(WebKit|khtml)/i.test(navigator.userAgent)){
dojo._khtmlTimer=setInterval(function(){
if(/loaded|complete/.test(document.readyState)){
dojo._loadInit();
}
},10);
}
(function(){
var _w=window;
var _87=function(_88,fp){
var _8a=_w[_88]||function(){
};
_w[_88]=function(){
fp.apply(_w,arguments);
_8a.apply(_w,arguments);
};
};
if(dojo.isIE){
document.write("<scr"+"ipt defer src=\"//:\" "+"onreadystatechange=\"if(this.readyState=='complete'){dojo._loadInit();}\">"+"</scr"+"ipt>");
var _8b=true;
_87("onbeforeunload",function(){
_w.setTimeout(function(){
_8b=false;
},0);
});
_87("onunload",function(){
if(_8b){
dojo.unloaded();
}
});
try{
document.namespaces.add("v","urn:schemas-microsoft-com:vml");
document.createStyleSheet().addRule("v\\:*","behavior:url(#default#VML)");
}
catch(e){
}
}else{
_87("onbeforeunload",function(){
dojo.unloaded();
});
}
})();
}
if(djConfig.isDebug){
dojo.require("dojo._firebug.firebug");
}
if(djConfig.debugAtAllCosts){
djConfig.useXDomain=true;
dojo.require("dojo._base._loader.loader_xd");
dojo.require("dojo._base._loader.loader_debug");
dojo.require("dojo.i18n");
}
}
if(!dojo._hasResource["dojo._base.lang"]){
dojo._hasResource["dojo._base.lang"]=true;
dojo.provide("dojo._base.lang");
dojo.isString=function(it){
return typeof it=="string"||it instanceof String;
};
dojo.isArray=function(it){
return it&&it instanceof Array||typeof it=="array";
};
dojo.isFunction=(function(){
var _8e=function(it){
return typeof it=="function"||it instanceof Function;
};
return dojo.isSafari?function(it){
if(typeof it=="function"&&it=="[object NodeList]"){
return false;
}
return _8e(it);
}:_8e;
})();
dojo.isObject=function(it){
return it!==undefined&&(it===null||typeof it=="object"||dojo.isArray(it)||dojo.isFunction(it));
};
dojo.isArrayLike=function(it){
var d=dojo;
return it&&it!==undefined&&!d.isString(it)&&!d.isFunction(it)&&!(it.tagName&&it.tagName.toLowerCase()=="form")&&(d.isArray(it)||isFinite(it.length));
};
dojo.isAlien=function(it){
return it&&!dojo.isFunction(it)&&/\{\s*\[native code\]\s*\}/.test(String(it));
};
dojo.extend=function(_95,_96){
for(var i=1,l=arguments.length;i<l;i++){
dojo._mixin(_95.prototype,arguments[i]);
}
return _95;
};
dojo._hitchArgs=function(_99,_9a){
var pre=dojo._toArray(arguments,2);
var _9c=dojo.isString(_9a);
return function(){
var _9d=dojo._toArray(arguments);
var f=_9c?(_99||dojo.global)[_9a]:_9a;
return f&&f.apply(_99||this,pre.concat(_9d));
};
};
dojo.hitch=function(_9f,_a0){
if(arguments.length>2){
return dojo._hitchArgs.apply(dojo,arguments);
}
if(!_a0){
_a0=_9f;
_9f=null;
}
if(dojo.isString(_a0)){
_9f=_9f||dojo.global;
if(!_9f[_a0]){
throw (["dojo.hitch: scope[\"",_a0,"\"] is null (scope=\"",_9f,"\")"].join(""));
}
return function(){
return _9f[_a0].apply(_9f,arguments||[]);
};
}
return !_9f?_a0:function(){
return _a0.apply(_9f,arguments||[]);
};
};
dojo.delegate=dojo._delegate=function(obj,_a2){
function TMP(){
}
TMP.prototype=obj;
var tmp=new TMP();
if(_a2){
dojo.mixin(tmp,_a2);
}
return tmp;
};
dojo.partial=function(_a4){
var arr=[null];
return dojo.hitch.apply(dojo,arr.concat(dojo._toArray(arguments)));
};
dojo._toArray=function(obj,_a7,_a8){
var arr=_a8||[];
for(var x=_a7||0;x<obj.length;x++){
arr.push(obj[x]);
}
return arr;
};
dojo.clone=function(o){
if(!o){
return o;
}
if(dojo.isArray(o)){
var r=[];
for(var i=0;i<o.length;++i){
r.push(dojo.clone(o[i]));
}
return r;
}else{
if(dojo.isObject(o)){
if(o.nodeType&&o.cloneNode){
return o.cloneNode(true);
}else{
var r=new o.constructor();
for(var i in o){
if(!(i in r)||r[i]!=o[i]){
r[i]=dojo.clone(o[i]);
}
}
return r;
}
}
}
return o;
};
dojo.trim=function(str){
return str.replace(/^\s\s*/,"").replace(/\s\s*$/,"");
};
}
if(!dojo._hasResource["dojo._base.declare"]){
dojo._hasResource["dojo._base.declare"]=true;
dojo.provide("dojo._base.declare");
dojo.declare=function(_af,_b0,_b1){
if(dojo.isFunction(_b1)||(arguments.length>3)){
dojo.deprecated("dojo.declare: for class '"+_af+"' pass initializer function as 'constructor' property instead of as a separate argument.","","1.0");
var c=_b1;
_b1=arguments[3]||{};
_b1.constructor=c;
}
var dd=arguments.callee,_b4=null;
if(dojo.isArray(_b0)){
_b4=_b0;
_b0=_b4.shift();
}
if(_b4){
for(var i=0,m;i<_b4.length;i++){
m=_b4[i];
if(!m){
throw ("Mixin #"+i+" to declaration of "+_af+" is null. It's likely a required module is not loaded.");
}
_b0=dd._delegate(_b0,m);
}
}
var _b7=(_b1||0).constructor,_b8=dd._delegate(_b0),fn;
for(var i in _b1){
if(dojo.isFunction(fn=_b1[i])&&(!0[i])){
fn.nom=i;
}
}
dojo.extend(_b8,{declaredClass:_af,_constructor:_b7,preamble:null},_b1||0);
_b8.prototype.constructor=_b8;
return dojo.setObject(_af,_b8);
};
dojo.mixin(dojo.declare,{_delegate:function(_ba,_bb){
var bp=(_ba||0).prototype,mp=(_bb||0).prototype;
var _be=dojo.declare._makeCtor();
dojo.mixin(_be,{superclass:bp,mixin:mp,extend:dojo.declare._extend});
if(_ba){
_be.prototype=dojo._delegate(bp);
}
dojo.extend(_be,dojo.declare._core,mp||0,{_constructor:null,preamble:null});
_be.prototype.constructor=_be;
_be.prototype.declaredClass=(bp||0).declaredClass+"_"+(mp||0).declaredClass;
return _be;
},_extend:function(_bf){
for(var i in _bf){
if(dojo.isFunction(fn=_bf[i])&&(!0[i])){
fn.nom=i;
}
}
dojo.extend(this,_bf);
},_makeCtor:function(){
return function(){
this._construct(arguments);
};
},_core:{_construct:function(_c1){
var c=_c1.callee,s=c.superclass,ct=s&&s.constructor,m=c.mixin,mct=m&&m.constructor,a=_c1,ii,fn;
if(a[0]){
if((fn=a[0]["preamble"])){
a=fn.apply(this,a)||a;
}
}
if(fn=c.prototype.preamble){
a=fn.apply(this,a)||a;
}
if(ct&&ct.apply){
ct.apply(this,a);
}
if(mct&&mct.apply){
mct.apply(this,a);
}
if(ii=c.prototype._constructor){
ii.apply(this,_c1);
}
if(this.constructor.prototype==c.prototype&&(ct=this.postscript)){
ct.apply(this,_c1);
}
},_findMixin:function(_ca){
var c=this.constructor,p,m;
while(c){
p=c.superclass;
m=c.mixin;
if(m==_ca||(m instanceof _ca.constructor)){
return p;
}
if(m&&(m=m._findMixin(_ca))){
return m;
}
c=p&&p.constructor;
}
},_findMethod:function(_ce,_cf,_d0,has){
var p=_d0,c,m,f;
do{
c=p.constructor;
m=c.mixin;
if(m&&(m=this._findMethod(_ce,_cf,m,has))){
return m;
}
if((f=p[_ce])&&(has==(f==_cf))){
return p;
}
p=c.superclass;
}while(p);
return !has&&(p=this._findMixin(_d0))&&this._findMethod(_ce,_cf,p,has);
},inherited:function(_d6,_d7,_d8){
var a=arguments;
if(!dojo.isString(a[0])){
_d8=_d7;
_d7=_d6;
_d6=_d7.callee.nom;
}
var c=_d7.callee,p=this.constructor.prototype,a=_d8||_d7,fn,mp;
if(this[_d6]!=c||p[_d6]==c){
mp=this._findMethod(_d6,c,p,true);
if(!mp){
throw (this.declaredClass+": name argument (\""+_d6+"\") to inherited must match callee (declare.js)");
}
p=this._findMethod(_d6,c,mp,false);
}
fn=p&&p[_d6];
if(!fn){
console.debug(mp.declaredClass+": no inherited \""+_d6+"\" was found (declare.js)");
return;
}
return fn.apply(this,a);
}}});
}
if(!dojo._hasResource["dojo._base.connect"]){
dojo._hasResource["dojo._base.connect"]=true;
dojo.provide("dojo._base.connect");
dojo._listener={getDispatcher:function(){
return function(){
var ap=Array.prototype,c=arguments.callee,ls=c._listeners,t=c.target;
var r=t&&t.apply(this,arguments);
for(var i in ls){
if(!(i in ap)){
ls[i].apply(this,arguments);
}
}
return r;
};
},add:function(_e4,_e5,_e6){
_e4=_e4||dojo.global;
var f=_e4[_e5];
if(!f||!f._listeners){
var d=dojo._listener.getDispatcher();
d.target=f;
d._listeners=[];
f=_e4[_e5]=d;
}
return f._listeners.push(_e6);
},remove:function(_e9,_ea,_eb){
var f=(_e9||dojo.global)[_ea];
if(f&&f._listeners&&_eb--){
delete f._listeners[_eb];
}
}};
dojo.connect=function(obj,_ee,_ef,_f0,_f1){
var a=arguments,_f3=[],i=0;
_f3.push(dojo.isString(a[0])?null:a[i++],a[i++]);
var a1=a[i+1];
_f3.push(dojo.isString(a1)||dojo.isFunction(a1)?a[i++]:null,a[i++]);
for(var l=a.length;i<l;i++){
_f3.push(a[i]);
}
return dojo._connect.apply(this,_f3);
};
dojo._connect=function(obj,_f8,_f9,_fa){
var l=dojo._listener,h=l.add(obj,_f8,dojo.hitch(_f9,_fa));
return [obj,_f8,h,l];
};
dojo.disconnect=function(_fd){
if(_fd&&_fd[0]!==undefined){
dojo._disconnect.apply(this,_fd);
delete _fd[0];
}
};
dojo._disconnect=function(obj,_ff,_e3,_e4){
_e4.remove(obj,_ff,_e3);
};
dojo._topics={};
dojo.subscribe=function(_e5,_e6,_e7){
return [_e5,dojo._listener.add(dojo._topics,_e5,dojo.hitch(_e6,_e7))];
};
dojo.unsubscribe=function(_e8){
if(_e8){
dojo._listener.remove(dojo._topics,_e8[0],_e8[1]);
}
};
dojo.publish=function(_e9,_ea){
var f=dojo._topics[_e9];
if(f){
f.apply(this,_ea||[]);
}
};
dojo.connectPublisher=function(_ec,obj,_ee){
var pf=function(){
dojo.publish(_ec,arguments);
};
return (_ee)?dojo.connect(obj,_ee,pf):dojo.connect(obj,pf);
};
}
if(!dojo._hasResource["dojo._base.Deferred"]){
dojo._hasResource["dojo._base.Deferred"]=true;
dojo.provide("dojo._base.Deferred");
dojo.Deferred=function(_f0){
this.chain=[];
this.id=this._nextId();
this.fired=-1;
this.paused=0;
this.results=[null,null];
this.canceller=_f0;
this.silentlyCancelled=false;
};
dojo.extend(dojo.Deferred,{_nextId:(function(){
var n=1;
return function(){
return n++;
};
})(),cancel:function(){
var err;
if(this.fired==-1){
if(this.canceller){
err=this.canceller(this);
}else{
this.silentlyCancelled=true;
}
if(this.fired==-1){
if(!(err instanceof Error)){
var res=err;
err=new Error("Deferred Cancelled");
err.dojoType="cancel";
err.cancelResult=res;
}
this.errback(err);
}
}else{
if((this.fired==0)&&(this.results[0] instanceof dojo.Deferred)){
this.results[0].cancel();
}
}
},_resback:function(res){
this.fired=((res instanceof Error)?1:0);
this.results[this.fired]=res;
this._fire();
},_check:function(){
if(this.fired!=-1){
if(!this.silentlyCancelled){
throw new Error("already called!");
}
this.silentlyCancelled=false;
return;
}
},callback:function(res){
this._check();
this._resback(res);
},errback:function(res){
this._check();
if(!(res instanceof Error)){
res=new Error(res);
}
this._resback(res);
},addBoth:function(cb,_f8){
var _f9=dojo.hitch(cb,_f8);
if(arguments.length>2){
_f9=dojo.partial(_f9,arguments,2);
}
return this.addCallbacks(_f9,_f9);
},addCallback:function(cb,_fb){
var _fc=dojo.hitch(cb,_fb);
if(arguments.length>2){
_fc=dojo.partial(_fc,arguments,2);
}
return this.addCallbacks(_fc,null);
},addErrback:function(cb,_fe){
var _ff=dojo.hitch(cb,_fe);
if(arguments.length>2){
_ff=dojo.partial(_ff,arguments,2);
}
return this.addCallbacks(null,_ff);
},addCallbacks:function(cb,eb){
this.chain.push([cb,eb]);
if(this.fired>=0){
this._fire();
}
return this;
},_fire:function(){
var _11f=this.chain;
var _120=this.fired;
var res=this.results[_120];
var self=this;
var cb=null;
while((_11f.length>0)&&(this.paused==0)){
var f=_11f.shift()[_120];
if(!f){
continue;
}
try{
res=f(res);
_120=((res instanceof Error)?1:0);
if(res instanceof dojo.Deferred){
cb=function(res){
self._resback(res);
self.paused--;
if((self.paused==0)&&(self.fired>=0)){
self._fire();
}
};
this.paused++;
}
}
catch(err){
console.debug(err);
_120=1;
res=err;
}
}
this.fired=_120;
this.results[_120]=res;
if((cb)&&(this.paused)){
res.addBoth(cb);
}
}});
}
if(!dojo._hasResource["dojo._base.json"]){
dojo._hasResource["dojo._base.json"]=true;
dojo.provide("dojo._base.json");
dojo.fromJson=function(json){
try{
return eval("("+json+")");
}
catch(e){
console.debug(e);
return json;
}
};
dojo._escapeString=function(str){
return ("\""+str.replace(/(["\\])/g,"\\$1")+"\"").replace(/[\f]/g,"\\f").replace(/[\b]/g,"\\b").replace(/[\n]/g,"\\n").replace(/[\t]/g,"\\t").replace(/[\r]/g,"\\r");
};
dojo.toJsonIndentStr="\t";
dojo.toJson=function(it,_129,_12a){
_12a=_12a||"";
var _12b=(_129?_12a+dojo.toJsonIndentStr:"");
var _12c=(_129?"\n":"");
var _12d=typeof (it);
if(_12d=="undefined"){
return "undefined";
}else{
if((_12d=="number")||(_12d=="boolean")){
return it+"";
}else{
if(it===null){
return "null";
}
}
}
if(dojo.isString(it)){
return dojo._escapeString(it);
}
if(it.nodeType&&it.cloneNode){
return "";
}
var _12e=arguments.callee;
var _12f;
if(typeof it.__json__=="function"){
_12f=it.__json__();
if(it!==_12f){
return _12e(_12f,_129,_12b);
}
}
if(typeof it.json=="function"){
_12f=it.json();
if(it!==_12f){
return _12e(_12f,_129,_12b);
}
}
if(dojo.isArray(it)){
var res=[];
for(var i=0;i<it.length;i++){
var val=_12e(it[i],_129,_12b);
if(typeof (val)!="string"){
val="undefined";
}
res.push(_12c+_12b+val);
}
return "["+res.join(", ")+_12c+_12a+"]";
}
if(_12d=="function"){
return null;
}
var _133=[];
for(var key in it){
var _135;
if(typeof (key)=="number"){
_135="\""+key+"\"";
}else{
if(typeof (key)=="string"){
_135=dojo._escapeString(key);
}else{
continue;
}
}
val=_12e(it[key],_129,_12b);
if(typeof (val)!="string"){
continue;
}
_133.push(_12c+_12b+_135+": "+val);
}
return "{"+_133.join(", ")+_12c+_12a+"}";
};
}
if(!dojo._hasResource["dojo._base.array"]){
dojo._hasResource["dojo._base.array"]=true;
dojo.provide("dojo._base.array");
(function(){
var _136=function(arr,obj,cb){
return [(dojo.isString(arr)?arr.split(""):arr),(obj||dojo.global),(dojo.isString(cb)?(new Function("item","index","array",cb)):cb)];
};
dojo.mixin(dojo,{indexOf:function(_13a,_13b,_13c,_13d){
var i=0,step=1,end=_13a.length;
if(_13d){
i=end-1;
step=end=-1;
}
for(i=_13c||i;i!=end;i+=step){
if(_13a[i]==_13b){
return i;
}
}
return -1;
},lastIndexOf:function(_141,_142,_143){
return dojo.indexOf(_141,_142,_143,true);
},forEach:function(arr,_145,obj){
if(!arr||!arr.length){
return;
}
var _p=_136(arr,obj,_145);
arr=_p[0];
for(var i=0,l=_p[0].length;i<l;i++){
_p[2].call(_p[1],arr[i],i,arr);
}
},_everyOrSome:function(_14a,arr,_14c,obj){
var _p=_136(arr,obj,_14c);
arr=_p[0];
for(var i=0,l=arr.length;i<l;i++){
var _151=!!_p[2].call(_p[1],arr[i],i,arr);
if(_14a^_151){
return _151;
}
}
return _14a;
},every:function(arr,_153,_154){
return this._everyOrSome(true,arr,_153,_154);
},some:function(arr,_156,_157){
return this._everyOrSome(false,arr,_156,_157);
},map:function(arr,func,obj){
var _p=_136(arr,obj,func);
arr=_p[0];
var _15c=((arguments[3])?(new arguments[3]()):[]);
for(var i=0;i<arr.length;++i){
_15c.push(_p[2].call(_p[1],arr[i],i,arr));
}
return _15c;
},filter:function(arr,_15f,obj){
var _p=_136(arr,obj,_15f);
arr=_p[0];
var _162=[];
for(var i=0;i<arr.length;i++){
if(_p[2].call(_p[1],arr[i],i,arr)){
_162.push(arr[i]);
}
}
return _162;
}});
})();
}
if(!dojo._hasResource["dojo._base.Color"]){
dojo._hasResource["dojo._base.Color"]=true;
dojo.provide("dojo._base.Color");
dojo.Color=function(_164){
if(_164){
this.setColor(_164);
}
};
dojo.Color.named={black:[0,0,0],silver:[192,192,192],gray:[128,128,128],white:[255,255,255],maroon:[128,0,0],red:[255,0,0],purple:[128,0,128],fuchsia:[255,0,255],green:[0,128,0],lime:[0,255,0],olive:[128,128,0],yellow:[255,255,0],navy:[0,0,128],blue:[0,0,255],teal:[0,128,128],aqua:[0,255,255]};
dojo.extend(dojo.Color,{r:255,g:255,b:255,a:1,_set:function(r,g,b,a){
var t=this;
t.r=r;
t.g=g;
t.b=b;
t.a=a;
},setColor:function(_16a){
var d=dojo;
if(d.isString(_16a)){
d.colorFromString(_16a,this);
}else{
if(d.isArray(_16a)){
d.colorFromArray(_16a,this);
}else{
this._set(_16a.r,_16a.g,_16a.b,_16a.a);
if(!(_16a instanceof d.Color)){
this.sanitize();
}
}
}
return this;
},sanitize:function(){
return this;
},toRgb:function(){
var t=this;
return [t.r,t.g,t.b];
},toRgba:function(){
var t=this;
return [t.r,t.g,t.b,t.a];
},toHex:function(){
var arr=dojo.map(["r","g","b"],function(x){
var s=this[x].toString(16);
return s.length<2?"0"+s:s;
},this);
return "#"+arr.join("");
},toCss:function(_171){
var t=this,rgb=t.r+", "+t.g+", "+t.b;
return (_171?"rgba("+rgb+", "+t.a:"rgb("+rgb)+")";
},toString:function(){
return this.toCss(true);
}});
dojo.blendColors=function(_174,end,_176,obj){
var d=dojo,t=obj||new dojo.Color();
d.forEach(["r","g","b","a"],function(x){
t[x]=_174[x]+(end[x]-_174[x])*_176;
if(x!="a"){
t[x]=Math.round(t[x]);
}
});
return t.sanitize();
};
dojo.colorFromRgb=function(_17b,obj){
var m=_17b.toLowerCase().match(/^rgba?\(([\s\.,0-9]+)\)/);
return m&&dojo.colorFromArray(m[1].split(/\s*,\s*/),obj);
};
dojo.colorFromHex=function(_17e,obj){
var d=dojo,t=obj||new d.Color(),bits=(_17e.length==4)?4:8,mask=(1<<bits)-1;
_17e=Number("0x"+_17e.substr(1));
if(isNaN(_17e)){
return null;
}
d.forEach(["b","g","r"],function(x){
var c=_17e&mask;
_17e>>=bits;
t[x]=bits==4?17*c:c;
});
t.a=1;
return t;
};
dojo.colorFromArray=function(a,obj){
var t=obj||new dojo.Color();
t._set(Number(a[0]),Number(a[1]),Number(a[2]),Number(a[3]));
if(isNaN(t.a)){
t.a=1;
}
return t.sanitize();
};
dojo.colorFromString=function(str,obj){
var a=dojo.Color.named[str];
return a&&dojo.colorFromArray(a,obj)||dojo.colorFromRgb(str,obj)||dojo.colorFromHex(str,obj);
};
}
if(!dojo._hasResource["dojo._base"]){
dojo._hasResource["dojo._base"]=true;
dojo.provide("dojo._base");
(function(){
if(djConfig.require){
for(var x=0;x<djConfig.require.length;x++){
dojo["require"](djConfig.require[x]);
}
}
})();
}
if(!dojo._hasResource["dojo._base.window"]){
dojo._hasResource["dojo._base.window"]=true;
dojo.provide("dojo._base.window");
dojo._gearsObject=function(){
var _18d;
var _18e;
var _18f=dojo.getObject("google.gears");
if(_18f){
return _18f;
}
if(typeof GearsFactory!="undefined"){
_18d=new GearsFactory();
}else{
if(dojo.isIE){
try{
_18d=new ActiveXObject("Gears.Factory");
}
catch(e){
}
}else{
if(navigator.mimeTypes["application/x-googlegears"]){
_18d=document.createElement("object");
_18d.setAttribute("type","application/x-googlegears");
_18d.setAttribute("width",0);
_18d.setAttribute("height",0);
_18d.style.display="none";
document.documentElement.appendChild(_18d);
}
}
}
if(!_18d){
return null;
}
dojo.setObject("google.gears.factory",_18d);
return dojo.getObject("google.gears");
};
dojo.isGears=(!!dojo._gearsObject())||0;
dojo.doc=window["document"]||null;
dojo.body=function(){
return dojo.doc.body||dojo.doc.getElementsByTagName("body")[0];
};
dojo.setContext=function(_190,_191){
dojo.global=_190;
dojo.doc=_191;
};
dojo._fireCallback=function(_192,_193,_194){
if(_193&&dojo.isString(_192)){
_192=_193[_192];
}
return (_193?_192.apply(_193,_194||[]):_192());
};
dojo.withGlobal=function(_195,_196,_197,_198){
var rval;
var _19a=dojo.global;
var _19b=dojo.doc;
try{
dojo.setContext(_195,_195.document);
rval=dojo._fireCallback(_196,_197,_198);
}
finally{
dojo.setContext(_19a,_19b);
}
return rval;
};
dojo.withDoc=function(_19c,_19d,_19e,_19f){
var rval;
var _1a1=dojo.doc;
try{
dojo.doc=_19c;
rval=dojo._fireCallback(_19d,_19e,_19f);
}
finally{
dojo.doc=_1a1;
}
return rval;
};
(function(){
var mp=djConfig["modulePaths"];
if(mp){
for(var _1a3 in mp){
dojo.registerModulePath(_1a3,mp[_1a3]);
}
}
})();
}
if(!dojo._hasResource["dojo._base.event"]){
dojo._hasResource["dojo._base.event"]=true;
dojo.provide("dojo._base.event");
(function(){
var del=dojo._event_listener={add:function(node,name,fp){
if(!node){
return;
}
name=del._normalizeEventName(name);
fp=del._fixCallback(name,fp);
var _1a8=name;
if((!dojo.isIE)&&((name=="mouseenter")||(name=="mouseleave"))){
var _1a8=name;
var ofp=fp;
name=(name=="mouseenter")?"mouseover":"mouseout";
fp=function(e){
var id=dojo.isDescendant(e.relatedTarget,node);
if(id==false){
return ofp.call(this,e);
}
};
}
node.addEventListener(name,fp,false);
return fp;
},remove:function(node,_1ad,_1ae){
(node)&&(node.removeEventListener(del._normalizeEventName(_1ad),_1ae,false));
},_normalizeEventName:function(name){
return (name.slice(0,2)=="on"?name.slice(2):name);
},_fixCallback:function(name,fp){
return (name!="keypress"?fp:function(e){
return fp.call(this,del._fixEvent(e,this));
});
},_fixEvent:function(evt,_1b4){
switch(evt.type){
case "keypress":
del._setKeyChar(evt);
break;
}
return evt;
},_setKeyChar:function(evt){
evt.keyChar=(evt.charCode?String.fromCharCode(evt.charCode):"");
}};
dojo.fixEvent=function(evt,_1b7){
return del._fixEvent(evt,_1b7);
};
dojo.stopEvent=function(evt){
evt.preventDefault();
evt.stopPropagation();
};
var _1b9=dojo._listener;
dojo._connect=function(obj,_1bb,_1bc,_1bd,_1be){
var _1bf=obj&&(obj.nodeType||obj.attachEvent||obj.addEventListener);
var lid=!_1bf?0:(!_1be?1:2),l=[dojo._listener,del,_1b9][lid];
var h=l.add(obj,_1bb,dojo.hitch(_1bc,_1bd));
return [obj,_1bb,h,lid];
};
dojo._disconnect=function(obj,_1c4,_1c5,_1c6){
([dojo._listener,del,_1b9][_1c6]).remove(obj,_1c4,_1c5);
};
dojo.keys={BACKSPACE:8,TAB:9,CLEAR:12,ENTER:13,SHIFT:16,CTRL:17,ALT:18,PAUSE:19,CAPS_LOCK:20,ESCAPE:27,SPACE:32,PAGE_UP:33,PAGE_DOWN:34,END:35,HOME:36,LEFT_ARROW:37,UP_ARROW:38,RIGHT_ARROW:39,DOWN_ARROW:40,INSERT:45,DELETE:46,HELP:47,LEFT_WINDOW:91,RIGHT_WINDOW:92,SELECT:93,NUMPAD_0:96,NUMPAD_1:97,NUMPAD_2:98,NUMPAD_3:99,NUMPAD_4:100,NUMPAD_5:101,NUMPAD_6:102,NUMPAD_7:103,NUMPAD_8:104,NUMPAD_9:105,NUMPAD_MULTIPLY:106,NUMPAD_PLUS:107,NUMPAD_ENTER:108,NUMPAD_MINUS:109,NUMPAD_PERIOD:110,NUMPAD_DIVIDE:111,F1:112,F2:113,F3:114,F4:115,F5:116,F6:117,F7:118,F8:119,F9:120,F10:121,F11:122,F12:123,F13:124,F14:125,F15:126,NUM_LOCK:144,SCROLL_LOCK:145};
if(dojo.isIE){
var _1c7=function(e,code){
try{
return (e.keyCode=code);
}
catch(e){
return 0;
}
};
var iel=dojo._listener;
if(!djConfig._allow_leaks){
_1b9=iel=dojo._ie_listener={handlers:[],add:function(_1cb,_1cc,_1cd){
_1cb=_1cb||dojo.global;
var f=_1cb[_1cc];
if(!f||!f._listeners){
var d=dojo._getIeDispatcher();
d.target=f&&(ieh.push(f)-1);
d._listeners=[];
f=_1cb[_1cc]=d;
}
return f._listeners.push(ieh.push(_1cd)-1);
},remove:function(_1d1,_1d2,_1d3){
var f=(_1d1||dojo.global)[_1d2],l=f&&f._listeners;
if(f&&l&&_1d3--){
delete ieh[l[_1d3]];
delete l[_1d3];
}
}};
var ieh=iel.handlers;
}
dojo.mixin(del,{add:function(node,_1d7,fp){
if(!node){
return;
}
_1d7=del._normalizeEventName(_1d7);
if(_1d7=="onkeypress"){
var kd=node.onkeydown;
if(!kd||!kd._listeners||!kd._stealthKeydown){
del.add(node,"onkeydown",del._stealthKeyDown);
node.onkeydown._stealthKeydown=true;
}
}
return iel.add(node,_1d7,del._fixCallback(fp));
},remove:function(node,_1db,_1dc){
iel.remove(node,del._normalizeEventName(_1db),_1dc);
},_normalizeEventName:function(_1dd){
return (_1dd.slice(0,2)!="on"?"on"+_1dd:_1dd);
},_nop:function(){
},_fixEvent:function(evt,_1df){
if(!evt){
var w=(_1df)&&((_1df.ownerDocument||_1df.document||_1df).parentWindow)||window;
evt=w.event;
}
if(!evt){
return (evt);
}
evt.target=evt.srcElement;
evt.currentTarget=(_1df||evt.srcElement);
evt.layerX=evt.offsetX;
evt.layerY=evt.offsetY;
var se=evt.srcElement,doc=(se&&se.ownerDocument)||document;
var _1e3=((dojo.isIE<6)||(doc["compatMode"]=="BackCompat"))?doc.body:doc.documentElement;
var _1e4=dojo._getIeDocumentElementOffset();
evt.pageX=evt.clientX+dojo._fixIeBiDiScrollLeft(_1e3.scrollLeft||0)-_1e4.x;
evt.pageY=evt.clientY+(_1e3.scrollTop||0)-_1e4.y;
if(evt.type=="mouseover"){
evt.relatedTarget=evt.fromElement;
}
if(evt.type=="mouseout"){
evt.relatedTarget=evt.toElement;
}
evt.stopPropagation=del._stopPropagation;
evt.preventDefault=del._preventDefault;
return del._fixKeys(evt);
},_fixKeys:function(evt){
switch(evt.type){
case "keypress":
var c=("charCode" in evt?evt.charCode:evt.keyCode);
if(c==10){
c=0;
evt.keyCode=13;
}else{
if(c==13||c==27){
c=0;
}else{
if(c==3){
c=99;
}
}
}
evt.charCode=c;
del._setKeyChar(evt);
break;
}
return evt;
},_punctMap:{106:42,111:47,186:59,187:43,188:44,189:45,190:46,191:47,192:96,219:91,220:92,221:93,222:39},_stealthKeyDown:function(evt){
var kp=evt.currentTarget.onkeypress;
if(!kp||!kp._listeners){
return;
}
var k=evt.keyCode;
var _1ea=(k!=13)&&(k!=32)&&(k!=27)&&(k<48||k>90)&&(k<96||k>111)&&(k<186||k>192)&&(k<219||k>222);
if(_1ea||evt.ctrlKey){
var c=(_1ea?0:k);
if(evt.ctrlKey){
if(k==3||k==13){
return;
}else{
if(c>95&&c<106){
c-=48;
}else{
if((!evt.shiftKey)&&(c>=65&&c<=90)){
c+=32;
}else{
c=del._punctMap[c]||c;
}
}
}
}
var faux=del._synthesizeEvent(evt,{type:"keypress",faux:true,charCode:c});
kp.call(evt.currentTarget,faux);
evt.cancelBubble=faux.cancelBubble;
evt.returnValue=faux.returnValue;
_1c7(evt,faux.keyCode);
}
},_stopPropagation:function(){
this.cancelBubble=true;
},_preventDefault:function(){
this.bubbledKeyCode=this.keyCode;
if(this.ctrlKey){
_1c7(this,0);
}
this.returnValue=false;
}});
dojo.stopEvent=function(evt){
evt=evt||window.event;
del._stopPropagation.call(evt);
del._preventDefault.call(evt);
};
}
del._synthesizeEvent=function(evt,_1ef){
var faux=dojo.mixin({},evt,_1ef);
del._setKeyChar(faux);
faux.preventDefault=function(){
evt.preventDefault();
};
faux.stopPropagation=function(){
evt.stopPropagation();
};
return faux;
};
if(dojo.isOpera){
dojo.mixin(del,{_fixEvent:function(evt,_1f2){
switch(evt.type){
case "keypress":
var c=evt.which;
if(c==3){
c=99;
}
c=((c<41)&&(!evt.shiftKey)?0:c);
if((evt.ctrlKey)&&(!evt.shiftKey)&&(c>=65)&&(c<=90)){
c+=32;
}
return del._synthesizeEvent(evt,{charCode:c});
}
return evt;
}});
}
if(dojo.isSafari){
dojo.mixin(del,{_fixEvent:function(evt,_1f5){
switch(evt.type){
case "keypress":
var c=evt.charCode,s=evt.shiftKey,k=evt.keyCode;
k=k||_1f9[evt.keyIdentifier]||0;
if(evt.keyIdentifier=="Enter"){
c=0;
}else{
if((evt.ctrlKey)&&(c>0)&&(c<27)){
c+=96;
}else{
if(c==dojo.keys.SHIFT_TAB){
c=dojo.keys.TAB;
s=true;
}else{
c=(c>=32&&c<63232?c:0);
}
}
}
return del._synthesizeEvent(evt,{charCode:c,shiftKey:s,keyCode:k});
}
return evt;
}});
dojo.mixin(dojo.keys,{SHIFT_TAB:25,UP_ARROW:63232,DOWN_ARROW:63233,LEFT_ARROW:63234,RIGHT_ARROW:63235,F1:63236,F2:63237,F3:63238,F4:63239,F5:63240,F6:63241,F7:63242,F8:63243,F9:63244,F10:63245,F11:63246,F12:63247,PAUSE:63250,DELETE:63272,HOME:63273,END:63275,PAGE_UP:63276,PAGE_DOWN:63277,INSERT:63302,PRINT_SCREEN:63248,SCROLL_LOCK:63249,NUM_LOCK:63289});
var dk=dojo.keys,_1f9={"Up":dk.UP_ARROW,"Down":dk.DOWN_ARROW,"Left":dk.LEFT_ARROW,"Right":dk.RIGHT_ARROW,"PageUp":dk.PAGE_UP,"PageDown":dk.PAGE_DOWN};
}
})();
if(dojo.isIE){
dojo._getIeDispatcher=function(){
return function(){
var ap=Array.prototype,h=dojo._ie_listener.handlers,c=arguments.callee,ls=c._listeners,t=h[c.target];
var r=t&&t.apply(this,arguments);
for(var i in ls){
if(!(i in ap)){
h[ls[i]].apply(this,arguments);
}
}
return r;
};
};
dojo._event_listener._fixCallback=function(fp){
var f=dojo._event_listener._fixEvent;
return function(e){
return fp.call(this,f(e,this));
};
};
}
}
if(!dojo._hasResource["dojo._base.html"]){
dojo._hasResource["dojo._base.html"]=true;
dojo.provide("dojo._base.html");
try{
document.execCommand("BackgroundImageCache",false,true);
}
catch(e){
}
if(dojo.isIE||dojo.isOpera){
dojo.byId=function(id,doc){
if(dojo.isString(id)){
var _d=doc||dojo.doc;
var te=_d.getElementById(id);
if(te&&te.attributes.id.value==id){
return te;
}else{
var eles=_d.all[id];
if(!eles){
return;
}
if(!eles.length){
return eles;
}
var i=0;
while((te=eles[i++])){
if(te.attributes.id.value==id){
return te;
}
}
}
}else{
return id;
}
};
}else{
dojo.byId=function(id,doc){
if(dojo.isString(id)){
return (doc||dojo.doc).getElementById(id);
}else{
return id;
}
};
}
(function(){
var _20d=null;
dojo._destroyElement=function(node){
node=dojo.byId(node);
try{
if(!_20d){
_20d=document.createElement("div");
}
_20d.appendChild(node.parentNode?node.parentNode.removeChild(node):node);
_20d.innerHTML="";
}
catch(e){
}
};
dojo.isDescendant=function(node,_210){
try{
node=dojo.byId(node);
_210=dojo.byId(_210);
while(node){
if(node===_210){
return true;
}
node=node.parentNode;
}
}
catch(e){
return -1;
}
return false;
};
dojo.setSelectable=function(node,_212){
node=dojo.byId(node);
if(dojo.isMozilla){
node.style.MozUserSelect=_212?"":"none";
}else{
if(dojo.isKhtml){
node.style.KhtmlUserSelect=_212?"auto":"none";
}else{
if(dojo.isIE){
node.unselectable=_212?"":"on";
dojo.query("*",node).forEach(function(_213){
_213.unselectable=_212?"":"on";
});
}
}
}
};
var _214=function(node,ref){
ref.parentNode.insertBefore(node,ref);
return true;
};
var _217=function(node,ref){
var pn=ref.parentNode;
if(ref==pn.lastChild){
pn.appendChild(node);
}else{
return _214(node,ref.nextSibling);
}
return true;
};
dojo.place=function(node,_21c,_21d){
if(!node||!_21c||_21d===undefined){
return false;
}
node=dojo.byId(node);
_21c=dojo.byId(_21c);
if(typeof _21d=="number"){
var cn=_21c.childNodes;
if((_21d==0&&cn.length==0)||cn.length==_21d){
_21c.appendChild(node);
return true;
}
if(_21d==0){
return _214(node,_21c.firstChild);
}
return _217(node,cn[_21d-1]);
}
switch(_21d.toLowerCase()){
case "before":
return _214(node,_21c);
case "after":
return _217(node,_21c);
case "first":
if(_21c.firstChild){
return _214(node,_21c.firstChild);
}else{
_21c.appendChild(node);
return true;
}
break;
default:
_21c.appendChild(node);
return true;
}
};
dojo.boxModel="content-box";
if(dojo.isIE){
var _dcm=document.compatMode;
dojo.boxModel=(_dcm=="BackCompat")||(_dcm=="QuirksMode")||(dojo.isIE<6)?"border-box":"content-box";
}
var gcs,dv=document.defaultView;
if(dojo.isSafari){
gcs=function(node){
var s=dv.getComputedStyle(node,null);
if(!s&&node.style){
node.style.display="";
s=dv.getComputedStyle(node,null);
}
return s||{};
};
}else{
if(dojo.isIE){
gcs=function(node){
return node.currentStyle;
};
}else{
gcs=function(node){
return dv.getComputedStyle(node,null);
};
}
}
dojo.getComputedStyle=gcs;
if(!dojo.isIE){
dojo._toPixelValue=function(_226,_227){
return parseFloat(_227)||0;
};
}else{
dojo._toPixelValue=function(_228,_229){
if(!_229){
return 0;
}
if(_229=="medium"){
return 4;
}
if(_229.slice&&(_229.slice(-2)=="px")){
return parseFloat(_229);
}
with(_228){
var _22a=style.left;
var _22b=runtimeStyle.left;
runtimeStyle.left=currentStyle.left;
try{
style.left=_229;
_229=style.pixelLeft;
}
catch(e){
_229=0;
}
style.left=_22a;
runtimeStyle.left=_22b;
}
return _229;
};
}
dojo._getOpacity=(dojo.isIE?function(node){
try{
return (node.filters.alpha.opacity/100);
}
catch(e){
return 1;
}
}:function(node){
return dojo.getComputedStyle(node).opacity;
});
dojo._setOpacity=(dojo.isIE?function(node,_22f){
if(_22f==1){
node.style.cssText=node.style.cssText.replace(/FILTER:[^;]*;/i,"");
if(node.nodeName.toLowerCase()=="tr"){
dojo.query("> td",node).forEach(function(i){
i.style.cssText=i.style.cssText.replace(/FILTER:[^;]*;/i,"");
});
}
}else{
var o="Alpha(Opacity="+(_22f*100)+")";
node.style.filter=o;
}
if(node.nodeName.toLowerCase()=="tr"){
dojo.query("> td",node).forEach(function(i){
i.style.filter=o;
});
}
return _22f;
}:function(node,_234){
return node.style.opacity=_234;
});
var _235={width:true,height:true,left:true,top:true};
var _236=function(node,type,_239){
type=type.toLowerCase();
if(_235[type]===true){
return dojo._toPixelValue(node,_239);
}else{
if(_235[type]===false){
return _239;
}else{
if(dojo.isOpera&&type=="cssText"){
}
if((type.indexOf("margin")>=0)||(type.indexOf("padding")>=0)||(type.indexOf("width")>=0)||(type.indexOf("height")>=0)||(type.indexOf("max")>=0)||(type.indexOf("min")>=0)||(type.indexOf("offset")>=0)){
_235[type]=true;
return dojo._toPixelValue(node,_239);
}else{
_235[type]=false;
return _239;
}
}
}
};
dojo.style=function(node,_23b,_23c){
var n=dojo.byId(node),args=arguments.length,op=(_23b=="opacity");
if(args==3){
return op?dojo._setOpacity(n,_23c):n.style[_23b]=_23c;
}
if(args==2&&op){
return dojo._getOpacity(n);
}
var s=dojo.getComputedStyle(n);
return (args==1)?s:_236(n,_23b,s[_23b]);
};
dojo._getPadExtents=function(n,_242){
var s=_242||gcs(n),px=dojo._toPixelValue,l=px(n,s.paddingLeft),t=px(n,s.paddingTop);
return {l:l,t:t,w:l+px(n,s.paddingRight),h:t+px(n,s.paddingBottom)};
};
dojo._getBorderExtents=function(n,_248){
var ne="none",px=dojo._toPixelValue,s=_248||gcs(n),bl=(s.borderLeftStyle!=ne?px(n,s.borderLeftWidth):0),bt=(s.borderTopStyle!=ne?px(n,s.borderTopWidth):0);
return {l:bl,t:bt,w:bl+(s.borderRightStyle!=ne?px(n,s.borderRightWidth):0),h:bt+(s.borderBottomStyle!=ne?px(n,s.borderBottomWidth):0)};
};
dojo._getPadBorderExtents=function(n,_24f){
var s=_24f||gcs(n),p=dojo._getPadExtents(n,s),b=dojo._getBorderExtents(n,s);
return {l:p.l+b.l,t:p.t+b.t,w:p.w+b.w,h:p.h+b.h};
};
dojo._getMarginExtents=function(n,_254){
var s=_254||gcs(n),px=dojo._toPixelValue,l=px(n,s.marginLeft),t=px(n,s.marginTop),r=px(n,s.marginRight),b=px(n,s.marginBottom);
if(dojo.isSafari&&(s.position!="absolute")){
r=l;
}
return {l:l,t:t,w:l+r,h:t+b};
};
dojo._getMarginBox=function(node,_25c){
var s=_25c||gcs(node),me=dojo._getMarginExtents(node,s);
var l=node.offsetLeft-me.l,t=node.offsetTop-me.t;
if(dojo.isMoz){
var sl=parseFloat(s.left),st=parseFloat(s.top);
if(!isNaN(sl)&&!isNaN(st)){
l=sl,t=st;
}else{
var p=node.parentNode;
if(p&&p.style){
var pcs=gcs(p);
if(pcs.overflow!="visible"){
var be=dojo._getBorderExtents(p,pcs);
l+=be.l,t+=be.t;
}
}
}
}else{
if(dojo.isOpera){
var p=node.parentNode;
if(p){
var be=dojo._getBorderExtents(p);
l-=be.l,t-=be.t;
}
}
}
return {l:l,t:t,w:node.offsetWidth+me.w,h:node.offsetHeight+me.h};
};
dojo._getContentBox=function(node,_267){
var s=_267||gcs(node),pe=dojo._getPadExtents(node,s),be=dojo._getBorderExtents(node,s),w=node.clientWidth,h;
if(!w){
w=node.offsetWidth,h=node.offsetHeight;
}else{
h=node.clientHeight,be.w=be.h=0;
}
if(dojo.isOpera){
pe.l+=be.l;
pe.t+=be.t;
}
return {l:pe.l,t:pe.t,w:w-pe.w-be.w,h:h-pe.h-be.h};
};
dojo._getBorderBox=function(node,_26e){
var s=_26e||gcs(node),pe=dojo._getPadExtents(node,s),cb=dojo._getContentBox(node,s);
return {l:cb.l-pe.l,t:cb.t-pe.t,w:cb.w+pe.w,h:cb.h+pe.h};
};
dojo._setBox=function(node,l,t,w,h,u){
u=u||"px";
with(node.style){
if(!isNaN(l)){
left=l+u;
}
if(!isNaN(t)){
top=t+u;
}
if(w>=0){
width=w+u;
}
if(h>=0){
height=h+u;
}
}
};
dojo._usesBorderBox=function(node){
var n=node.tagName;
return dojo.boxModel=="border-box"||n=="TABLE"||n=="BUTTON";
};
dojo._setContentSize=function(node,_27b,_27c,_27d){
var bb=dojo._usesBorderBox(node);
if(bb){
var pb=dojo._getPadBorderExtents(node,_27d);
if(_27b>=0){
_27b+=pb.w;
}
if(_27c>=0){
_27c+=pb.h;
}
}
dojo._setBox(node,NaN,NaN,_27b,_27c);
};
dojo._setMarginBox=function(node,_281,_282,_283,_284,_285){
var s=_285||dojo.getComputedStyle(node);
var bb=dojo._usesBorderBox(node),pb=bb?_289:dojo._getPadBorderExtents(node,s),mb=dojo._getMarginExtents(node,s);
if(_283>=0){
_283=Math.max(_283-pb.w-mb.w,0);
}
if(_284>=0){
_284=Math.max(_284-pb.h-mb.h,0);
}
dojo._setBox(node,_281,_282,_283,_284);
};
var _289={l:0,t:0,w:0,h:0};
dojo.marginBox=function(node,box){
var n=dojo.byId(node),s=gcs(n),b=box;
return !b?dojo._getMarginBox(n,s):dojo._setMarginBox(n,b.l,b.t,b.w,b.h,s);
};
dojo.contentBox=function(node,box){
var n=dojo.byId(node),s=gcs(n),b=box;
return !b?dojo._getContentBox(n,s):dojo._setContentSize(n,b.w,b.h,s);
};
var _295=function(node,prop){
if(!(node=(node||0).parentNode)){
return 0;
}
var val,_299=0,_b=dojo.body();
while(node&&node.style){
if(gcs(node).position=="fixed"){
return 0;
}
val=node[prop];
if(val){
_299+=val-0;
if(node==_b){
break;
}
}
node=node.parentNode;
}
return _299;
};
dojo._docScroll=function(){
var _b=dojo.body();
var _w=dojo.global;
var de=dojo.doc.documentElement;
return {y:(_w.pageYOffset||de.scrollTop||_b.scrollTop||0),x:(_w.pageXOffset||dojo._fixIeBiDiScrollLeft(de.scrollLeft)||_b.scrollLeft||0)};
};
dojo._isBodyLtr=function(){
return !("_bodyLtr" in dojo)?dojo._bodyLtr=dojo.getComputedStyle(dojo.body()).direction=="ltr":dojo._bodyLtr;
};
dojo._getIeDocumentElementOffset=function(){
var de=dojo.doc.documentElement;
if(dojo.isIE>=7){
return {x:de.getBoundingClientRect().left,y:de.getBoundingClientRect().top};
}else{
return {x:dojo._isBodyLtr()||window.parent==window?de.clientLeft:de.offsetWidth-de.clientWidth-de.clientLeft,y:de.clientTop};
}
};
dojo._fixIeBiDiScrollLeft=function(_29f){
if(dojo.isIE&&!dojo._isBodyLtr()){
var de=dojo.doc.documentElement;
return _29f+de.clientWidth-de.scrollWidth;
}
return _29f;
};
dojo._abs=function(node,_2a2){
var _2a3=node.ownerDocument;
var ret={x:0,y:0};
var _2a5=false;
var db=dojo.body();
if(dojo.isIE){
var _2a7=node.getBoundingClientRect();
var _2a8=dojo._getIeDocumentElementOffset();
ret.x=_2a7.left-_2a8.x;
ret.y=_2a7.top-_2a8.y;
}else{
if(_2a3["getBoxObjectFor"]){
var bo=_2a3.getBoxObjectFor(node);
ret.x=bo.x-_295(node,"scrollLeft");
ret.y=bo.y-_295(node,"scrollTop");
}else{
if(node["offsetParent"]){
_2a5=true;
var _2aa;
if(dojo.isSafari&&(gcs(node).position=="absolute")&&(node.parentNode==db)){
_2aa=db;
}else{
_2aa=db.parentNode;
}
if(node.parentNode!=db){
var nd=node;
if(dojo.isOpera||(dojo.isSafari>=3)){
nd=db;
}
ret.x-=_295(nd,"scrollLeft");
ret.y-=_295(nd,"scrollTop");
}
var _2ac=node;
do{
var n=_2ac["offsetLeft"];
if(!dojo.isOpera||n>0){
ret.x+=isNaN(n)?0:n;
}
var m=_2ac["offsetTop"];
ret.y+=isNaN(m)?0:m;
_2ac=_2ac.offsetParent;
}while((_2ac!=_2aa)&&_2ac);
}else{
if(node["x"]&&node["y"]){
ret.x+=isNaN(node.x)?0:node.x;
ret.y+=isNaN(node.y)?0:node.y;
}
}
}
}
if(_2a5||_2a2){
var _2af=dojo._docScroll();
var m=_2a5?(!_2a2?-1:0):1;
ret.y+=m*_2af.y;
ret.x+=m*_2af.x;
}
return ret;
};
dojo.coords=function(node,_2b1){
var n=dojo.byId(node),s=gcs(n),mb=dojo._getMarginBox(n,s);
var abs=dojo._abs(n,_2b1);
mb.x=abs.x;
mb.y=abs.y;
return mb;
};
})();
dojo.hasClass=function(node,_2b7){
return ((" "+dojo.byId(node).className+" ").indexOf(" "+_2b7+" ")>=0);
};
dojo.addClass=function(node,_2b9){
node=dojo.byId(node);
var cls=node.className;
if((" "+cls+" ").indexOf(" "+_2b9+" ")<0){
node.className=cls+(cls?" ":"")+_2b9;
}
};
dojo.removeClass=function(node,_2bc){
node=dojo.byId(node);
var t=dojo.trim((" "+node.className+" ").replace(" "+_2bc+" "," "));
if(node.className!=t){
node.className=t;
}
};
dojo.toggleClass=function(node,_2bf,_2c0){
if(_2c0===undefined){
_2c0=!dojo.hasClass(node,_2bf);
}
dojo[_2c0?"addClass":"removeClass"](node,_2bf);
};
}
if(!dojo._hasResource["dojo._base.NodeList"]){
dojo._hasResource["dojo._base.NodeList"]=true;
dojo.provide("dojo._base.NodeList");
(function(){
var d=dojo;
var tnl=function(arr){
arr.constructor=dojo.NodeList;
dojo._mixin(arr,dojo.NodeList.prototype);
return arr;
};
dojo.NodeList=function(){
return tnl(Array.apply(null,arguments));
};
dojo.NodeList._wrap=tnl;
dojo.extend(dojo.NodeList,{slice:function(){
var a=dojo._toArray(arguments);
return tnl(a.slice.apply(this,a));
},splice:function(){
var a=dojo._toArray(arguments);
return tnl(a.splice.apply(this,a));
},concat:function(){
var a=dojo._toArray(arguments,0,[this]);
return tnl(a.concat.apply([],a));
},indexOf:function(_2c7,_2c8){
return d.indexOf(this,_2c7,_2c8);
},lastIndexOf:function(){
return d.lastIndexOf.apply(d,d._toArray(arguments,0,[this]));
},every:function(_2c9,_2ca){
return d.every(this,_2c9,_2ca);
},some:function(_2cb,_2cc){
return d.some(this,_2cb,_2cc);
},map:function(func,obj){
return d.map(this,func,obj,d.NodeList);
},forEach:function(_2cf,_2d0){
d.forEach(this,_2cf,_2d0);
return this;
},coords:function(){
return d.map(this,d.coords);
},style:function(){
var aa=d._toArray(arguments,0,[null]);
var s=this.map(function(i){
aa[0]=i;
return d.style.apply(d,aa);
});
return (arguments.length>1)?this:s;
},styles:function(){
d.deprecated("NodeList.styles","use NodeList.style instead","1.1");
return this.style.apply(this,arguments);
},addClass:function(_2d4){
this.forEach(function(i){
d.addClass(i,_2d4);
});
return this;
},removeClass:function(_2d6){
this.forEach(function(i){
d.removeClass(i,_2d6);
});
return this;
},place:function(_2d8,_2d9){
var item=d.query(_2d8)[0];
_2d9=_2d9||"last";
for(var x=0;x<this.length;x++){
d.place(this[x],item,_2d9);
}
return this;
},connect:function(_2dc,_2dd,_2de){
this.forEach(function(item){
d.connect(item,_2dc,_2dd,_2de);
});
return this;
},orphan:function(_2e0){
var _2e1=(_2e0)?d._filterQueryResult(this,_2e0):this;
_2e1.forEach(function(item){
if(item["parentNode"]){
item.parentNode.removeChild(item);
}
});
return _2e1;
},adopt:function(_2e3,_2e4){
var item=this[0];
return d.query(_2e3).forEach(function(ai){
d.place(ai,item,(_2e4||"last"));
});
},query:function(_2e7){
_2e7=_2e7||"";
var ret=d.NodeList();
this.forEach(function(item){
d.query(_2e7,item).forEach(function(_2ea){
if(typeof _2ea!="undefined"){
ret.push(_2ea);
}
});
});
return ret;
},filter:function(_2eb){
var _2ec=this;
var _a=arguments;
var r=d.NodeList();
var rp=function(t){
if(typeof t!="undefined"){
r.push(t);
}
};
if(d.isString(_2eb)){
_2ec=d._filterQueryResult(this,_a[0]);
if(_a.length==1){
return _2ec;
}
d.forEach(d.filter(_2ec,_a[1],_a[2]),rp);
return r;
}
d.forEach(d.filter(_2ec,_a[0],_a[1]),rp);
return r;
},addContent:function(_2f1,_2f2){
var ta=d.doc.createElement("span");
if(d.isString(_2f1)){
ta.innerHTML=_2f1;
}else{
ta.appendChild(_2f1);
}
var ct=((_2f2=="first")||(_2f2=="after"))?"lastChild":"firstChild";
this.forEach(function(item){
var tn=ta.cloneNode(true);
while(tn[ct]){
d.place(tn[ct],item,_2f2);
}
});
return this;
}});
d.forEach(["blur","click","keydown","keypress","keyup","mousedown","mouseenter","mouseleave","mousemove","mouseout","mouseover","mouseup"],function(evt){
var _oe="on"+evt;
dojo.NodeList.prototype[_oe]=function(a,b){
return this.connect(_oe,a,b);
};
});
})();
}
if(!dojo._hasResource["dojo._base.query"]){
dojo._hasResource["dojo._base.query"]=true;
dojo.provide("dojo._base.query");
(function(){
var d=dojo;
var _2fc=dojo.isIE?"children":"childNodes";
var _2fd=function(_2fe){
if(_2fe.charAt(_2fe.length-1)==">"){
_2fe+=" *";
}
_2fe+=" ";
var ts=function(s,e){
return d.trim(_2fe.slice(s,e));
};
var _302=[];
var _303=-1;
var _304=-1;
var _305=-1;
var _306=-1;
var _307=-1;
var inId=-1;
var _309=-1;
var lc="";
var cc="";
var _30c;
var x=0;
var ql=_2fe.length;
var _30f=null;
var _cp=null;
var _311=function(){
if(_309>=0){
var tv=(_309==x)?null:ts(_309,x).toLowerCase();
_30f[(">~+".indexOf(tv)<0)?"tag":"oper"]=tv;
_309=-1;
}
};
var _313=function(){
if(inId>=0){
_30f.id=ts(inId,x).replace(/\\/g,"");
inId=-1;
}
};
var _314=function(){
if(_307>=0){
_30f.classes.push(ts(_307+1,x).replace(/\\/g,""));
_307=-1;
}
};
var _315=function(){
_313();
_311();
_314();
};
for(;x<ql,lc=cc,cc=_2fe.charAt(x);x++){
if(lc=="\\"){
continue;
}
if(!_30f){
_30c=x;
_30f={query:null,pseudos:[],attrs:[],classes:[],tag:null,oper:null,id:null};
_309=x;
}
if(_303>=0){
if(cc=="]"){
if(!_cp.attr){
_cp.attr=ts(_303+1,x);
}else{
_cp.matchFor=ts((_305||_303+1),x);
}
var cmf=_cp.matchFor;
if(cmf){
if((cmf.charAt(0)=="\"")||(cmf.charAt(0)=="'")){
_cp.matchFor=cmf.substring(1,cmf.length-1);
}
}
_30f.attrs.push(_cp);
_cp=null;
_303=_305=-1;
}else{
if(cc=="="){
var _317=("|~^$*".indexOf(lc)>=0)?lc:"";
_cp.type=_317+cc;
_cp.attr=ts(_303+1,x-_317.length);
_305=x+1;
}
}
}else{
if(_304>=0){
if(cc==")"){
if(_306>=0){
_cp.value=ts(_304+1,x);
}
_306=_304=-1;
}
}else{
if(cc=="#"){
_315();
inId=x+1;
}else{
if(cc=="."){
_315();
_307=x;
}else{
if(cc==":"){
_315();
_306=x;
}else{
if(cc=="["){
_315();
_303=x;
_cp={};
}else{
if(cc=="("){
if(_306>=0){
_cp={name:ts(_306+1,x),value:null};
_30f.pseudos.push(_cp);
}
_304=x;
}else{
if(cc==" "&&lc!=cc){
_315();
if(_306>=0){
_30f.pseudos.push({name:ts(_306+1,x)});
}
_30f.hasLoops=(_30f.pseudos.length||_30f.attrs.length||_30f.classes.length);
_30f.query=ts(_30c,x);
_30f.tag=(_30f["oper"])?null:(_30f.tag||"*");
_302.push(_30f);
_30f=null;
}
}
}
}
}
}
}
}
}
return _302;
};
var _318={"*=":function(attr,_31a){
return "[contains(@"+attr+", '"+_31a+"')]";
},"^=":function(attr,_31c){
return "[starts-with(@"+attr+", '"+_31c+"')]";
},"$=":function(attr,_31e){
return "[substring(@"+attr+", string-length(@"+attr+")-"+(_31e.length-1)+")='"+_31e+"']";
},"~=":function(attr,_320){
return "[contains(concat(' ',@"+attr+",' '), ' "+_320+" ')]";
},"|=":function(attr,_322){
return "[contains(concat(' ',@"+attr+",' '), ' "+_322+"-')]";
},"=":function(attr,_324){
return "[@"+attr+"='"+_324+"']";
}};
var _325=function(_326,_327,_328,_329){
d.forEach(_327.attrs,function(attr){
var _32b;
if(attr.type&&_326[attr.type]){
_32b=_326[attr.type](attr.attr,attr.matchFor);
}else{
if(attr.attr.length){
_32b=_328(attr.attr);
}
}
if(_32b){
_329(_32b);
}
});
};
var _32c=function(_32d){
var _32e=".";
var _32f=_2fd(d.trim(_32d));
while(_32f.length){
var tqp=_32f.shift();
var _331;
if(tqp.oper==">"){
_331="/";
tqp=_32f.shift();
}else{
_331="//";
}
_32e+=_331+tqp.tag;
if(tqp.id){
_32e+="[@id='"+tqp.id+"'][1]";
}
d.forEach(tqp.classes,function(cn){
var cnl=cn.length;
var _334=" ";
if(cn.charAt(cnl-1)=="*"){
_334="";
cn=cn.substr(0,cnl-1);
}
_32e+="[contains(concat(' ',@class,' '), ' "+cn+_334+"')]";
});
_325(_318,tqp,function(_335){
return "[@"+_335+"]";
},function(_336){
_32e+=_336;
});
}
return _32e;
};
var _337={};
var _338=function(path){
if(_337[path]){
return _337[path];
}
var doc=d.doc;
var _33b=_32c(path);
var tf=function(_33d){
var ret=[];
var _33f;
try{
_33f=doc.evaluate(_33b,_33d,null,XPathResult.ANY_TYPE,null);
}
catch(e){
console.debug("failure in exprssion:",_33b,"under:",_33d);
console.debug(e);
}
var _340=_33f.iterateNext();
while(_340){
ret.push(_340);
_340=_33f.iterateNext();
}
return ret;
};
return _337[path]=tf;
};
var _341={};
var _342={};
var _343=function(_344,_345){
if(!_344){
return _345;
}
if(!_345){
return _344;
}
return function(){
return _344.apply(window,arguments)&&_345.apply(window,arguments);
};
};
var _346=function(_347,_348,_349,idx){
var nidx=idx+1;
var _34c=(_348.length==nidx);
var tqp=_348[idx];
if(tqp.oper==">"){
var ecn=_347[_2fc];
if(!ecn||!ecn.length){
return;
}
nidx++;
_34c=(_348.length==nidx);
var tf=_350(_348[idx+1]);
for(var x=0,ecnl=ecn.length,te;x<ecnl,te=ecn[x];x++){
if(tf(te)){
if(_34c){
_349.push(te);
}else{
_346(te,_348,_349,nidx);
}
}
}
}
var _354=_355(tqp)(_347);
if(_34c){
while(_354.length){
_349.push(_354.shift());
}
}else{
while(_354.length){
_346(_354.shift(),_348,_349,nidx);
}
}
};
var _356=function(_357,_358){
var ret=[];
var x=_357.length-1,te;
while(te=_357[x--]){
_346(te,_358,ret,0);
}
return ret;
};
var _350=function(q){
if(_341[q.query]){
return _341[q.query];
}
var ff=null;
if(q.tag){
if(q.tag=="*"){
ff=_343(ff,function(elem){
return (elem.nodeType==1);
});
}else{
ff=_343(ff,function(elem){
return ((elem.nodeType==1)&&(q.tag==elem.tagName.toLowerCase()));
});
}
}
if(q.id){
ff=_343(ff,function(elem){
return ((elem.nodeType==1)&&(elem.id==q.id));
});
}
if(q.hasLoops){
ff=_343(ff,_361(q));
}
return _341[q.query]=ff;
};
var _362=function(node){
var pn=node.parentNode;
var pnc=pn.childNodes;
var nidx=-1;
var _367=pn.firstChild;
if(!_367){
return nidx;
}
var ci=node["__cachedIndex"];
var cl=pn["__cachedLength"];
if(((typeof cl=="number")&&(cl!=pnc.length))||(typeof ci!="number")){
pn["__cachedLength"]=pnc.length;
var idx=1;
do{
if(_367===node){
nidx=idx;
}
if(_367.nodeType==1){
_367["__cachedIndex"]=idx;
idx++;
}
_367=_367.nextSibling;
}while(_367);
}else{
nidx=ci;
}
return nidx;
};
var _36b=0;
var _36c="";
var _36d=function(elem,attr){
if(attr=="class"){
return elem.className||_36c;
}
if(attr=="for"){
return elem.htmlFor||_36c;
}
return elem.getAttribute(attr,2)||_36c;
};
var _370={"*=":function(attr,_372){
return function(elem){
return (_36d(elem,attr).indexOf(_372)>=0);
};
},"^=":function(attr,_375){
return function(elem){
return (_36d(elem,attr).indexOf(_375)==0);
};
},"$=":function(attr,_378){
var tval=" "+_378;
return function(elem){
var ea=" "+_36d(elem,attr);
return (ea.lastIndexOf(_378)==(ea.length-_378.length));
};
},"~=":function(attr,_37d){
var tval=" "+_37d+" ";
return function(elem){
var ea=" "+_36d(elem,attr)+" ";
return (ea.indexOf(tval)>=0);
};
},"|=":function(attr,_382){
var _383=" "+_382+"-";
return function(elem){
var ea=" "+(elem.getAttribute(attr,2)||"");
return ((ea==_382)||(ea.indexOf(_383)==0));
};
},"=":function(attr,_387){
return function(elem){
return (_36d(elem,attr)==_387);
};
}};
var _389={"first-child":function(name,_38b){
return function(elem){
if(elem.nodeType!=1){
return false;
}
var fc=elem.previousSibling;
while(fc&&(fc.nodeType!=1)){
fc=fc.previousSibling;
}
return (!fc);
};
},"last-child":function(name,_38f){
return function(elem){
if(elem.nodeType!=1){
return false;
}
var nc=elem.nextSibling;
while(nc&&(nc.nodeType!=1)){
nc=nc.nextSibling;
}
return (!nc);
};
},"empty":function(name,_393){
return function(elem){
var cn=elem.childNodes;
var cnl=elem.childNodes.length;
for(var x=cnl-1;x>=0;x--){
var nt=cn[x].nodeType;
if((nt==1)||(nt==3)){
return false;
}
}
return true;
};
},"not":function(name,_39a){
var ntf=_350(_2fd(_39a)[0]);
return function(elem){
return (!ntf(elem));
};
},"nth-child":function(name,_39e){
var pi=parseInt;
if(_39e=="odd"){
return function(elem){
return (((_362(elem))%2)==1);
};
}else{
if((_39e=="2n")||(_39e=="even")){
return function(elem){
return ((_362(elem)%2)==0);
};
}else{
if(_39e.indexOf("0n+")==0){
var _3a2=pi(_39e.substr(3));
return function(elem){
return (elem.parentNode[_2fc][_3a2-1]===elem);
};
}else{
if((_39e.indexOf("n+")>0)&&(_39e.length>3)){
var _3a4=_39e.split("n+",2);
var pred=pi(_3a4[0]);
var idx=pi(_3a4[1]);
return function(elem){
return ((_362(elem)%pred)==idx);
};
}else{
if(_39e.indexOf("n")==-1){
var _3a2=pi(_39e);
return function(elem){
return (_362(elem)==_3a2);
};
}
}
}
}
}
}};
var _3a9=(d.isIE)?function(cond){
var clc=cond.toLowerCase();
return function(elem){
return elem[cond]||elem[clc];
};
}:function(cond){
return function(elem){
return (elem&&elem.getAttribute&&elem.hasAttribute(cond));
};
};
var _361=function(_3af){
var _3b0=(_342[_3af.query]||_341[_3af.query]);
if(_3b0){
return _3b0;
}
var ff=null;
if(_3af.id){
if(_3af.tag!="*"){
ff=_343(ff,function(elem){
return (elem.tagName.toLowerCase()==_3af.tag);
});
}
}
d.forEach(_3af.classes,function(_3b3,idx,arr){
var _3b6=_3b3.charAt(_3b3.length-1)=="*";
if(_3b6){
_3b3=_3b3.substr(0,_3b3.length-1);
}
var re=new RegExp("(?:^|\\s)"+_3b3+(_3b6?".*":"")+"(?:\\s|$)");
ff=_343(ff,function(elem){
return re.test(elem.className);
});
ff.count=idx;
});
d.forEach(_3af.pseudos,function(_3b9){
if(_389[_3b9.name]){
ff=_343(ff,_389[_3b9.name](_3b9.name,_3b9.value));
}
});
_325(_370,_3af,_3a9,function(_3ba){
ff=_343(ff,_3ba);
});
if(!ff){
ff=function(){
return true;
};
}
return _342[_3af.query]=ff;
};
var _3bb={};
var _355=function(_3bc,root){
var fHit=_3bb[_3bc.query];
if(fHit){
return fHit;
}
if(_3bc.id&&!_3bc.hasLoops&&!_3bc.tag){
return _3bb[_3bc.query]=function(root){
return [d.byId(_3bc.id)];
};
}
var _3c0=_361(_3bc);
var _3c1;
if(_3bc.tag&&_3bc.id&&!_3bc.hasLoops){
_3c1=function(root){
var te=d.byId(_3bc.id);
if(_3c0(te)){
return [te];
}
};
}else{
var tret;
if(!_3bc.hasLoops){
_3c1=function(root){
var ret=[];
var te,x=0,tret=root.getElementsByTagName(_3bc.tag);
while(te=tret[x++]){
ret.push(te);
}
return ret;
};
}else{
_3c1=function(root){
var ret=[];
var te,x=0,tret=root.getElementsByTagName(_3bc.tag);
while(te=tret[x++]){
if(_3c0(te)){
ret.push(te);
}
}
return ret;
};
}
}
return _3bb[_3bc.query]=_3c1;
};
var _3cd={};
var _3ce={"*":d.isIE?function(root){
return root.all;
}:function(root){
return root.getElementsByTagName("*");
},">":function(root){
var ret=[];
var te,x=0,tret=root[_2fc];
while(te=tret[x++]){
if(te.nodeType==1){
ret.push(te);
}
}
return ret;
}};
var _3d6=function(_3d7){
var _3d8=_2fd(d.trim(_3d7));
if(_3d8.length==1){
var tt=_355(_3d8[0]);
tt.nozip=true;
return tt;
}
var sqf=function(root){
var _3dc=_3d8.slice(0);
var _3dd;
if(_3dc[0].oper==">"){
_3dd=[root];
}else{
_3dd=_355(_3dc.shift())(root);
}
return _356(_3dd,_3dc);
};
return sqf;
};
var _3de=((document["evaluate"]&&!d.isSafari)?function(_3df){
var _3e0=_3df.split(" ");
if((document["evaluate"])&&(_3df.indexOf(":")==-1)&&((true))){
if(((_3e0.length>2)&&(_3df.indexOf(">")==-1))||(_3e0.length>3)||(_3df.indexOf("[")>=0)||((1==_3e0.length)&&(0<=_3df.indexOf(".")))){
return _338(_3df);
}
}
return _3d6(_3df);
}:_3d6);
var _3e1=function(_3e2){
if(_3ce[_3e2]){
return _3ce[_3e2];
}
if(0>_3e2.indexOf(",")){
return _3ce[_3e2]=_3de(_3e2);
}else{
var _3e3=_3e2.split(/\s*,\s*/);
var tf=function(root){
var _3e6=0;
var ret=[];
var tp;
while(tp=_3e3[_3e6++]){
ret=ret.concat(_3de(tp,tp.indexOf(" "))(root));
}
return ret;
};
return _3ce[_3e2]=tf;
}
};
var _3e9=0;
var _zip=function(arr){
if(arr&&arr.nozip){
return d.NodeList._wrap(arr);
}
var ret=new d.NodeList();
if(!arr){
return ret;
}
if(arr[0]){
ret.push(arr[0]);
}
if(arr.length<2){
return ret;
}
_3e9++;
arr[0]["_zipIdx"]=_3e9;
for(var x=1,te;te=arr[x];x++){
if(arr[x]["_zipIdx"]!=_3e9){
ret.push(te);
}
te["_zipIdx"]=_3e9;
}
return ret;
};
d.query=function(_3ef,root){
if(_3ef.constructor==d.NodeList){
return _3ef;
}
if(!d.isString(_3ef)){
return new d.NodeList(_3ef);
}
if(d.isString(root)){
root=d.byId(root);
}
return _zip(_3e1(_3ef)(root||d.doc));
};
d._filterQueryResult=function(_3f1,_3f2){
var tnl=new d.NodeList();
var ff=(_3f2)?_350(_2fd(_3f2)[0]):function(){
return true;
};
for(var x=0,te;te=_3f1[x];x++){
if(ff(te)){
tnl.push(te);
}
}
return tnl;
};
})();
}
if(!dojo._hasResource["dojo._base.xhr"]){
dojo._hasResource["dojo._base.xhr"]=true;
dojo.provide("dojo._base.xhr");
(function(){
var _d=dojo;
function setValue(obj,name,_3fa){
var val=obj[name];
if(_d.isString(val)){
obj[name]=[val,_3fa];
}else{
if(_d.isArray(val)){
val.push(_3fa);
}else{
obj[name]=_3fa;
}
}
}
dojo.formToObject=function(_3fc){
var ret={};
var iq="input:not([type=file]):not([type=submit]):not([type=image]):not([type=reset]):not([type=button]), select, textarea";
_d.query(iq,_3fc).filter(function(node){
return (!node.disabled);
}).forEach(function(item){
var _in=item.name;
var type=(item.type||"").toLowerCase();
if(type=="radio"||type=="checkbox"){
if(item.checked){
setValue(ret,_in,item.value);
}
}else{
if(item.multiple){
ret[_in]=[];
_d.query("option",item).forEach(function(opt){
if(opt.selected){
setValue(ret,_in,opt.value);
}
});
}else{
setValue(ret,_in,item.value);
if(type=="image"){
ret[_in+".x"]=ret[_in+".y"]=ret[_in].x=ret[_in].y=0;
}
}
}
});
return ret;
};
dojo.objectToQuery=function(map){
var ec=encodeURIComponent;
var ret="";
var _407={};
for(var x in map){
if(map[x]!=_407[x]){
if(_d.isArray(map[x])){
for(var y=0;y<map[x].length;y++){
ret+=ec(x)+"="+ec(map[x][y])+"&";
}
}else{
ret+=ec(x)+"="+ec(map[x])+"&";
}
}
}
if(ret.length&&ret.charAt(ret.length-1)=="&"){
ret=ret.substr(0,ret.length-1);
}
return ret;
};
dojo.formToQuery=function(_40a){
return _d.objectToQuery(_d.formToObject(_40a));
};
dojo.formToJson=function(_40b,_40c){
return _d.toJson(_d.formToObject(_40b),_40c);
};
dojo.queryToObject=function(str){
var ret={};
var qp=str.split("&");
var dc=decodeURIComponent;
_d.forEach(qp,function(item){
if(item.length){
var _412=item.split("=");
var name=dc(_412.shift());
var val=dc(_412.join("="));
if(_d.isString(ret[name])){
ret[name]=[ret[name]];
}
if(_d.isArray(ret[name])){
ret[name].push(val);
}else{
ret[name]=val;
}
}
});
return ret;
};
dojo._blockAsync=false;
dojo._contentHandlers={"text":function(xhr){
return xhr.responseText;
},"json":function(xhr){
if(!djConfig.usePlainJson){
console.debug("Consider using mimetype:text/json-comment-filtered"+" to avoid potential security issues with JSON endpoints"+" (use djConfig.usePlainJson=true to turn off this message)");
}
return _d.fromJson(xhr.responseText);
},"json-comment-filtered":function(xhr){
var _418=xhr.responseText;
var _419=_418.indexOf("/*");
var _41a=_418.lastIndexOf("*/");
if(_419==-1||_41a==-1){
throw new Error("JSON was not comment filtered");
}
return _d.fromJson(_418.substring(_419+2,_41a));
},"javascript":function(xhr){
return _d.eval(xhr.responseText);
},"xml":function(xhr){
if(_d.isIE&&!xhr.responseXML){
_d.forEach(["MSXML2","Microsoft","MSXML","MSXML3"],function(i){
try{
var doc=new ActiveXObject(prefixes[i]+".XMLDOM");
doc.async=false;
doc.loadXML(xhr.responseText);
return doc;
}
catch(e){
}
});
}else{
return xhr.responseXML;
}
}};
dojo._contentHandlers["json-comment-optional"]=function(xhr){
var _420=_d._contentHandlers;
try{
return _420["json-comment-filtered"](xhr);
}
catch(e){
return _420["json"](xhr);
}
};
dojo._ioSetArgs=function(args,_422,_423,_424){
var _425={args:args,url:args.url};
var _426=null;
if(args.form){
var form=_d.byId(args.form);
var _428=form.getAttributeNode("action");
_425.url=_425.url||(_428?_428.value:null);
_426=_d.formToObject(form);
}
var _429=[{}];
if(_426){
_429.push(_426);
}
if(args.content){
_429.push(args.content);
}
if(args.preventCache){
_429.push({"dojo.preventCache":new Date().valueOf()});
}
_425.query=_d.objectToQuery(_d.mixin.apply(null,_429));
_425.handleAs=args.handleAs||"text";
var d=new _d.Deferred(_422);
d.addCallbacks(_423,function(_42b){
return _424(_42b,d);
});
var ld=args.load;
if(ld&&_d.isFunction(ld)){
d.addCallback(function(_42d){
return ld.call(args,_42d,_425);
});
}
var err=args.error;
if(err&&_d.isFunction(err)){
d.addErrback(function(_42f){
return err.call(args,_42f,_425);
});
}
var _430=args.handle;
if(_430&&_d.isFunction(_430)){
d.addBoth(function(_431){
return _430.call(args,_431,_425);
});
}
d.ioArgs=_425;
return d;
};
var _432=function(dfd){
dfd.canceled=true;
var xhr=dfd.ioArgs.xhr;
var _at=(typeof xhr.abort);
if((_at=="function")||(_at=="unknown")){
xhr.abort();
}
var err=new Error("xhr cancelled");
err.dojoType="cancel";
return err;
};
var _437=function(dfd){
return _d._contentHandlers[dfd.ioArgs.handleAs](dfd.ioArgs.xhr);
};
var _439=function(_43a,dfd){
console.debug(_43a);
return _43a;
};
var _43c=function(args){
var dfd=_d._ioSetArgs(args,_432,_437,_439);
dfd.ioArgs.xhr=_d._xhrObj(dfd.ioArgs.args);
return dfd;
};
var _43f=null;
var _440=[];
var _441=function(){
var now=(new Date()).getTime();
if(!_d._blockAsync){
for(var i=0,tif;(i<_440.length)&&(tif=_440[i]);i++){
var dfd=tif.dfd;
try{
if(!dfd||dfd.canceled||!tif.validCheck(dfd)){
_440.splice(i--,1);
}else{
if(tif.ioCheck(dfd)){
_440.splice(i--,1);
tif.resHandle(dfd);
}else{
if(dfd.startTime){
if(dfd.startTime+(dfd.ioArgs.args.timeout||0)<now){
_440.splice(i--,1);
var err=new Error("timeout exceeded");
err.dojoType="timeout";
dfd.errback(err);
dfd.cancel();
}
}
}
}
}
catch(e){
console.debug(e);
dfd.errback(new Error("_watchInFlightError!"));
}
}
}
if(!_440.length){
clearInterval(_43f);
_43f=null;
return;
}
};
dojo._ioCancelAll=function(){
try{
_d.forEach(_440,function(i){
i.dfd.cancel();
});
}
catch(e){
}
};
if(_d.isIE){
_d.addOnUnload(_d._ioCancelAll);
}
_d._ioWatch=function(dfd,_449,_44a,_44b){
if(dfd.ioArgs.args.timeout){
dfd.startTime=(new Date()).getTime();
}
_440.push({dfd:dfd,validCheck:_449,ioCheck:_44a,resHandle:_44b});
if(!_43f){
_43f=setInterval(_441,50);
}
_441();
};
var _44c="application/x-www-form-urlencoded";
var _44d=function(dfd){
return dfd.ioArgs.xhr.readyState;
};
var _44f=function(dfd){
return 4==dfd.ioArgs.xhr.readyState;
};
var _451=function(dfd){
if(_d._isDocumentOk(dfd.ioArgs.xhr)){
dfd.callback(dfd);
}else{
dfd.errback(new Error("bad http response code:"+dfd.ioArgs.xhr.status));
}
};
var _453=function(type,dfd){
var _456=dfd.ioArgs;
var args=_456.args;
_456.xhr.open(type,_456.url,args.sync!==true,args.user||undefined,args.password||undefined);
if(args.headers){
for(var hdr in args.headers){
if(hdr.toLowerCase()==="content-type"&&!args.contentType){
args.contentType=args.headers[hdr];
}else{
_456.xhr.setRequestHeader(hdr,args.headers[hdr]);
}
}
}
_456.xhr.setRequestHeader("Content-Type",(args.contentType||_44c));
try{
_456.xhr.send(_456.query);
}
catch(e){
dfd.cancel();
}
_d._ioWatch(dfd,_44d,_44f,_451);
return dfd;
};
dojo._ioAddQueryToUrl=function(_459){
if(_459.query.length){
_459.url+=(_459.url.indexOf("?")==-1?"?":"&")+_459.query;
_459.query=null;
}
};
dojo.xhrGet=function(args){
var dfd=_43c(args);
_d._ioAddQueryToUrl(dfd.ioArgs);
return _453("GET",dfd);
};
dojo.xhrPost=function(args){
return _453("POST",_43c(args));
};
dojo.rawXhrPost=function(args){
var dfd=_43c(args);
dfd.ioArgs.query=args.postData;
return _453("POST",dfd);
};
dojo.xhrPut=function(args){
return _453("PUT",_43c(args));
};
dojo.rawXhrPut=function(args){
var dfd=_43c(args);
var _462=dfd.ioArgs;
if(args["putData"]){
_462.query=args.putData;
args.putData=null;
}
return _453("PUT",dfd);
};
dojo.xhrDelete=function(args){
var dfd=_43c(args);
_d._ioAddQueryToUrl(dfd.ioArgs);
return _453("DELETE",dfd);
};
})();
}
if(!dojo._hasResource["dojo._base.fx"]){
dojo._hasResource["dojo._base.fx"]=true;
dojo.provide("dojo._base.fx");
dojo._Line=function(_465,end){
this.start=_465;
this.end=end;
this.getValue=function(n){
return ((this.end-this.start)*n)+this.start;
};
};
dojo.declare("dojo._Animation",null,{constructor:function(args){
dojo.mixin(this,args);
if(dojo.isArray(this.curve)){
this.curve=new dojo._Line(this.curve[0],this.curve[1]);
}
},duration:1000,repeat:0,rate:10,_percent:0,_startRepeatCount:0,fire:function(evt,args){
if(this[evt]){
this[evt].apply(this,args||[]);
}
return this;
},play:function(_46b,_46c){
var _t=this;
if(_46c){
_t._stopTimer();
_t._active=_t._paused=false;
_t._percent=0;
}else{
if(_t._active&&!_t._paused){
return _t;
}
}
_t.fire("beforeBegin");
var d=_46b||_t.delay;
var _p=dojo.hitch(_t,"_play",_46c);
if(d>0){
setTimeout(_p,d);
return _t;
}
_p();
return _t;
},_play:function(_470){
var _t=this;
_t._startTime=new Date().valueOf();
if(_t._paused){
_t._startTime-=_t.duration*_t._percent;
}
_t._endTime=_t._startTime+_t.duration;
_t._active=true;
_t._paused=false;
var _472=_t.curve.getValue(_t._percent);
if(!_t._percent){
if(!_t._startRepeatCount){
_t._startRepeatCount=_t.repeat;
}
_t.fire("onBegin",[_472]);
}
_t.fire("onPlay",[_472]);
_t._cycle();
return _t;
},pause:function(){
this._stopTimer();
if(!this._active){
return this;
}
this._paused=true;
this.fire("onPause",[this.curve.getValue(this._percent)]);
return this;
},gotoPercent:function(_473,_474){
this._stopTimer();
this._active=this._paused=true;
this._percent=_473;
if(_474){
this.play();
}
return this;
},stop:function(_475){
if(!this._timer){
return;
}
this._stopTimer();
if(_475){
this._percent=1;
}
this.fire("onStop",[this.curve.getValue(this._percent)]);
this._active=this._paused=false;
return this;
},status:function(){
if(this._active){
return this._paused?"paused":"playing";
}
return "stopped";
},_cycle:function(){
var _t=this;
if(_t._active){
var curr=new Date().valueOf();
var step=(curr-_t._startTime)/(_t._endTime-_t._startTime);
if(step>=1){
step=1;
}
_t._percent=step;
if(_t.easing){
step=_t.easing(step);
}
_t.fire("onAnimate",[_t.curve.getValue(step)]);
if(step<1){
_t._startTimer();
}else{
_t._active=false;
if(_t.repeat>0){
_t.repeat--;
_t.play(null,true);
}else{
if(_t.repeat==-1){
_t.play(null,true);
}else{
if(_t._startRepeatCount){
_t.repeat=_t._startRepeatCount;
_t._startRepeatCount=0;
}
}
}
_t._percent=0;
_t.fire("onEnd");
}
}
return _t;
}});
(function(){
var d=dojo;
var ctr=0;
var _47b=[];
var _47c={run:function(){
}};
var _47d=null;
dojo._Animation.prototype._startTimer=function(){
if(!this._timer){
this._timer=dojo.connect(_47c,"run",this,"_cycle");
ctr++;
}
if(!_47d){
_47d=setInterval(dojo.hitch(_47c,"run"),this.rate);
}
};
dojo._Animation.prototype._stopTimer=function(){
dojo.disconnect(this._timer);
this._timer=null;
ctr--;
if(!ctr){
clearInterval(_47d);
_47d=null;
}
};
var _47e=(d.isIE)?function(node){
var ns=node.style;
if(!ns.zoom.length&&d.style(node,"zoom")=="normal"){
ns.zoom="1";
}
if(!ns.width.length&&d.style(node,"width")=="auto"){
ns.width="auto";
}
}:function(){
};
dojo._fade=function(args){
args.node=d.byId(args.node);
var _482=d.mixin({properties:{}},args);
var _483=(_482.properties.opacity={});
_483.start=!("start" in _482)?function(){
return Number(d.style(_482.node,"opacity"));
}:_482.start;
_483.end=_482.end;
var anim=d.animateProperty(_482);
d.connect(anim,"beforeBegin",d.partial(_47e,_482.node));
return anim;
};
dojo.fadeIn=function(args){
return d._fade(d.mixin({end:1},args));
};
dojo.fadeOut=function(args){
return d._fade(d.mixin({end:0},args));
};
dojo._defaultEasing=function(n){
return 0.5+((Math.sin((n+1.5)*Math.PI))/2);
};
var _488=function(_489){
this._properties=_489;
for(var p in _489){
var prop=_489[p];
if(prop.start instanceof d.Color){
prop.tempColor=new d.Color();
}
}
this.getValue=function(r){
var ret={};
for(var p in this._properties){
var prop=this._properties[p];
var _490=prop.start;
if(_490 instanceof d.Color){
ret[p]=d.blendColors(_490,prop.end,r,prop.tempColor).toCss();
}else{
if(!d.isArray(_490)){
ret[p]=((prop.end-_490)*r)+_490+(p!="opacity"?prop.units||"px":"");
}
}
}
return ret;
};
};
dojo.animateProperty=function(args){
args.node=d.byId(args.node);
if(!args.easing){
args.easing=d._defaultEasing;
}
var anim=new d._Animation(args);
d.connect(anim,"beforeBegin",anim,function(){
var pm={};
for(var p in this.properties){
var prop=(pm[p]=d.mixin({},this.properties[p]));
if(d.isFunction(prop.start)){
prop.start=prop.start();
}
if(d.isFunction(prop.end)){
prop.end=prop.end();
}
var _496=(p.toLowerCase().indexOf("color")>=0);
function getStyle(node,p){
var v=({height:node.offsetHeight,width:node.offsetWidth})[p];
if(v!==undefined){
return v;
}
v=d.style(node,p);
return (p=="opacity")?Number(v):parseFloat(v);
}
if(!("end" in prop)){
prop.end=getStyle(this.node,p);
}else{
if(!("start" in prop)){
prop.start=getStyle(this.node,p);
}
}
if(_496){
prop.start=new d.Color(prop.start);
prop.end=new d.Color(prop.end);
}else{
prop.start=(p=="opacity")?Number(prop.start):parseFloat(prop.start);
}
}
this.curve=new _488(pm);
});
d.connect(anim,"onAnimate",anim,function(_49a){
for(var s in _49a){
d.style(this.node,s,_49a[s]);
}
});
return anim;
};
})();
}

if(!dojo._hasResource["dojo.fx"]){
dojo._hasResource["dojo.fx"]=true;
dojo.provide("dojo.fx");
dojo.provide("dojo.fx.Toggler");
dojo.fx.chain=function(_1){
var _2=_1.shift();
var _3=_2;
dojo.forEach(_1,function(_4){
dojo.connect(_3,"onEnd",_4,"play");
_3=_4;
});
return _2;
};
dojo.fx.combine=function(_5){
var _6=new dojo._Animation({curve:[0,1]});
if(!_5.length){
return _6;
}
_6.duration=_5[0].duration;
dojo.forEach(_5,function(_7){
dojo.forEach(["play","pause","stop"],function(e){
if(_7[e]){
dojo.connect(_6,e,_7,e);
}
});
});
return _6;
};
dojo.declare("dojo.fx.Toggler",null,{constructor:function(_9){
var _t=this;
dojo.mixin(_t,_9);
_t.node=_9.node;
_t._showArgs=dojo.mixin({},_9);
_t._showArgs.node=_t.node;
_t._showArgs.duration=_t.showDuration;
_t.showAnim=_t.showFunc(_t._showArgs);
_t._hideArgs=dojo.mixin({},_9);
_t._hideArgs.node=_t.node;
_t._hideArgs.duration=_t.hideDuration;
_t.hideAnim=_t.hideFunc(_t._hideArgs);
dojo.connect(_t.showAnim,"beforeBegin",dojo.hitch(_t.hideAnim,"stop",true));
dojo.connect(_t.hideAnim,"beforeBegin",dojo.hitch(_t.showAnim,"stop",true));
},node:null,showFunc:dojo.fadeIn,hideFunc:dojo.fadeOut,showDuration:200,hideDuration:200,show:function(_b){
return this.showAnim.play(_b||0);
},hide:function(_c){
return this.hideAnim.play(_c||0);
}});
dojo.fx.wipeIn=function(_d){
_d.node=dojo.byId(_d.node);
var _e=_d.node,s=_e.style;
var _f=dojo.animateProperty(dojo.mixin({properties:{height:{start:function(){
s.overflow="hidden";
if(s.visibility=="hidden"||s.display=="none"){
s.height="1px";
s.display="";
s.visibility="";
return 1;
}else{
var _10=dojo.style(_e,"height");
return Math.max(_10,1);
}
},end:function(){
return _e.scrollHeight;
}}}},_d));
dojo.connect(_f,"onEnd",function(){
s.height="auto";
});
return _f;
};
dojo.fx.wipeOut=function(_11){
var _12=_11.node=dojo.byId(_11.node);
var s=_12.style;
var _14=dojo.animateProperty(dojo.mixin({properties:{height:{end:1}}},_11));
dojo.connect(_14,"beforeBegin",function(){
s.overflow="hidden";
s.display="";
});
dojo.connect(_14,"onEnd",function(){
s.height="auto";
s.display="none";
});
return _14;
};
dojo.fx.slideTo=function(_15){
var _16=(_15.node=dojo.byId(_15.node));
var top=null;
var _18=null;
var _19=(function(n){
return function(){
var cs=dojo.getComputedStyle(n);
var pos=cs.position;
top=(pos=="absolute"?n.offsetTop:parseInt(cs.top)||0);
_18=(pos=="absolute"?n.offsetLeft:parseInt(cs.left)||0);
if(pos!="absolute"&&pos!="relative"){
var ret=dojo.coords(n,true);
top=ret.y;
_18=ret.x;
n.style.position="absolute";
n.style.top=top+"px";
n.style.left=_18+"px";
}
};
})(_16);
_19();
var _1e=dojo.animateProperty(dojo.mixin({properties:{top:{end:_15.top||0},left:{end:_15.left||0}}},_15));
dojo.connect(_1e,"beforeBegin",_1e,_19);
return _1e;
};
}

if(!dojo._hasResource["dojo.io.iframe"]){
dojo._hasResource["dojo.io.iframe"]=true;
dojo.provide("dojo.io.iframe");
dojo.io.iframe={create:function(_1,_2,_3){
if(window[_1]){
return window[_1];
}
if(window.frames[_1]){
return window.frames[_1];
}
var _4=null;
var _5=_3;
if(!_5){
if(djConfig["useXDomain"]&&!djConfig["dojoBlankHtmlUrl"]){
console.debug("dojo.io.iframe.create: When using cross-domain Dojo builds,"+" please save dojo/resources/blank.html to your domain and set djConfig.dojoBlankHtmlUrl"+" to the path on your domain to blank.html");
}
_5=(djConfig["dojoBlankHtmlUrl"]||dojo.moduleUrl("dojo","resources/blank.html"));
}
var _6=dojo.isIE?"<iframe name=\""+_1+"\" src=\""+_5+"\" onload=\""+_2+"\">":"iframe";
_4=dojo.doc.createElement(_6);
with(_4){
name=_1;
setAttribute("name",_1);
id=_1;
}
dojo.body().appendChild(_4);
window[_1]=_4;
with(_4.style){
if(dojo.isSafari<3){
position="absolute";
}
left=top="1px";
height=width="1px";
visibility="hidden";
}
if(!dojo.isIE){
this.setSrc(_4,_5,true);
_4.onload=new Function(_2);
}
return _4;
},setSrc:function(_7,_8,_9){
try{
if(!_9){
if(dojo.isSafari){
_7.location=_8;
}else{
frames[_7.name].location=_8;
}
}else{
var _a;
if(dojo.isIE||dojo.isSafari>2){
_a=_7.contentWindow.document;
}else{
if(dojo.isSafari){
_a=_7.document;
}else{
_a=_7.contentWindow;
}
}
if(!_a){
_7.location=_8;
return;
}else{
_a.location.replace(_8);
}
}
}
catch(e){
console.debug("dojo.io.iframe.setSrc: ",e);
}
},doc:function(_b){
var _c=_b.contentDocument||((_b.contentWindow)&&(_b.contentWindow.document))||((_b.name)&&(document.frames[_b.name])&&(document.frames[_b.name].document))||null;
return _c;
},send:function(_d){
if(!this["_frame"]){
this._frame=this.create(this._iframeName,"dojo.io.iframe._iframeOnload();");
}
var _e=dojo._ioSetArgs(_d,function(_f){
_f.canceled=true;
_f.ioArgs._callNext();
},function(dfd){
var _11=null;
try{
var _12=dfd.ioArgs;
var dii=dojo.io.iframe;
var ifd=dii.doc(dii._frame);
var _15=_12.handleAs;
_11=ifd;
if(_15!="html"){
_11=ifd.getElementsByTagName("textarea")[0].value;
if(_15=="json"){
_11=dojo.fromJson(_11);
}else{
if(_15=="javascript"){
_11=dojo.eval(_11);
}
}
}
}
catch(e){
_11=e;
}
finally{
_12._callNext();
}
return _11;
},function(_16,dfd){
dfd.ioArgs._hasError=true;
dfd.ioArgs._callNext();
return _16;
});
_e.ioArgs._callNext=function(){
if(!this["_calledNext"]){
this._calledNext=true;
dojo.io.iframe._currentDfd=null;
dojo.io.iframe._fireNextRequest();
}
};
this._dfdQueue.push(_e);
this._fireNextRequest();
dojo._ioWatch(_e,function(dfd){
return !dfd.ioArgs["_hasError"];
},function(dfd){
return (!!dfd.ioArgs["_finished"]);
},function(dfd){
if(dfd.ioArgs._finished){
dfd.callback(dfd);
}else{
dfd.errback(new Error("Invalid dojo.io.iframe request state"));
}
});
return _e;
},_currentDfd:null,_dfdQueue:[],_iframeName:"dojoIoIframe",_fireNextRequest:function(){
try{
if((this._currentDfd)||(this._dfdQueue.length==0)){
return;
}
var dfd=this._currentDfd=this._dfdQueue.shift();
var _1c=dfd.ioArgs;
var _1d=_1c.args;
_1c._contentToClean=[];
var fn=_1d["form"];
var _1f=_1d["content"]||{};
if(fn){
if(_1f){
for(var x in _1f){
if(!fn[x]){
var tn;
if(dojo.isIE){
tn=dojo.doc.createElement("<input type='hidden' name='"+x+"'>");
}else{
tn=dojo.doc.createElement("input");
tn.type="hidden";
tn.name=x;
}
tn.value=_1f[x];
fn.appendChild(tn);
_1c._contentToClean.push(x);
}else{
fn[x].value=_1f[x];
}
}
}
var _22=fn.getAttributeNode("action");
var _23=fn.getAttributeNode("method");
var _24=fn.getAttributeNode("target");
if(_1d["url"]){
_1c._originalAction=_22?_22.value:null;
if(_22){
_22.value=_1d.url;
}else{
fn.setAttribute("action",_1d.url);
}
}
if(!_23||!_23.value){
if(_23){
_23.value=(_1d["method"])?_1d["method"]:"post";
}else{
fn.setAttribute("method",(_1d["method"])?_1d["method"]:"post");
}
}
_1c._originalTarget=_24?_24.value:null;
if(_24){
_24.value=this._iframeName;
}else{
fn.setAttribute("target",this._iframeName);
}
fn.target=this._iframeName;
fn.submit();
}else{
var _25=_1d.url+(_1d.url.indexOf("?")>-1?"&":"?")+_1c.query;
this.setSrc(this._frame,_25,true);
}
}
catch(e){
dfd.errback(e);
}
},_iframeOnload:function(){
var dfd=this._currentDfd;
if(!dfd){
this._fireNextRequest();
return;
}
var _27=dfd.ioArgs;
var _28=_27.args;
var _29=_28.form;
if(_29){
var _2a=_27._contentToClean;
for(var i=0;i<_2a.length;i++){
var key=_2a[i];
if(dojo.isSafari<3){
for(var j=0;j<_29.childNodes.length;j++){
var _2e=_29.childNodes[j];
if(_2e.name==key){
dojo._destroyElement(_2e);
break;
}
}
}else{
dojo._destroyElement(_29[key]);
_29[key]=null;
}
}
if(_27["_originalAction"]){
_29.setAttribute("action",_27._originalAction);
}
if(_27["_originalTarget"]){
_29.setAttribute("target",_27._originalTarget);
_29.target=_27._originalTarget;
}
}
_27._finished=true;
}};
}

if(!dojo._hasResource["dojo.io.script"]){
dojo._hasResource["dojo.io.script"]=true;
dojo.provide("dojo.io.script");
dojo.io.script={get:function(_1){
var _2=this._makeScriptDeferred(_1);
var _3=_2.ioArgs;
dojo._ioAddQueryToUrl(_3);
_3.id=_1.id;
this.attach(_3.id,_3.url);
dojo._ioWatch(_2,this._validCheck,this._ioCheck,this._resHandle);
return _2;
},attach:function(id,_5){
var _6=dojo.doc.createElement("script");
_6.type="text/javascript";
_6.src=_5;
_6.id=id;
dojo.doc.getElementsByTagName("head")[0].appendChild(_6);
},remove:function(id){
dojo._destroyElement(dojo.byId(id));
if(this["jsonp_"+id]){
delete this["jsonp_"+id];
}
},_makeScriptDeferred:function(_8){
var _9=dojo._ioSetArgs(_8,this._deferredCancel,this._deferredOk,this._deferredError);
var _a=_9.ioArgs;
_a.id="dojoIoScript"+(this._counter++);
_a.canDelete=false;
if(_8.callbackParamName){
_a.query=_a.query||"";
if(_a.query.length>0){
_a.query+="&";
}
_a.query+=_8.callbackParamName+"=dojo.io.script.jsonp_"+_a.id+"._jsonpCallback";
_a.canDelete=true;
_9._jsonpCallback=this._jsonpCallback;
this["jsonp_"+_a.id]=_9;
}
return _9;
},_deferredCancel:function(_b){
_b.canceled=true;
if(_b.ioArgs.canDelete){
dojo.io.script._deadScripts.push(_b.ioArgs.id);
}
},_deferredOk:function(_c){
if(_c.ioArgs.canDelete){
dojo.io.script._deadScripts.push(_c.ioArgs.id);
}
if(_c.ioArgs.json){
return _c.ioArgs.json;
}else{
return _c.ioArgs;
}
},_deferredError:function(_d,_e){
if(_e.ioArgs.canDelete){
if(_d.dojoType=="timeout"){
dojo.io.script.remove(_e.ioArgs.id);
}else{
dojo.io.script._deadScripts.push(_e.ioArgs.id);
}
}
console.debug("dojo.io.script error",_d);
return _d;
},_deadScripts:[],_counter:1,_validCheck:function(_f){
var _10=dojo.io.script;
var _11=_10._deadScripts;
if(_11&&_11.length>0){
for(var i=0;i<_11.length;i++){
_10.remove(_11[i]);
}
dojo.io.script._deadScripts=[];
}
return true;
},_ioCheck:function(dfd){
if(dfd.ioArgs.json){
return true;
}
var _14=dfd.ioArgs.args.checkString;
if(_14&&eval("typeof("+_14+") != 'undefined'")){
return true;
}
return false;
},_resHandle:function(dfd){
if(dojo.io.script._ioCheck(dfd)){
dfd.callback(dfd);
}else{
dfd.errback(new Error("inconceivable dojo.io.script._resHandle error"));
}
},_jsonpCallback:function(_16){
this.ioArgs.json=_16;
}};
}

if(!dojo._hasResource["dojo.cookie"]){
dojo._hasResource["dojo.cookie"]=true;
dojo.provide("dojo.cookie");
dojo.cookie=function(_1,_2,_3){
var c=document.cookie;
if(arguments.length==1){
var _5=c.lastIndexOf(_1+"=");
if(_5==-1){
return null;
}
var _6=_5+_1.length+1;
var _7=c.indexOf(";",_5+_1.length+1);
if(_7==-1){
_7=c.length;
}
return decodeURIComponent(c.substring(_6,_7));
}else{
_3=_3||{};
_2=encodeURIComponent(_2);
if(typeof (_3.expires)=="number"){
var d=new Date();
d.setTime(d.getTime()+(_3.expires*24*60*60*1000));
_3.expires=d;
}
document.cookie=_1+"="+_2+(_3.expires?"; expires="+_3.expires.toUTCString():"")+(_3.path?"; path="+_3.path:"")+(_3.domain?"; domain="+_3.domain:"")+(_3.secure?"; secure":"");
return null;
}
};
}

if(!dojo._hasResource["dojo.string"]){
dojo._hasResource["dojo.string"]=true;
dojo.provide("dojo.string");
dojo.string.pad=function(_1,_2,ch,_4){
var _5=String(_1);
if(!ch){
ch="0";
}
while(_5.length<_2){
if(_4){
_5+=ch;
}else{
_5=ch+_5;
}
}
return _5;
};
dojo.string.substitute=function(_6,_7,_8,_9){
return _6.replace(/\$\{([^\s\:\}]+)(?:\:([^\s\:\}]+))?\}/g,function(_a,_b,_c){
var _d=dojo.getObject(_b,false,_7);
if(_c){
_d=dojo.getObject(_c,false,_9)(_d);
}
if(_8){
_d=_8(_d,_b);
}
return _d.toString();
});
};
dojo.string.trim=function(_e){
_e=_e.replace(/^\s+/,"");
for(var i=_e.length-1;i>0;i--){
if(/\S/.test(_e.charAt(i))){
_e=_e.substring(0,i+1);
break;
}
}
return _e;
};
}

