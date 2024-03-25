/*! For license information please see 158.main.js.LICENSE.txt */
"use strict";(self.webpackChunkfrontend_base=self.webpackChunkfrontend_base||[]).push([[158],{158:(t,r,e)=>{e.r(r);var n=e(416),o=e.n(n),a=e(745),i=e(94),c=e(714),u=e.n(c);function s(t){return s="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},s(t)}function f(t,r){var e=Object.keys(t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(t);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(t,r).enumerable}))),e.push.apply(e,n)}return e}function p(t){for(var r=1;r<arguments.length;r++){var e=null!=arguments[r]?arguments[r]:{};r%2?f(Object(e),!0).forEach((function(r){var n,o,a,i;n=t,o=r,a=e[r],i=function(t,r){if("object"!=s(t)||!t)return t;var e=t[Symbol.toPrimitive];if(void 0!==e){var n=e.call(t,"string");if("object"!=s(n))return n;throw new TypeError("@@toPrimitive must return a primitive value.")}return String(t)}(o),(o="symbol"==s(i)?i:String(i))in n?Object.defineProperty(n,o,{value:a,enumerable:!0,configurable:!0,writable:!0}):n[o]=a})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(e)):f(Object(e)).forEach((function(r){Object.defineProperty(t,r,Object.getOwnPropertyDescriptor(e,r))}))}return t}function l(t){return function(t){if(Array.isArray(t))return w(t)}(t)||function(t){if("undefined"!=typeof Symbol&&null!=t[Symbol.iterator]||null!=t["@@iterator"])return Array.from(t)}(t)||m(t)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function h(){h=function(){return r};var t,r={},e=Object.prototype,n=e.hasOwnProperty,o=Object.defineProperty||function(t,r,e){t[r]=e.value},a="function"==typeof Symbol?Symbol:{},i=a.iterator||"@@iterator",c=a.asyncIterator||"@@asyncIterator",u=a.toStringTag||"@@toStringTag";function f(t,r,e){return Object.defineProperty(t,r,{value:e,enumerable:!0,configurable:!0,writable:!0}),t[r]}try{f({},"")}catch(t){f=function(t,r,e){return t[r]=e}}function p(t,r,e,n){var a=r&&r.prototype instanceof b?r:b,i=Object.create(a.prototype),c=new K(n||[]);return o(i,"_invoke",{value:P(t,e,c)}),i}function l(t,r,e){try{return{type:"normal",arg:t.call(r,e)}}catch(t){return{type:"throw",arg:t}}}r.wrap=p;var y="suspendedStart",v="suspendedYield",d="executing",m="completed",w={};function b(){}function g(){}function S(){}var x={};f(x,i,(function(){return this}));var E=Object.getPrototypeOf,A=E&&E(E(T([])));A&&A!==e&&n.call(A,i)&&(x=A);var O=S.prototype=b.prototype=Object.create(x);function j(t){["next","throw","return"].forEach((function(r){f(t,r,(function(t){return this._invoke(r,t)}))}))}function k(t,r){function e(o,a,i,c){var u=l(t[o],t,a);if("throw"!==u.type){var f=u.arg,p=f.value;return p&&"object"==s(p)&&n.call(p,"__await")?r.resolve(p.__await).then((function(t){e("next",t,i,c)}),(function(t){e("throw",t,i,c)})):r.resolve(p).then((function(t){f.value=t,i(f)}),(function(t){return e("throw",t,i,c)}))}c(u.arg)}var a;o(this,"_invoke",{value:function(t,n){function o(){return new r((function(r,o){e(t,n,r,o)}))}return a=a?a.then(o,o):o()}})}function P(r,e,n){var o=y;return function(a,i){if(o===d)throw new Error("Generator is already running");if(o===m){if("throw"===a)throw i;return{value:t,done:!0}}for(n.method=a,n.arg=i;;){var c=n.delegate;if(c){var u=L(c,n);if(u){if(u===w)continue;return u}}if("next"===n.method)n.sent=n._sent=n.arg;else if("throw"===n.method){if(o===y)throw o=m,n.arg;n.dispatchException(n.arg)}else"return"===n.method&&n.abrupt("return",n.arg);o=d;var s=l(r,e,n);if("normal"===s.type){if(o=n.done?m:v,s.arg===w)continue;return{value:s.arg,done:n.done}}"throw"===s.type&&(o=m,n.method="throw",n.arg=s.arg)}}}function L(r,e){var n=e.method,o=r.iterator[n];if(o===t)return e.delegate=null,"throw"===n&&r.iterator.return&&(e.method="return",e.arg=t,L(r,e),"throw"===e.method)||"return"!==n&&(e.method="throw",e.arg=new TypeError("The iterator does not provide a '"+n+"' method")),w;var a=l(o,r.iterator,e.arg);if("throw"===a.type)return e.method="throw",e.arg=a.arg,e.delegate=null,w;var i=a.arg;return i?i.done?(e[r.resultName]=i.value,e.next=r.nextLoc,"return"!==e.method&&(e.method="next",e.arg=t),e.delegate=null,w):i:(e.method="throw",e.arg=new TypeError("iterator result is not an object"),e.delegate=null,w)}function _(t){var r={tryLoc:t[0]};1 in t&&(r.catchLoc=t[1]),2 in t&&(r.finallyLoc=t[2],r.afterLoc=t[3]),this.tryEntries.push(r)}function C(t){var r=t.completion||{};r.type="normal",delete r.arg,t.completion=r}function K(t){this.tryEntries=[{tryLoc:"root"}],t.forEach(_,this),this.reset(!0)}function T(r){if(r||""===r){var e=r[i];if(e)return e.call(r);if("function"==typeof r.next)return r;if(!isNaN(r.length)){var o=-1,a=function e(){for(;++o<r.length;)if(n.call(r,o))return e.value=r[o],e.done=!1,e;return e.value=t,e.done=!0,e};return a.next=a}}throw new TypeError(s(r)+" is not iterable")}return g.prototype=S,o(O,"constructor",{value:S,configurable:!0}),o(S,"constructor",{value:g,configurable:!0}),g.displayName=f(S,u,"GeneratorFunction"),r.isGeneratorFunction=function(t){var r="function"==typeof t&&t.constructor;return!!r&&(r===g||"GeneratorFunction"===(r.displayName||r.name))},r.mark=function(t){return Object.setPrototypeOf?Object.setPrototypeOf(t,S):(t.__proto__=S,f(t,u,"GeneratorFunction")),t.prototype=Object.create(O),t},r.awrap=function(t){return{__await:t}},j(k.prototype),f(k.prototype,c,(function(){return this})),r.AsyncIterator=k,r.async=function(t,e,n,o,a){void 0===a&&(a=Promise);var i=new k(p(t,e,n,o),a);return r.isGeneratorFunction(e)?i:i.next().then((function(t){return t.done?t.value:i.next()}))},j(O),f(O,u,"Generator"),f(O,i,(function(){return this})),f(O,"toString",(function(){return"[object Generator]"})),r.keys=function(t){var r=Object(t),e=[];for(var n in r)e.push(n);return e.reverse(),function t(){for(;e.length;){var n=e.pop();if(n in r)return t.value=n,t.done=!1,t}return t.done=!0,t}},r.values=T,K.prototype={constructor:K,reset:function(r){if(this.prev=0,this.next=0,this.sent=this._sent=t,this.done=!1,this.delegate=null,this.method="next",this.arg=t,this.tryEntries.forEach(C),!r)for(var e in this)"t"===e.charAt(0)&&n.call(this,e)&&!isNaN(+e.slice(1))&&(this[e]=t)},stop:function(){this.done=!0;var t=this.tryEntries[0].completion;if("throw"===t.type)throw t.arg;return this.rval},dispatchException:function(r){if(this.done)throw r;var e=this;function o(n,o){return c.type="throw",c.arg=r,e.next=n,o&&(e.method="next",e.arg=t),!!o}for(var a=this.tryEntries.length-1;a>=0;--a){var i=this.tryEntries[a],c=i.completion;if("root"===i.tryLoc)return o("end");if(i.tryLoc<=this.prev){var u=n.call(i,"catchLoc"),s=n.call(i,"finallyLoc");if(u&&s){if(this.prev<i.catchLoc)return o(i.catchLoc,!0);if(this.prev<i.finallyLoc)return o(i.finallyLoc)}else if(u){if(this.prev<i.catchLoc)return o(i.catchLoc,!0)}else{if(!s)throw new Error("try statement without catch or finally");if(this.prev<i.finallyLoc)return o(i.finallyLoc)}}}},abrupt:function(t,r){for(var e=this.tryEntries.length-1;e>=0;--e){var o=this.tryEntries[e];if(o.tryLoc<=this.prev&&n.call(o,"finallyLoc")&&this.prev<o.finallyLoc){var a=o;break}}a&&("break"===t||"continue"===t)&&a.tryLoc<=r&&r<=a.finallyLoc&&(a=null);var i=a?a.completion:{};return i.type=t,i.arg=r,a?(this.method="next",this.next=a.finallyLoc,w):this.complete(i)},complete:function(t,r){if("throw"===t.type)throw t.arg;return"break"===t.type||"continue"===t.type?this.next=t.arg:"return"===t.type?(this.rval=this.arg=t.arg,this.method="return",this.next="end"):"normal"===t.type&&r&&(this.next=r),w},finish:function(t){for(var r=this.tryEntries.length-1;r>=0;--r){var e=this.tryEntries[r];if(e.finallyLoc===t)return this.complete(e.completion,e.afterLoc),C(e),w}},catch:function(t){for(var r=this.tryEntries.length-1;r>=0;--r){var e=this.tryEntries[r];if(e.tryLoc===t){var n=e.completion;if("throw"===n.type){var o=n.arg;C(e)}return o}}throw new Error("illegal catch attempt")},delegateYield:function(r,e,n){return this.delegate={iterator:T(r),resultName:e,nextLoc:n},"next"===this.method&&(this.arg=t),w}},r}function y(t,r,e,n,o,a,i){try{var c=t[a](i),u=c.value}catch(t){return void e(t)}c.done?r(u):Promise.resolve(u).then(n,o)}function v(t){return function(){var r=this,e=arguments;return new Promise((function(n,o){var a=t.apply(r,e);function i(t){y(a,n,o,i,c,"next",t)}function c(t){y(a,n,o,i,c,"throw",t)}i(void 0)}))}}function d(t,r){return function(t){if(Array.isArray(t))return t}(t)||function(t,r){var e=null==t?null:"undefined"!=typeof Symbol&&t[Symbol.iterator]||t["@@iterator"];if(null!=e){var n,o,a,i,c=[],u=!0,s=!1;try{if(a=(e=e.call(t)).next,0===r){if(Object(e)!==e)return;u=!1}else for(;!(u=(n=a.call(e)).done)&&(c.push(n.value),c.length!==r);u=!0);}catch(t){s=!0,o=t}finally{try{if(!u&&null!=e.return&&(i=e.return(),Object(i)!==i))return}finally{if(s)throw o}}return c}}(t,r)||m(t,r)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function m(t,r){if(t){if("string"==typeof t)return w(t,r);var e=Object.prototype.toString.call(t).slice(8,-1);return"Object"===e&&t.constructor&&(e=t.constructor.name),"Map"===e||"Set"===e?Array.from(t):"Arguments"===e||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(e)?w(t,r):void 0}}function w(t,r){(null==r||r>t.length)&&(r=t.length);for(var e=0,n=new Array(r);e<r;e++)n[e]=t[e];return n}var b=(0,n.createContext)(null),g=function(){var t=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",r=crypto.getRandomValues(new Uint8Array(16)),e=Array.from(r).map((function(t){return t.toString(16).padStart(2,"0")})).join("");return t?t+e:e};const S=function(t){var r=t.entropy,e=void 0===r?"":r,a=t.children,c=d((0,n.useState)(g((e||"")+Date.now())),2),s=c[0],f=c[1],y=d((0,n.useState)(new(u())(s)),2),m=y[0],w=y[1];(0,n.useEffect)((function(){var t=function(){var t=v(h().mark((function t(){var r;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.next=2,S(e);case 2:r=t.sent,f(r),w(new(u())(r));case 5:case"end":return t.stop()}}),t)})));return function(){return t.apply(this,arguments)}}();t()}),[e]);var S=function(){var t=v(h().mark((function t(r){var e,n,o,a,i,c;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return e=JSON.stringify(r),n=new TextEncoder,o=n.encode(e),t.next=5,crypto.subtle.digest("SHA-256",o);case 5:return a=t.sent,i=Array.from(new Uint8Array(a)),c=i.map((function(t){return t.toString(16).padStart(2,"0")})).join(""),t.abrupt("return",c);case 9:case"end":return t.stop()}}),t)})));return function(r){return t.apply(this,arguments)}}(),x=function(){var t=v(h().mark((function t(r){var e,n,o,a,i,c;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return e=JSON.stringify(r),n=new TextEncoder,o=n.encode(e),t.next=5,crypto.subtle.digest("SHA-512",o);case 5:return a=t.sent,i=Array.from(new Uint8Array(a)),c=i.map((function(t){return t.toString(16).padStart(2,"0")})).join(""),t.abrupt("return",c);case 9:case"end":return t.stop()}}),t)})));return function(r){return t.apply(this,arguments)}}(),E=function(){var t=v(h().mark((function t(r){var e,n;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return e=JSON.stringify(r),n=(0,i.sha3_512)(e),t.abrupt("return",n);case 3:case"end":return t.stop()}}),t)})));return function(r){return t.apply(this,arguments)}}(),A=function(){var t=v(h().mark((function t(){var r;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.prev=0,t.next=3,crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,["encrypt","decrypt"]);case 3:return r=t.sent,t.abrupt("return",{publicKey:r.publicKey,privateKey:r.privateKey});case 7:throw t.prev=7,t.t0=t.catch(0),console.error("Error generating key pair:",t.t0),t.t0;case 11:case"end":return t.stop()}}),t,null,[[0,7]])})));return function(){return t.apply(this,arguments)}}();function O(t,r){for(var e in t)t.hasOwnProperty(e)&&(r[e]=t[e]);return r}var j=function(){var t=v(h().mark((function t(r){var e;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.prev=0,t.next=3,crypto.subtle.importKey("jwk",r,{name:"RSA-OAEP",hash:"SHA-256"},!0,["encrypt"]);case 3:return e=t.sent,t.abrupt("return",O(r,e));case 7:throw t.prev=7,t.t0=t.catch(0),console.error("Error deserializing public key:",t.t0),t.t0;case 11:case"end":return t.stop()}}),t,null,[[0,7]])})));return function(r){return t.apply(this,arguments)}}(),k=function(){var t=v(h().mark((function t(r){var e;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.prev=0,t.next=3,crypto.subtle.importKey("jwk",r,{name:"RSA-OAEP",hash:"SHA-256"},!0,["decrypt"]);case 3:return e=t.sent,t.abrupt("return",O(r,e));case 7:throw t.prev=7,t.t0=t.catch(0),console.error("Error deserializing private key:",t.t0),t.t0;case 11:case"end":return t.stop()}}),t,null,[[0,7]])})));return function(r){return t.apply(this,arguments)}}(),P=function(){var t=v(h().mark((function t(r,e){var n,o;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return n=(new TextEncoder).encode(r),t.next=3,window.crypto.subtle.encrypt({name:"RSA-OAEP",hash:"SHA-256"},e,n).catch((function(t){console.log("error",t)}));case 3:return o=t.sent,t.abrupt("return",btoa(String.fromCharCode.apply(String,l(new Uint8Array(o)))));case 5:case"end":return t.stop()}}),t)})));return function(r,e){return t.apply(this,arguments)}}(),L=function(){var t=v(h().mark((function t(r,e,n){var o,a,i;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return o=Uint8Array.from(atob(r),(function(t){return t.charCodeAt(0)})),t.prev=1,t.next=4,window.crypto.subtle.decrypt({name:"RSA-OAEP",hash:"SHA-256"},e,o);case 4:return a=t.sent,i=(new TextDecoder).decode(a),t.abrupt("return",i);case 9:throw t.prev=9,t.t0=t.catch(1),console.log("error",t.t0),new Error("Unable to decrypt message. Incorrect passphrase.",t.t0);case 13:case"end":return t.stop()}}),t,null,[[1,9]])})));return function(r,e,n){return t.apply(this,arguments)}}(),_=function(){var t=v(h().mark((function t(){var r;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.next=2,window.crypto.subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"]);case 2:return r=t.sent,t.abrupt("return",r);case 4:case"end":return t.stop()}}),t)})));return function(){return t.apply(this,arguments)}}(),C=function(){var t=v(h().mark((function t(r){var e;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.next=2,window.crypto.subtle.importKey("jwk",p(p({},r),{},{kty:"oct"}),{name:"AES-GCM"},!0,["encrypt","decrypt"]);case 2:return e=t.sent,t.abrupt("return",O(r,e));case 4:case"end":return t.stop()}}),t)})));return function(r){return t.apply(this,arguments)}}(),K=function(){var t=v(h().mark((function t(r,e){var n,o,a;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return n=(new TextEncoder).encode(r),o=window.crypto.getRandomValues(new Uint8Array(12)),t.next=4,window.crypto.subtle.encrypt({name:"AES-GCM",iv:o},e,n).catch((function(t){console.log("error",t)}));case 4:return a=t.sent,t.abrupt("return",{ciphertext:btoa(String.fromCharCode.apply(String,l(new Uint8Array(a)))),iv:btoa(String.fromCharCode.apply(String,l(new Uint8Array(o))))});case 6:case"end":return t.stop()}}),t)})));return function(r,e){return t.apply(this,arguments)}}(),T=function(){var t=v(h().mark((function t(r,e){var n,o,a,i,c,u;return h().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return n=r.ciphertext,o=r.iv,a=Uint8Array.from(atob(n),(function(t){return t.charCodeAt(0)})),i=Uint8Array.from(atob(o),(function(t){return t.charCodeAt(0)})),t.prev=3,t.next=6,window.crypto.subtle.decrypt({name:"AES-GCM",iv:i},e,a);case 6:return c=t.sent,u=(new TextDecoder).decode(c),t.abrupt("return",u);case 11:throw t.prev=11,t.t0=t.catch(3),new Error("Unable to decrypt message. Incorrect key.");case 14:case"end":return t.stop()}}),t,null,[[3,11]])})));return function(r,e){return t.apply(this,arguments)}}(),U={randomString:g,sha256Hash:S,sha512Hash:x,sha3_512Hash:E,generateKeyPair:A,deserializePublicKey:j,deserializePrivateKey:k,encrypt:P,decrypt:L,generateSymmetricKey:_,deserializeSymmetricKey:C,encryptWithSymmetricKey:K,decryptWithSymmetricKey:T,chance:m};return o().createElement(b.Provider,{value:U},a)};var x=function(){return o().createElement("div",null,o().createElement(S,null,"positive-intentions"))},E=document.getElementById("app");(0,a.s)(E).render(o().createElement(x,null))},745:(t,r,e)=>{var n=e(556);r.s=n.createRoot,n.hydrateRoot}}]);