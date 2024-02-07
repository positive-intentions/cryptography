"use strict";(self.webpackChunkfrontend_base=self.webpackChunkfrontend_base||[]).push([[725],{"./src/stories/Cryptography.stories.js":(__unused_webpack_module,__webpack_exports__,__webpack_require__)=>{__webpack_require__.r(__webpack_exports__),__webpack_require__.d(__webpack_exports__,{Basic:()=>Basic,__namedExportsOrder:()=>__namedExportsOrder,default:()=>Cryptography_stories});var react=__webpack_require__("./node_modules/react/index.js"),sha3=__webpack_require__("./node_modules/js-sha3/src/sha3.js"),chance_chance=__webpack_require__("./node_modules/chance/chance.js"),chance_default=__webpack_require__.n(chance_chance);function _array_like_to_array(arr,len){(null==len||len>arr.length)&&(len=arr.length);for(var i=0,arr2=Array(len);i<len;i++)arr2[i]=arr[i];return arr2}function _array_with_holes(arr){if(Array.isArray(arr))return arr}function _array_without_holes(arr){if(Array.isArray(arr))return _array_like_to_array(arr)}function asyncGeneratorStep(gen,resolve,reject,_next,_throw,key,arg){try{var info=gen[key](arg),value=info.value}catch(error){reject(error);return}info.done?resolve(value):Promise.resolve(value).then(_next,_throw)}function _async_to_generator(fn){return function(){var self1=this,args=arguments;return new Promise(function(resolve,reject){var gen=fn.apply(self1,args);function _next(value){asyncGeneratorStep(gen,resolve,reject,_next,_throw,"next",value)}function _throw(err){asyncGeneratorStep(gen,resolve,reject,_next,_throw,"throw",err)}_next(void 0)})}}function _define_property(obj,key,value){return key in obj?Object.defineProperty(obj,key,{value:value,enumerable:!0,configurable:!0,writable:!0}):obj[key]=value,obj}function _iterable_to_array(iter){if("undefined"!=typeof Symbol&&null!=iter[Symbol.iterator]||null!=iter["@@iterator"])return Array.from(iter)}function _iterable_to_array_limit(arr,i){var _s,_e,_i=null==arr?null:"undefined"!=typeof Symbol&&arr[Symbol.iterator]||arr["@@iterator"];if(null!=_i){var _arr=[],_n=!0,_d=!1;try{for(_i=_i.call(arr);!(_n=(_s=_i.next()).done)&&(_arr.push(_s.value),!i||_arr.length!==i);_n=!0);}catch(err){_d=!0,_e=err}finally{try{_n||null==_i.return||_i.return()}finally{if(_d)throw _e}}return _arr}}function _non_iterable_rest(){throw TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}function _non_iterable_spread(){throw TypeError("Invalid attempt to spread non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}function _object_spread(target){for(var i=1;i<arguments.length;i++){var source=null!=arguments[i]?arguments[i]:{},ownKeys=Object.keys(source);"function"==typeof Object.getOwnPropertySymbols&&(ownKeys=ownKeys.concat(Object.getOwnPropertySymbols(source).filter(function(sym){return Object.getOwnPropertyDescriptor(source,sym).enumerable}))),ownKeys.forEach(function(key){_define_property(target,key,source[key])})}return target}function ownKeys(object,enumerableOnly){var keys=Object.keys(object);if(Object.getOwnPropertySymbols){var symbols=Object.getOwnPropertySymbols(object);enumerableOnly&&(symbols=symbols.filter(function(sym){return Object.getOwnPropertyDescriptor(object,sym).enumerable})),keys.push.apply(keys,symbols)}return keys}function _object_spread_props(target,source){return source=null!=source?source:{},Object.getOwnPropertyDescriptors?Object.defineProperties(target,Object.getOwnPropertyDescriptors(source)):ownKeys(Object(source)).forEach(function(key){Object.defineProperty(target,key,Object.getOwnPropertyDescriptor(source,key))}),target}function _sliced_to_array(arr,i){return _array_with_holes(arr)||_iterable_to_array_limit(arr,i)||_unsupported_iterable_to_array(arr,i)||_non_iterable_rest()}function _to_consumable_array(arr){return _array_without_holes(arr)||_iterable_to_array(arr)||_unsupported_iterable_to_array(arr)||_non_iterable_spread()}function _unsupported_iterable_to_array(o,minLen){if(o){if("string"==typeof o)return _array_like_to_array(o,minLen);var n=Object.prototype.toString.call(o).slice(8,-1);if("Object"===n&&o.constructor&&(n=o.constructor.name),"Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return _array_like_to_array(o,minLen)}}function _ts_generator(thisArg,body){var f,y,t,g,_={label:0,sent:function(){if(1&t[0])throw t[1];return t[1]},trys:[],ops:[]};return g={next:verb(0),throw:verb(1),return:verb(2)},"function"==typeof Symbol&&(g[Symbol.iterator]=function(){return this}),g;function verb(n){return function(v){return step([n,v])}}function step(op){if(f)throw TypeError("Generator is already executing.");for(;_;)try{if(f=1,y&&(t=2&op[0]?y.return:op[0]?y.throw||((t=y.return)&&t.call(y),0):y.next)&&!(t=t.call(y,op[1])).done)return t;switch(y=0,t&&(op=[2&op[0],t.value]),op[0]){case 0:case 1:t=op;break;case 4:return _.label++,{value:op[1],done:!1};case 5:_.label++,y=op[1],op=[0];continue;case 7:op=_.ops.pop(),_.trys.pop();continue;default:if(!(t=(t=_.trys).length>0&&t[t.length-1])&&(6===op[0]||2===op[0])){_=0;continue}if(3===op[0]&&(!t||op[1]>t[0]&&op[1]<t[3])){_.label=op[1];break}if(6===op[0]&&_.label<t[1]){_.label=t[1],t=op;break}if(t&&_.label<t[2]){_.label=t[2],_.ops.push(op);break}t[2]&&_.ops.pop(),_.trys.pop();continue}op=body.call(thisArg,_)}catch(e){op=[6,e],y=0}finally{f=t=0}if(5&op[0])throw op[1];return{value:op[0]?op[1]:void 0,done:!0}}}var CryptographyContext=(0,react.createContext)(null),randomString=function(){var additionalSalt=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",randomHex=Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function(byte){return byte.toString(16).padStart(2,"0")}).join("");return additionalSalt?additionalSalt+randomHex:randomHex},CryptographyProvider=function(param){var _ref,_ref1,_ref2,_ref3,_ref4,_ref5,_ref6,_ref7,_ref8,_ref9,_ref10,_ref11,_param_entropy=param.entropy,entropy=void 0===_param_entropy?"":_param_entropy,children=param.children,setClassPropsFromJson=function(json,instance){for(var prop in json)json.hasOwnProperty(prop)&&(instance[prop]=json[prop]);return instance},_useState=_sliced_to_array((0,react.useState)(""),2),salt=_useState[0],setSalt=_useState[1],_useState1=_sliced_to_array((0,react.useState)(new(chance_default())(salt)),2),chance=_useState1[0],setChance=_useState1[1];(0,react.useEffect)(function(){var _ref;(_ref=_async_to_generator(function(){var newSalt;return _ts_generator(this,function(_state){switch(_state.label){case 0:return[4,sha256Hash(entropy)];case 1:return setSalt(newSalt=_state.sent()),setChance(new(chance_default())(newSalt)),[2]}})}),function updateSates(){return _ref.apply(this,arguments)})()},[entropy]);var sha256Hash=(_ref=_async_to_generator(function(input){var inputString,data,hashBuffer;return _ts_generator(this,function(_state){switch(_state.label){case 0:return inputString=JSON.stringify(input),data=new TextEncoder().encode(inputString),[4,crypto.subtle.digest("SHA-256",data)];case 1:return hashBuffer=_state.sent(),[2,Array.from(new Uint8Array(hashBuffer)).map(function(byte){return byte.toString(16).padStart(2,"0")}).join("")]}})}),function sha256Hash(input){return _ref.apply(this,arguments)}),sha512Hash=(_ref1=_async_to_generator(function(input){var inputString,data,hashBuffer;return _ts_generator(this,function(_state){switch(_state.label){case 0:return inputString=JSON.stringify(input),data=new TextEncoder().encode(inputString),[4,crypto.subtle.digest("SHA-512",data)];case 1:return hashBuffer=_state.sent(),[2,Array.from(new Uint8Array(hashBuffer)).map(function(byte){return byte.toString(16).padStart(2,"0")}).join("")]}})}),function sha512Hash(input){return _ref1.apply(this,arguments)}),sha3_512Hash=(_ref2=_async_to_generator(function(input){var inputString;return _ts_generator(this,function(_state){return inputString=JSON.stringify(input),[2,(0,sha3.sha3_512)(inputString)]})}),function sha3_512Hash(input){return _ref2.apply(this,arguments)}),generateKeyPair=(_ref3=_async_to_generator(function(){var keyPair,error;return _ts_generator(this,function(_state){switch(_state.label){case 0:return _state.trys.push([0,2,,3]),[4,crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,["encrypt","decrypt"])];case 1:return[2,{publicKey:(keyPair=_state.sent()).publicKey,privateKey:keyPair.privateKey}];case 2:throw console.error("Error generating key pair:",error=_state.sent()),error;case 3:return[2]}})}),function generateKeyPair(){return _ref3.apply(this,arguments)}),deserializePublicKey=(_ref4=_async_to_generator(function(key){var error;return _ts_generator(this,function(_state){switch(_state.label){case 0:return _state.trys.push([0,2,,3]),[4,crypto.subtle.importKey("jwk",key,{name:"RSA-OAEP",hash:"SHA-256"},!0,["encrypt"])];case 1:return[2,setClassPropsFromJson(key,_state.sent())];case 2:throw console.error("Error deserializing public key:",error=_state.sent()),error;case 3:return[2]}})}),function deserializePublicKey(key){return _ref4.apply(this,arguments)}),deserializePrivateKey=(_ref5=_async_to_generator(function(key){var error;return _ts_generator(this,function(_state){switch(_state.label){case 0:return _state.trys.push([0,2,,3]),[4,crypto.subtle.importKey("jwk",key,{name:"RSA-OAEP",hash:"SHA-256"},!0,["decrypt"])];case 1:return[2,setClassPropsFromJson(key,_state.sent())];case 2:throw console.error("Error deserializing private key:",error=_state.sent()),error;case 3:return[2]}})}),function deserializePrivateKey(key){return _ref5.apply(this,arguments)}),encrypt=(_ref6=_async_to_generator(function(message,publicKey){var _String,encodedMessage,encrypted;return _ts_generator(this,function(_state){switch(_state.label){case 0:return encodedMessage=new TextEncoder().encode(message),[4,window.crypto.subtle.encrypt({name:"RSA-OAEP",hash:"SHA-256"},publicKey,encodedMessage).catch(function(error){console.log("error",error)})];case 1:return encrypted=_state.sent(),[2,btoa((_String=String).fromCharCode.apply(_String,_to_consumable_array(new Uint8Array(encrypted))))]}})}),function encrypt(message,publicKey){return _ref6.apply(this,arguments)}),decrypt=(_ref7=_async_to_generator(function(encryptedMessage,privateKey,passphrase){var buffer,decrypted,error;return _ts_generator(this,function(_state){switch(_state.label){case 0:buffer=Uint8Array.from(atob(encryptedMessage),function(c){return c.charCodeAt(0)}),_state.label=1;case 1:return _state.trys.push([1,3,,4]),[4,window.crypto.subtle.decrypt({name:"RSA-OAEP",hash:"SHA-256"},privateKey,buffer)];case 2:return decrypted=_state.sent(),[2,new TextDecoder().decode(decrypted)];case 3:throw console.log("error",error=_state.sent()),Error("Unable to decrypt message. Incorrect passphrase.",error);case 4:return[2]}})}),function decrypt(encryptedMessage,privateKey,passphrase){return _ref7.apply(this,arguments)}),generateSymmetricKey=(_ref8=_async_to_generator(function(){return _ts_generator(this,function(_state){switch(_state.label){case 0:return[4,window.crypto.subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"])];case 1:return[2,_state.sent()]}})}),function generateSymmetricKey(){return _ref8.apply(this,arguments)}),deserializeSymmetricKey=(_ref9=_async_to_generator(function(key){return _ts_generator(this,function(_state){switch(_state.label){case 0:return[4,window.crypto.subtle.importKey("jwk",_object_spread_props(_object_spread({},key),{kty:"oct"}),{name:"AES-GCM"},!0,["encrypt","decrypt"])];case 1:return[2,setClassPropsFromJson(key,_state.sent())]}})}),function deserializeSymmetricKey(key){return _ref9.apply(this,arguments)}),encryptWithSymmetricKey=(_ref10=_async_to_generator(function(message,key){var _String,_String1,encodedMessage,iv,encrypted;return _ts_generator(this,function(_state){switch(_state.label){case 0:return encodedMessage=new TextEncoder().encode(message),iv=window.crypto.getRandomValues(new Uint8Array(12)),[4,window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv},key,encodedMessage).catch(function(error){console.log("error",error)})];case 1:return encrypted=_state.sent(),[2,{ciphertext:btoa((_String=String).fromCharCode.apply(_String,_to_consumable_array(new Uint8Array(encrypted)))),iv:btoa((_String1=String).fromCharCode.apply(_String1,_to_consumable_array(new Uint8Array(iv))))}]}})}),function encryptWithSymmetricKey(message,key){return _ref10.apply(this,arguments)}),decryptWithSymmetricKey=(_ref11=_async_to_generator(function(encryptedData,key){var ciphertext,iv,buffer,ivBuffer,decrypted;return _ts_generator(this,function(_state){switch(_state.label){case 0:ciphertext=encryptedData.ciphertext,iv=encryptedData.iv,buffer=Uint8Array.from(atob(ciphertext),function(c){return c.charCodeAt(0)}),ivBuffer=Uint8Array.from(atob(iv),function(c){return c.charCodeAt(0)}),_state.label=1;case 1:return _state.trys.push([1,3,,4]),[4,window.crypto.subtle.decrypt({name:"AES-GCM",iv:ivBuffer},key,buffer)];case 2:return decrypted=_state.sent(),[2,new TextDecoder().decode(decrypted)];case 3:throw _state.sent(),Error("Unable to decrypt message. Incorrect key.");case 4:return[2]}})}),function decryptWithSymmetricKey(encryptedData,key){return _ref11.apply(this,arguments)});return react.createElement(CryptographyContext.Provider,{value:{randomString:randomString,sha256Hash:sha256Hash,sha512Hash:sha512Hash,sha3_512Hash:sha3_512Hash,generateKeyPair:generateKeyPair,deserializePublicKey:deserializePublicKey,deserializePrivateKey:deserializePrivateKey,encrypt:encrypt,decrypt:decrypt,generateSymmetricKey:generateSymmetricKey,deserializeSymmetricKey:deserializeSymmetricKey,encryptWithSymmetricKey:encryptWithSymmetricKey,decryptWithSymmetricKey:decryptWithSymmetricKey,chance:chance}},children)};try{randomString.displayName="randomString",randomString.__docgenInfo={description:"",displayName:"randomString",props:{}},"undefined"!=typeof STORYBOOK_REACT_CLASSES&&(STORYBOOK_REACT_CLASSES["src/stories/components/Cryptography.tsx#randomString"]={docgenInfo:randomString.__docgenInfo,name:"randomString",path:"src/stories/components/Cryptography.tsx#randomString"})}catch(__react_docgen_typescript_loader_error){}try{CryptographyProvider.displayName="CryptographyProvider",CryptographyProvider.__docgenInfo={description:"",displayName:"CryptographyProvider",props:{entropy:{defaultValue:{value:""},description:"",name:"entropy",required:!1,type:{name:"string"}}}},"undefined"!=typeof STORYBOOK_REACT_CLASSES&&(STORYBOOK_REACT_CLASSES["src/stories/components/Cryptography.tsx#CryptographyProvider"]={docgenInfo:CryptographyProvider.__docgenInfo,name:"CryptographyProvider",path:"src/stories/components/Cryptography.tsx#CryptographyProvider"})}catch(__react_docgen_typescript_loader_error){}try{Cryptography.displayName="Cryptography",Cryptography.__docgenInfo={description:"",displayName:"Cryptography",props:{entropy:{defaultValue:{value:""},description:"",name:"entropy",required:!1,type:{name:"string"}}}},"undefined"!=typeof STORYBOOK_REACT_CLASSES&&(STORYBOOK_REACT_CLASSES["src/stories/components/Cryptography.tsx#Cryptography"]={docgenInfo:Cryptography.__docgenInfo,name:"Cryptography",path:"src/stories/components/Cryptography.tsx#Cryptography"})}catch(__react_docgen_typescript_loader_error){}let Cryptography_stories={title:"Components/Cryptography",component:CryptographyProvider,parameters:{layout:"centered"},tags:["autodocs"]};var Basic={args:{children:"positive-intentions",onClick:function(){return alert("positive-intentions")}}};Basic.parameters={...Basic.parameters,docs:{...Basic.parameters?.docs,source:{originalSource:'{\n  args: {\n    children: "positive-intentions",\n    onClick: () => alert("positive-intentions")\n  }\n}',...Basic.parameters?.docs?.source}}};let __namedExportsOrder=["Basic"]}}]);