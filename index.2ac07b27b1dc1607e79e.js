(()=>{"use strict";var e,t,n,r={25:(e,t,n)=>{var r=n(848),o=n(540),i=n(338),a=n(468),l=n(892),u=function(){return u=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var o in t=arguments[n])Object.prototype.hasOwnProperty.call(t,o)&&(e[o]=t[o]);return e},u.apply(this,arguments)},c=function(e,t,n,r){return new(n||(n=Promise))((function(o,i){function a(e){try{u(r.next(e))}catch(e){i(e)}}function l(e){try{u(r.throw(e))}catch(e){i(e)}}function u(e){var t;e.done?o(e.value):(t=e.value,t instanceof n?t:new n((function(e){e(t)}))).then(a,l)}u((r=r.apply(e,t||[])).next())}))},s=function(e,t){var n,r,o,i,a={label:0,sent:function(){if(1&o[0])throw o[1];return o[1]},trys:[],ops:[]};return i={next:l(0),throw:l(1),return:l(2)},"function"==typeof Symbol&&(i[Symbol.iterator]=function(){return this}),i;function l(l){return function(u){return function(l){if(n)throw new TypeError("Generator is already executing.");for(;i&&(i=0,l[0]&&(a=0)),a;)try{if(n=1,r&&(o=2&l[0]?r.return:l[0]?r.throw||((o=r.return)&&o.call(r),0):r.next)&&!(o=o.call(r,l[1])).done)return o;switch(r=0,o&&(l=[2&l[0],o.value]),l[0]){case 0:case 1:o=l;break;case 4:return a.label++,{value:l[1],done:!1};case 5:a.label++,r=l[1],l=[0];continue;case 7:l=a.ops.pop(),a.trys.pop();continue;default:if(!(o=a.trys,(o=o.length>0&&o[o.length-1])||6!==l[0]&&2!==l[0])){a=0;continue}if(3===l[0]&&(!o||l[1]>o[0]&&l[1]<o[3])){a.label=l[1];break}if(6===l[0]&&a.label<o[1]){a.label=o[1],o=l;break}if(o&&a.label<o[2]){a.label=o[2],a.ops.push(l);break}o[2]&&a.ops.pop(),a.trys.pop();continue}l=t.call(e,a)}catch(e){l=[6,e],r=0}finally{n=o=0}if(5&l[0])throw l[1];return{value:l[0]?l[1]:void 0,done:!0}}([l,u])}}},f={wallet:{state:{address:null,balance:"0"},reducers:{setAddress:function(e,t){return u(u({},e),{address:t})},setBalance:function(e,t){return u(u({},e),{balance:t})}},effects:function(e){return{initializeWallet:function(){return c(this,void 0,void 0,(function(){return s(this,(function(e){return[2]}))}))}}}}},h=(0,l.Ts)({models:f}),p=n(976),d=n(767);const v=function(){return(0,r.jsxs)("div",{children:[(0,r.jsx)("h1",{children:"Quantum Purse"}),(0,r.jsx)("p",{children:"Welcome to your quantum-resistant wallet!"})]})};const b=function(){return(0,r.jsxs)("div",{children:[(0,r.jsx)("h1",{children:"Quantum Purse 1 v1.0.0, hello"}),(0,r.jsx)("p",{children:"Welcome to your quantum-resistant wallet!"})]})};var y=function(){return y=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var o in t=arguments[n])Object.prototype.hasOwnProperty.call(t,o)&&(e[o]=t[o]);return e},y.apply(this,arguments)};const j=function(){return(0,r.jsx)("nav",{children:(0,r.jsxs)("ul",{children:[(0,r.jsx)("li",{children:(0,r.jsx)(p.N_,y({to:"/"},{children:"Home"}))}),(0,r.jsx)("li",{children:(0,r.jsx)(p.N_,y({to:"/home1"},{children:"Home 1"}))})]})})};var O=function(){return O=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var o in t=arguments[n])Object.prototype.hasOwnProperty.call(t,o)&&(e[o]=t[o]);return e},O.apply(this,arguments)},m=window.location.hostname.includes("github.io"),x=m?window.location.pathname.split("/")[1]:"",w=m?"/".concat(x):"/";const g=function(){return(0,r.jsxs)(p.Kd,O({basename:w},{children:[(0,r.jsx)(j,{}),(0,r.jsxs)(d.BV,{children:[(0,r.jsx)(d.qh,{path:"/",element:(0,r.jsx)(v,{})}),(0,r.jsx)(d.qh,{path:"/home1",element:(0,r.jsx)(b,{})})]})]}))};var P=function(){return P=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var o in t=arguments[n])Object.prototype.hasOwnProperty.call(t,o)&&(e[o]=t[o]);return e},P.apply(this,arguments)},_=document.getElementById("root");if(!_)throw new Error("Failed to find the root element");(0,i.H)(_).render((0,r.jsx)(o.StrictMode,{children:(0,r.jsx)(a.Kq,P({store:h},{children:(0,r.jsx)(g,{})}))}))}},o={};function i(e){var t=o[e];if(void 0!==t)return t.exports;var n=o[e]={exports:{}};return r[e](n,n.exports,i),n.exports}i.m=r,e=[],i.O=(t,n,r,o)=>{if(!n){var a=1/0;for(s=0;s<e.length;s++){for(var[n,r,o]=e[s],l=!0,u=0;u<n.length;u++)(!1&o||a>=o)&&Object.keys(i.O).every((e=>i.O[e](n[u])))?n.splice(u--,1):(l=!1,o<a&&(a=o));if(l){e.splice(s--,1);var c=r();void 0!==c&&(t=c)}}return t}o=o||0;for(var s=e.length;s>0&&e[s-1][2]>o;s--)e[s]=e[s-1];e[s]=[n,r,o]},n=Object.getPrototypeOf?e=>Object.getPrototypeOf(e):e=>e.__proto__,i.t=function(e,r){if(1&r&&(e=this(e)),8&r)return e;if("object"==typeof e&&e){if(4&r&&e.__esModule)return e;if(16&r&&"function"==typeof e.then)return e}var o=Object.create(null);i.r(o);var a={};t=t||[null,n({}),n([]),n(n)];for(var l=2&r&&e;"object"==typeof l&&!~t.indexOf(l);l=n(l))Object.getOwnPropertyNames(l).forEach((t=>a[t]=()=>e[t]));return a.default=()=>e,i.d(o,a),o},i.d=(e,t)=>{for(var n in t)i.o(t,n)&&!i.o(e,n)&&Object.defineProperty(e,n,{enumerable:!0,get:t[n]})},i.o=(e,t)=>Object.prototype.hasOwnProperty.call(e,t),i.r=e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},(()=>{var e={57:0};i.O.j=t=>0===e[t];var t=(t,n)=>{var r,o,[a,l,u]=n,c=0;if(a.some((t=>0!==e[t]))){for(r in l)i.o(l,r)&&(i.m[r]=l[r]);if(u)var s=u(i)}for(t&&t(n);c<a.length;c++)o=a[c],i.o(e,o)&&e[o]&&e[o][0](),e[o]=0;return i.O(s)},n=self.webpackChunkquantum_purse=self.webpackChunkquantum_purse||[];n.forEach(t.bind(null,0)),n.push=t.bind(null,n.push.bind(n))})();var a=i.O(void 0,[420],(()=>i(25)));a=i.O(a)})();
//# sourceMappingURL=index.2ac07b27b1dc1607e79e.js.map