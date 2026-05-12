var Ct=Object.defineProperty;var It=(e,t,r)=>t in e?Ct(e,t,{enumerable:!0,configurable:!0,writable:!0,value:r}):e[t]=r;var fe=(e,t,r)=>It(e,typeof t!="symbol"?t+"":t,r);import{b as xe,a as N,d as Ot,c as ie,f as M}from"../chunks/D8Wbw_s5.js";import{o as Mt}from"../chunks/DCgorsMW.js";import{d as Se,f as Pe,aK as et,h as C,i as Z,k as ee,a as ge,Y as c,N as Lt,ag as Pt,O as Ue,s as te,j as K,C as tt,aC as Dt,ao as Be,J as ae,aL as Y,I as he,aM as zt,L as Rt,a8 as rt,aN as at,aB as De,aO as Wt,aP as Ht,aF as Ft,U as Ve,aQ as jt,a1 as Ut,D as nt,G as st,aR as Ae,ae as it,aS as Bt,aT as Vt,az as Yt,K as Jt,F as ye,g as ot,t as F,z as lt,aU as Gt,aD as Kt,ax as qt,w as ft,aV as ut,aW as Xt,M as ct,aX as Zt,aY as dt,aZ as vt,m as bt,a_ as Qt,a$ as $t,b0 as er,b1 as tr,b2 as rr,b3 as ar,b4 as nr,b5 as Ee,b6 as sr,b7 as ir,b8 as or,b9 as lr,ba as fr,aH as ur,b as Te,P as cr,c as dr,aG as vr,u as ne,bb as Ye,bc as br,bd as $,a7 as gr,p as j,q as U,v as O,n as k,o as oe,r as m,aJ as R,be as hr,ap as pr,_ as A,aI as z,bf as _r,Z as ve,bg as mr,bh as wr}from"../chunks/iFoU3qJD.js";import{i as xr,a as Sr,d as V,b as pe,c as yr,n as Tr,e as kr,s as B}from"../chunks/D9r3YBct.js";import{B as gt,l as ke,p as G,s as ht,i as _e,b as pt}from"../chunks/DmgCvR-O.js";import{s as ze}from"../chunks/BxHz8PXP.js";function se(e,t){return t}function Er(e,t,r){for(var a=[],n=t.length,i,o=t.length,s=0;s<n;s++){let b=t[s];st(b,()=>{if(i){if(i.pending.delete(b),i.done.add(b),i.pending.size===0){var d=e.outrogroups;Me(e,De(i.done)),d.delete(i),d.size===0&&(e.outrogroups=null)}}else o-=1},!1)}if(o===0){var l=a.length===0&&r!==null;if(l){var u=r,f=u.parentNode;Yt(f),f.append(u),e.items.clear()}Me(e,t,!l)}else i={pending:new Set(t),done:new Set},(e.outrogroups??(e.outrogroups=new Set)).add(i)}function Me(e,t,r=!0){var a;if(e.pending.size>0){a=new Set;for(const o of e.pending.values())for(const s of o)a.add(e.items.get(s).e)}for(var n=0;n<t.length;n++){var i=t[n];if(a!=null&&a.has(i)){i.f|=Y;const o=document.createDocumentFragment();Jt(i,o)}else ye(t[n],r)}}var Je;function Q(e,t,r,a,n,i=null){var o=e,s=new Map,l=(t&et)!==0;if(l){var u=e;o=C?Z(ee(u)):u.appendChild(Se())}C&&ge();var f=null,b=rt(()=>{var E=r();return at(E)?E:E==null?[]:De(E)}),d,w=new Map,h=!0;function T(E){(I.effect.f&Ut)===0&&(I.pending.delete(E),I.fallback=f,Ar(I,d,o,t,a),f!==null&&(d.length===0?(f.f&Y)===0?nt(f):(f.f^=Y,be(f,null,o)):st(f,()=>{f=null})))}function v(E){I.pending.delete(E)}var p=Pe(()=>{d=c(b);var E=d.length;let S=!1;if(C){var D=Lt(o)===Pt;D!==(E===0)&&(o=Ue(),Z(o),te(!1),S=!0)}for(var x=new Set,y=ae,L=Rt(),g=0;g<E;g+=1){C&&K.nodeType===tt&&K.data===Dt&&(o=K,S=!0,te(!1));var _=d[g],W=a(_,g),H=h?null:s.get(W);H?(H.v&&Be(H.v,_),H.i&&Be(H.i,g),L&&y.unskip_effect(H.e)):(H=Nr(s,h?o:Je??(Je=Se()),_,W,g,n,t,r),h||(H.e.f|=Y),s.set(W,H)),x.add(W)}if(E===0&&i&&!f&&(h?f=he(()=>i(o)):(f=he(()=>i(Je??(Je=Se()))),f.f|=Y)),E>x.size&&zt(),C&&E>0&&Z(Ue()),!h)if(w.set(y,x),L){for(const[me,we]of s)x.has(me)||y.skip_effect(we.e);y.oncommit(T),y.ondiscard(v)}else T(y);S&&te(!0),c(b)}),I={effect:p,items:s,pending:w,outrogroups:null,fallback:f};h=!1,C&&(o=K)}function ue(e){for(;e!==null&&(e.f&Bt)===0;)e=e.next;return e}function Ar(e,t,r,a,n){var _,W,H,me,we,Re,We,He,Fe;var i=(a&Vt)!==0,o=t.length,s=e.items,l=ue(e.effect.first),u,f=null,b,d=[],w=[],h,T,v,p;if(i)for(p=0;p<o;p+=1)h=t[p],T=n(h,p),v=s.get(T).e,(v.f&Y)===0&&((W=(_=v.nodes)==null?void 0:_.a)==null||W.measure(),(b??(b=new Set)).add(v));for(p=0;p<o;p+=1){if(h=t[p],T=n(h,p),v=s.get(T).e,e.outrogroups!==null)for(const J of e.outrogroups)J.pending.delete(v),J.done.delete(v);if((v.f&Ae)!==0&&(nt(v),i&&((me=(H=v.nodes)==null?void 0:H.a)==null||me.unfix(),(b??(b=new Set)).delete(v))),(v.f&Y)!==0)if(v.f^=Y,v===l)be(v,null,r);else{var I=f?f.next:l;v===e.effect.last&&(e.effect.last=v.prev),v.prev&&(v.prev.next=v.next),v.next&&(v.next.prev=v.prev),X(e,f,v),X(e,v,I),be(v,I,r),f=v,d=[],w=[],l=ue(f.next);continue}if(v!==l){if(u!==void 0&&u.has(v)){if(d.length<w.length){var E=w[0],S;f=E.prev;var D=d[0],x=d[d.length-1];for(S=0;S<d.length;S+=1)be(d[S],E,r);for(S=0;S<w.length;S+=1)u.delete(w[S]);X(e,D.prev,x.next),X(e,f,D),X(e,x,E),l=E,f=x,p-=1,d=[],w=[]}else u.delete(v),be(v,l,r),X(e,v.prev,v.next),X(e,v,f===null?e.effect.first:f.next),X(e,f,v),f=v;continue}for(d=[],w=[];l!==null&&l!==v;)(u??(u=new Set)).add(l),w.push(l),l=ue(l.next);if(l===null)continue}(v.f&Y)===0&&d.push(v),f=v,l=ue(v.next)}if(e.outrogroups!==null){for(const J of e.outrogroups)J.pending.size===0&&(Me(e,De(J.done)),(we=e.outrogroups)==null||we.delete(J));e.outrogroups.size===0&&(e.outrogroups=null)}if(l!==null||u!==void 0){var y=[];if(u!==void 0)for(v of u)(v.f&Ae)===0&&y.push(v);for(;l!==null;)(l.f&Ae)===0&&l!==e.fallback&&y.push(l),l=ue(l.next);var L=y.length;if(L>0){var g=(a&et)!==0&&o===0?r:null;if(i){for(p=0;p<L;p+=1)(We=(Re=y[p].nodes)==null?void 0:Re.a)==null||We.measure();for(p=0;p<L;p+=1)(Fe=(He=y[p].nodes)==null?void 0:He.a)==null||Fe.fix()}Er(e,y,g)}}i&&it(()=>{var J,je;if(b!==void 0)for(v of b)(je=(J=v.nodes)==null?void 0:J.a)==null||je.apply()})}function Nr(e,t,r,a,n,i,o,s){var l=(o&Wt)!==0?(o&Ht)===0?Ft(r,!1,!1):Ve(r):null,u=(o&jt)!==0?Ve(n):null;return{v:l,i:u,e:he(()=>(i(t,l??r,u??n,s),()=>{e.delete(a)}))}}function be(e,t,r){if(e.nodes)for(var a=e.nodes.start,n=e.nodes.end,i=t&&(t.f&Y)===0?t.nodes.start:r;a!==null;){var o=ot(a);if(i.before(a),a===n)return;a=o}}function X(e,t,r){t===null?e.effect.first=r:t.next=r,r===null?e.effect.last=t:r.prev=t}function _t(e,t,r=!1,a=!1,n=!1,i=!1){var o=e,s="";if(r){var l=e;C&&(o=Z(ee(l)))}F(()=>{var u=lt;if(s===(s=t()??"")){C&&ge();return}if(r&&!C){u.nodes=null,l.innerHTML=s,s!==""&&xe(ee(l),l.lastChild);return}if(u.nodes!==null&&(Gt(u.nodes.start,u.nodes.end),u.nodes=null),s!==""){if(C){K.data;for(var f=ge(),b=f;f!==null&&(f.nodeType!==tt||f.data!=="");)b=f,f=ot(f);if(f===null)throw Kt(),qt;xe(K,b),o=Z(f);return}var d=a?ut:n?Xt:void 0,w=ft(a?"svg":n?"math":"template",d);w.innerHTML=s;var h=a||n?w:w.content;if(xe(ee(h),h.lastChild),a||n)for(;ee(h);)o.before(ee(h));else o.before(h)}})}function Cr(e,t,...r){var a=new gt(e);Pe(()=>{const n=t()??null;a.ensure(n,n&&(i=>n(i,...r)))},ct)}function Ir(e,t,r,a,n,i){let o=C;C&&ge();var s=null;C&&K.nodeType===Zt&&(s=K,ge());var l=C?K:e,u=new gt(l,!1);Pe(()=>{const f=t()||null;var b=ut;if(f===null){u.ensure(null,null);return}return u.ensure(f,d=>{if(f){if(s=C?s:ft(f,b),xe(s,s),a){C&&xr(f)&&s.append(document.createComment(""));var w=C?ee(s):s.appendChild(Se());C&&(w===null?te(!1):Z(w)),a(s,w)}lt.nodes.end=s,d.before(s)}C&&Z(d)}),()=>{}},ct),dt(()=>{}),o&&(te(!0),Z(l))}function Or(e,t){var r=void 0,a;vt(()=>{r!==(r=t())&&(a&&(ye(a),a=null),r&&(a=he(()=>{bt(()=>r(e))})))})}function mt(e){var t,r,a="";if(typeof e=="string"||typeof e=="number")a+=e;else if(typeof e=="object")if(Array.isArray(e)){var n=e.length;for(t=0;t<n;t++)e[t]&&(r=mt(e[t]))&&(a&&(a+=" "),a+=r)}else for(r in e)e[r]&&(a&&(a+=" "),a+=r);return a}function Mr(){for(var e,t,r=0,a="",n=arguments.length;r<n;r++)(e=arguments[r])&&(t=mt(e))&&(a&&(a+=" "),a+=t);return a}function Lr(e){return typeof e=="object"?Mr(e):e??""}const Ge=[...` 	
\r\f \v\uFEFF`];function Pr(e,t,r){var a=e==null?"":""+e;if(r){for(var n of Object.keys(r))if(r[n])a=a?a+" "+n:n;else if(a.length)for(var i=n.length,o=0;(o=a.indexOf(n,o))>=0;){var s=o+i;(o===0||Ge.includes(a[o-1]))&&(s===a.length||Ge.includes(a[s]))?a=(o===0?"":a.substring(0,o))+a.substring(s+1):o=s}}return a===""?null:a}function Ke(e,t=!1){var r=t?" !important;":";",a="";for(var n of Object.keys(e)){var i=e[n];i!=null&&i!==""&&(a+=" "+n+": "+i+r)}return a}function Ne(e){return e[0]!=="-"||e[1]!=="-"?e.toLowerCase():e}function Dr(e,t){if(t){var r="",a,n;if(Array.isArray(t)?(a=t[0],n=t[1]):a=t,e){e=String(e).replaceAll(/\s*\/\*.*?\*\/\s*/g,"").trim();var i=!1,o=0,s=!1,l=[];a&&l.push(...Object.keys(a).map(Ne)),n&&l.push(...Object.keys(n).map(Ne));var u=0,f=-1;const T=e.length;for(var b=0;b<T;b++){var d=e[b];if(s?d==="/"&&e[b-1]==="*"&&(s=!1):i?i===d&&(i=!1):d==="/"&&e[b+1]==="*"?s=!0:d==='"'||d==="'"?i=d:d==="("?o++:d===")"&&o--,!s&&i===!1&&o===0){if(d===":"&&f===-1)f=b;else if(d===";"||b===T-1){if(f!==-1){var w=Ne(e.substring(u,f).trim());if(!l.includes(w)){d!==";"&&b++;var h=e.substring(u,b).trim();r+=" "+h+";"}}u=b+1,f=-1}}}}return a&&(r+=Ke(a)),n&&(r+=Ke(n,!0)),r=r.trim(),r===""?null:r}return e==null?null:String(e)}function q(e,t,r,a,n,i){var o=e.__className;if(C||o!==r||o===void 0){var s=Pr(r,a,i);(!C||s!==e.getAttribute("class"))&&(s==null?e.removeAttribute("class"):t?e.className=s:e.setAttribute("class",s)),e.__className=r}else if(i&&n!==i)for(var l in i){var u=!!i[l];(n==null||u!==!!n[l])&&e.classList.toggle(l,u)}return i}function Ce(e,t={},r,a){for(var n in r){var i=r[n];t[n]!==i&&(r[n]==null?e.style.removeProperty(n):e.style.setProperty(n,i,a))}}function zr(e,t,r,a){var n=e.__style;if(C||n!==t){var i=Dr(t,a);(!C||i!==e.getAttribute("style"))&&(i==null?e.removeAttribute("style"):e.style.cssText=i),e.__style=t}else a&&(Array.isArray(a)?(Ce(e,r==null?void 0:r[0],a[0]),Ce(e,r==null?void 0:r[1],a[1],"important")):Ce(e,r,a));return a}function Le(e,t,r=!1){if(e.multiple){if(t==null)return;if(!at(t))return Qt();for(var a of e.options)a.selected=t.includes(qe(a));return}for(a of e.options){var n=qe(a);if($t(n,t)){a.selected=!0;return}}(!r||t!==void 0)&&(e.selectedIndex=-1)}function Rr(e){var t=new MutationObserver(()=>{Le(e,e.__value)});t.observe(e,{childList:!0,subtree:!0,attributes:!0,attributeFilter:["value"]}),dt(()=>{t.disconnect()})}function qe(e){return"__value"in e?e.__value:e.value}const ce=Symbol("class"),de=Symbol("style"),wt=Symbol("is custom element"),xt=Symbol("is html"),Wr=Ee?"link":"LINK",Hr=Ee?"input":"INPUT",Fr=Ee?"option":"OPTION",jr=Ee?"select":"SELECT";function St(e){if(C){var t=!1,r=()=>{if(!t){if(t=!0,e.hasAttribute("value")){var a=e.value;re(e,"value",null),e.value=a}if(e.hasAttribute("checked")){var n=e.checked;re(e,"checked",null),e.checked=n}}};e.__on_r=r,it(r),or()}}function Ur(e,t){t?e.hasAttribute("selected")||e.setAttribute("selected",""):e.removeAttribute("selected")}function re(e,t,r,a){var n=yt(e);C&&(n[t]=e.getAttribute(t),t==="src"||t==="srcset"||t==="href"&&e.nodeName===Wr)||n[t]!==(n[t]=r)&&(t==="loading"&&(e[lr]=r),r==null?e.removeAttribute(t):typeof r!="string"&&Tt(e).includes(t)?e[t]=r:e.setAttribute(t,r))}function Br(e,t,r,a,n=!1,i=!1){if(C&&n&&e.nodeName===Hr){var o=e,s=o.type==="checkbox"?"defaultChecked":"defaultValue";s in r||St(o)}var l=yt(e),u=l[wt],f=!l[xt];let b=C&&u;b&&te(!1);var d=t||{},w=e.nodeName===Fr;for(var h in t)h in r||(r[h]=null);r.class?r.class=Lr(r.class):r[ce]&&(r.class=null),r[de]&&(r.style??(r.style=null));var T=Tt(e);for(const x in r){let y=r[x];if(w&&x==="value"&&y==null){e.value=e.__value="",d[x]=y;continue}if(x==="class"){var v=e.namespaceURI==="http://www.w3.org/1999/xhtml";q(e,v,y,a,t==null?void 0:t[ce],r[ce]),d[x]=y,d[ce]=r[ce];continue}if(x==="style"){zr(e,y,t==null?void 0:t[de],r[de]),d[x]=y,d[de]=r[de];continue}var p=d[x];if(!(y===p&&!(y===void 0&&e.hasAttribute(x)))){d[x]=y;var I=x[0]+x[1];if(I!=="$$")if(I==="on"){const L={},g="$$"+x;let _=x.slice(2);var E=kr(_);if(Sr(_)&&(_=_.slice(0,-7),L.capture=!0),!E&&p){if(y!=null)continue;e.removeEventListener(_,d[g],L),d[g]=null}if(E)V(_,e,y),pe([_]);else if(y!=null){let W=function(H){d[x].call(this,H)};d[g]=yr(_,e,W,L)}}else if(x==="style")re(e,x,y);else if(x==="autofocus")sr(e,!!y);else if(!u&&(x==="__value"||x==="value"&&y!=null))e.value=e.__value=y;else if(x==="selected"&&w)Ur(e,y);else{var S=x;f||(S=Tr(S));var D=S==="defaultValue"||S==="defaultChecked";if(y==null&&!u&&!D)if(l[x]=null,S==="value"||S==="checked"){let L=e;const g=t===void 0;if(S==="value"){let _=L.defaultValue;L.removeAttribute(S),L.defaultValue=_,L.value=L.__value=g?_:null}else{let _=L.defaultChecked;L.removeAttribute(S),L.defaultChecked=_,L.checked=g?_:!1}}else e.removeAttribute(x);else D||T.includes(S)&&(u||typeof y!="string")?(e[S]=y,S in l&&(l[S]=ir)):typeof y!="function"&&re(e,S,y)}}}return b&&te(!0),d}function Xe(e,t,r=[],a=[],n=[],i,o=!1,s=!1){er(n,r,a,l=>{var u=void 0,f={},b=e.nodeName===jr,d=!1;if(vt(()=>{var h=t(...l.map(c)),T=Br(e,u,h,i,o,s);d&&b&&"value"in h&&Le(e,h.value);for(let p of Object.getOwnPropertySymbols(f))h[p]||ye(f[p]);for(let p of Object.getOwnPropertySymbols(h)){var v=h[p];p.description===ar&&(!u||v!==u[p])&&(f[p]&&ye(f[p]),f[p]=he(()=>Or(e,()=>v))),T[p]=v}u=T}),b){var w=e;bt(()=>{Le(w,u.value,!0),Rr(w)})}d=!0})}function yt(e){return e.__attributes??(e.__attributes={[wt]:e.nodeName.includes("-"),[xt]:e.namespaceURI===tr})}var Ze=new Map;function Tt(e){var t=e.getAttribute("is")||e.nodeName,r=Ze.get(t);if(r)return r;Ze.set(t,r=[]);for(var a,n=e,i=Element.prototype;i!==n;){a=nr(n);for(var o in a)a[o].set&&r.push(o);n=rr(n)}return r}function kt(e,t,r=t){var a=new WeakSet;fr(e,"input",async n=>{var i=n?e.defaultValue:e.value;if(i=Ie(e)?Oe(i):i,r(i),ae!==null&&a.add(ae),await ur(),i!==(i=t())){var o=e.selectionStart,s=e.selectionEnd,l=e.value.length;if(e.value=i??"",s!==null){var u=e.value.length;o===s&&s===l&&u>l?(e.selectionStart=u,e.selectionEnd=u):(e.selectionStart=o,e.selectionEnd=Math.min(s,u))}}}),(C&&e.defaultValue!==e.value||Te(t)==null&&e.value)&&(r(Ie(e)?Oe(e.value):e.value),ae!==null&&a.add(ae)),cr(()=>{var n=t();if(e===document.activeElement){var i=ae;if(a.has(i))return}Ie(e)&&n===Oe(e.value)||e.type==="date"&&!n&&!e.value||n!==e.value&&(e.value=n??"")})}function Ie(e){var t=e.type;return t==="number"||t==="range"}function Oe(e){return e===""?null:+e}function Vr(e=!1){const t=dr,r=t.l.u;if(!r)return;let a=()=>$(t.s);if(e){let n=0,i={};const o=gr(()=>{let s=!1;const l=t.s;for(const u in l)l[u]!==i[u]&&(i[u]=l[u],s=!0);return s&&n++,n});a=()=>c(o)}r.b.length&&vr(()=>{Qe(t,a),Ye(r.b)}),ne(()=>{const n=Te(()=>r.m.map(br));return()=>{for(const i of n)typeof i=="function"&&i()}}),r.a.length&&ne(()=>{Qe(t,a),Ye(r.a)})}function Qe(e,t){if(e.l.s)for(const r of e.l.s)c(r);t()}const Yr=!0,$a=Object.freeze(Object.defineProperty({__proto__:null,prerender:Yr},Symbol.toStringTag,{value:"Module"})),Et="";async function le(e,t){const r=await fetch(`${Et}${e}`,t);if(!r.ok){const a=await r.text().catch(()=>"Unknown error");throw new Error(`HTTP ${r.status}: ${a}`)}return r.json()}async function Jr(){return(await le("/api/sessions")).sessions}async function Gr(e){return(await le("/api/sessions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(e)})).session}async function Kr(e){return(await le(`/api/sessions/${e}`)).session}async function qr(e,t){await le(`/api/sessions/${e}/messages`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)})}async function Xr(e){return(await le(`/api/agents/tree/${e}`)).tree}async function Zr(e){return(await le(`/api/files/${e}`)).files}function Qr(e,t){return`${Et}/api/files/${e}/${t}`}function $r(){const e=typeof window<"u"&&window.location.protocol==="https:"?"wss:":"ws:",t=typeof window<"u"?window.location.host:"localhost:8080";return`${e}//${t}/ws`}class ea{constructor(){fe(this,"ws",null);fe(this,"reconnectTimer",null);fe(this,"onMessage",null);fe(this,"pendingSubscribe",null)}connect(t){this.onMessage=t,this.tryConnect()}tryConnect(){var r;if(((r=this.ws)==null?void 0:r.readyState)===WebSocket.OPEN)return;const t=$r();this.ws=new WebSocket(t),this.ws.onopen=()=>{console.log("[WS] connected"),this.pendingSubscribe&&this.subscribe(this.pendingSubscribe)},this.ws.onmessage=a=>{var n;try{const i=JSON.parse(a.data);(n=this.onMessage)==null||n.call(this,i)}catch(i){console.error("[WS] parse error",i)}},this.ws.onclose=()=>{console.log("[WS] disconnected, reconnecting in 3s..."),this.reconnectTimer=setTimeout(()=>this.tryConnect(),3e3)},this.ws.onerror=a=>{console.error("[WS] error",a)}}subscribe(t){var r;if(this.pendingSubscribe=t,((r=this.ws)==null?void 0:r.readyState)===WebSocket.OPEN){const a={type:"subscribe",session_id:t};this.ws.send(JSON.stringify(a))}}disconnect(){var t;this.reconnectTimer&&(clearTimeout(this.reconnectTimer),this.reconnectTimer=null),(t=this.ws)==null||t.close(),this.ws=null}}/**
 * @license lucide-svelte v0.575.0 - ISC
 *
 * ISC License
 * 
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2026.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ---
 * 
 * The MIT License (MIT) (for portions derived from Feather)
 * 
 * Copyright (c) 2013-2026 Cole Bemis
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */const ta={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"};/**
 * @license lucide-svelte v0.575.0 - ISC
 *
 * ISC License
 * 
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2026.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ---
 * 
 * The MIT License (MIT) (for portions derived from Feather)
 * 
 * Copyright (c) 2013-2026 Cole Bemis
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */const ra=e=>{for(const t in e)if(t.startsWith("aria-")||t==="role"||t==="title")return!0;return!1};/**
 * @license lucide-svelte v0.575.0 - ISC
 *
 * ISC License
 * 
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2026.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ---
 * 
 * The MIT License (MIT) (for portions derived from Feather)
 * 
 * Copyright (c) 2013-2026 Cole Bemis
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */const $e=(...e)=>e.filter((t,r,a)=>!!t&&t.trim()!==""&&a.indexOf(t)===r).join(" ").trim();var aa=Ot("<svg><!><!></svg>");function At(e,t){const r=ke(t,["children","$$slots","$$events","$$legacy"]),a=ke(r,["name","color","size","strokeWidth","absoluteStrokeWidth","iconNode"]);j(t,!1);let n=G(t,"name",8,void 0),i=G(t,"color",8,"currentColor"),o=G(t,"size",8,24),s=G(t,"strokeWidth",8,2),l=G(t,"absoluteStrokeWidth",8,!1),u=G(t,"iconNode",24,()=>[]);Vr();var f=aa();Xe(f,(w,h,T)=>({...ta,...w,...a,width:o(),height:o(),stroke:i(),"stroke-width":h,class:T}),[()=>ra(a)?void 0:{"aria-hidden":"true"},()=>($(l()),$(s()),$(o()),Te(()=>l()?Number(s())*24/Number(o()):s())),()=>($($e),$(n()),$(r),Te(()=>$e("lucide-icon","lucide",n()?`lucide-${n()}`:"",r.class)))]);var b=k(f);Q(b,1,u,se,(w,h)=>{var T=R(()=>hr(c(h),2));let v=()=>c(T)[0],p=()=>c(T)[1];var I=ie(),E=oe(I);Ir(E,v,!0,(S,D)=>{Xe(S,()=>({...p()}))}),N(w,I)});var d=O(b);ze(d,t,"default",{}),m(f),N(e,f),U()}function na(e,t){const r=ke(t,["children","$$slots","$$events","$$legacy"]);/**
 * @license lucide-svelte v0.575.0 - ISC
 *
 * ISC License
 *
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2026.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * ---
 *
 * The MIT License (MIT) (for portions derived from Feather)
 *
 * Copyright (c) 2013-2026 Cole Bemis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */const a=[["path",{d:"M5 12h14"}],["path",{d:"M12 5v14"}]];At(e,ht({name:"plus"},()=>r,{get iconNode(){return a},children:(n,i)=>{var o=ie(),s=oe(o);ze(s,t,"default",{}),N(n,o)},$$slots:{default:!0}}))}function sa(e,t){const r=ke(t,["children","$$slots","$$events","$$legacy"]);/**
 * @license lucide-svelte v0.575.0 - ISC
 *
 * ISC License
 *
 * Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2026.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * ---
 *
 * The MIT License (MIT) (for portions derived from Feather)
 *
 * Copyright (c) 2013-2026 Cole Bemis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */const a=[["path",{d:"M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z"}],["path",{d:"m21.854 2.147-10.94 10.939"}]];At(e,ht({name:"send"},()=>r,{get iconNode(){return a},children:(n,i)=>{var o=ie(),s=oe(o);ze(s,t,"default",{}),N(n,o)},$$slots:{default:!0}}))}var ia=M("<span></span>");function oa(e,t){const r={idle:"bg-[#7a8194]",running:"bg-[#fbbf24] animate-pulse",completed:"bg-[#4ade80]",error:"bg-[#f87171]"};var a=ia();F(()=>{q(a,1,`inline-block h-[7px] w-[7px] rounded-full ${r[t.status]??r.idle??""}`),re(a,"title",t.status)}),N(e,a)}function P(e){if(e==null)return"";if(typeof document>"u")return String(e);const t=document.createElement("div");return t.textContent=String(e),t.innerHTML}function la(e){return new Date(e).toLocaleTimeString()}var fa=M('<button><!> <span class="truncate"> </span></button>');function ua(e,t){j(t,!0);var r=fa(),a=k(r);oa(a,{get status(){return t.session.status}});var n=O(a,2),i=k(n,!0);m(n),m(r),F(o=>{q(r,1,`flex w-full cursor-pointer items-center gap-2 rounded-md px-3 py-2.5 text-left text-sm transition-colors ${t.isActive?"border-l-[3px] border-[#3bd0ee] bg-[#1e212b] text-[#3bd0ee]":"text-[#7a8194] hover:bg-[#1e212b] hover:text-[#c9cdd6]"}`),B(i,o)},[()=>P(t.session.title)]),V("click",r,function(...o){var s;(s=t.onClick)==null||s.apply(this,o)}),N(e,r),U()}pe(["click"]);var ca=M('<ul class="flex flex-col gap-1 overflow-y-auto p-2"></ul>');function da(e,t){j(t,!0);var r=ca();Q(r,21,()=>t.sessions,a=>a.id,(a,n)=>{{let i=R(()=>c(n).id===t.activeId);ua(a,{get session(){return c(n)},get isActive(){return c(i)},onClick:()=>t.onSelect(c(n).id)})}}),m(r),N(e,r),U()}var va=M('<div class="fixed inset-0 z-50 flex items-center justify-center"><div class="absolute inset-0 bg-black/60" role="presentation"></div> <div class="relative z-10 w-[360px] rounded-xl border border-[#2a2e3b] bg-[#161922] p-6"><h2 class="mb-4 text-base font-semibold">New Session</h2> <input class="mb-4 w-full rounded-md border border-[#2a2e3b] bg-[#1e212b] px-3 py-2 text-sm text-[#c9cdd6] outline-none focus:border-[#4f8cf7]"/> <div class="flex justify-end gap-2"><button class="rounded-md bg-[#1e212b] px-3.5 py-2 text-sm text-[#c9cdd6]">Cancel</button> <button class="rounded-md bg-[#4f8cf7] px-3.5 py-2 text-sm font-semibold text-white disabled:opacity-50">Create</button></div></div></div>'),ba=M('<aside class="flex w-[260px] flex-col border-r border-[#2a2e3b] bg-[#161922]"><div class="border-b border-[#2a2e3b] p-4"><h1 class="mb-3 text-lg font-bold tracking-wide text-[#4f8cf7]">brws</h1> <button class="flex w-full items-center justify-center gap-1.5 rounded-md bg-[#4f8cf7] px-3 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90"><!> New Session</button></div> <!> <!></aside>');function ga(e,t){j(t,!0);let r=z(!1),a=z("New Session"),n=z(!1);async function i(){A(n,!0);try{await t.onCreate(c(a).trim()||"New Session"),A(r,!1),A(a,"New Session")}finally{A(n,!1)}}function o(h){h.key==="Enter"&&i()}var s=ba(),l=k(s),u=O(k(l),2),f=k(u);na(f,{size:14}),pr(),m(u),m(l);var b=O(l,2);da(b,{get sessions(){return t.sessions},get activeId(){return t.activeId},get onSelect(){return t.onSelect}});var d=O(b,2);{var w=h=>{var T=va(),v=k(T),p=O(v,2),I=O(k(p),2);St(I);var E=O(I,2),S=k(E),D=O(S,2);m(E),m(p),m(T),F(()=>D.disabled=c(n)),V("click",v,()=>A(r,!1)),V("keydown",I,o),kt(I,()=>c(a),x=>A(a,x)),V("click",S,()=>A(r,!1)),V("click",D,i),N(h,T)};_e(d,h=>{c(r)&&h(w)})}m(s),V("click",u,()=>A(r,!0)),N(e,s),U()}pe(["click","keydown"]);var ha=M('<div><div class="mb-1 text-[11px] text-[#7a8194]"> </div> <div class="whitespace-pre-wrap break-words"></div></div>');function pa(e,t){j(t,!0);let r=R(()=>t.msg.role==="user"),a=R(()=>t.msg.role==="system"),n=R(()=>c(a)?"System":t.msg.agent_id?`Assistant (${t.msg.agent_id.slice(0,8)})`:"Assistant");var i=ha(),o=k(i),s=k(o,!0);m(o);var l=O(o,2);_t(l,()=>P(t.msg.content),!0),m(l),m(i),F(()=>{q(i,1,`max-w-[85%] rounded-xl px-4 py-3 leading-relaxed ${c(r)?"self-end rounded-br-sm bg-[#1e3a5f]":"self-start rounded-bl-sm bg-[#1e2736]"}`),B(s,c(n))}),N(e,i),U()}var _a=M('<div class="flex flex-1 flex-col gap-3 overflow-y-auto p-5"><!> <div></div></div>');function ma(e,t){j(t,!0);let r=z(null);ne(()=>{var o;t.messages,(o=c(r))==null||o.scrollIntoView({behavior:"smooth"})});var a=_a(),n=k(a);Q(n,17,()=>t.messages,o=>o.id,(o,s)=>{pa(o,{get msg(){return c(s)}})});var i=O(n,2);pt(i,o=>A(r,o),()=>c(r)),m(a),N(e,a),U()}var wa=M('<div class="flex gap-2 border-t border-[#2a2e3b] bg-[#161922] p-3"><textarea placeholder="Ask the research agent..." class="max-h-32 min-h-[44px] flex-1 resize-none rounded-lg border border-[#2a2e3b] bg-[#1e212b] px-3 py-2.5 text-sm text-[#c9cdd6] outline-none transition-colors focus:border-[#4f8cf7] disabled:opacity-50"></textarea> <button class="flex items-center gap-1.5 rounded-lg bg-[#4f8cf7] px-4 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:bg-[#7a8194]"><!></button></div>');function xa(e,t){j(t,!0);let r=G(t,"disabled",3,!1),a=z("");function n(){const f=c(a).trim();f&&(t.onSend(f),A(a,""))}function i(f){f.key==="Enter"&&!f.shiftKey&&(f.preventDefault(),n())}var o=wa(),s=k(o);_r(s),re(s,"rows",1);var l=O(s,2),u=k(l);sa(u,{size:14}),m(l),m(o),F(f=>{s.disabled=r(),l.disabled=f},[()=>r()||!c(a).trim()]),V("keydown",s,i),kt(s,()=>c(a),f=>A(a,f)),V("click",l,n),N(e,o),U()}pe(["keydown","click"]);var Sa=M('<div class="flex min-h-0 flex-1 flex-col"><!> <!></div>');function ya(e,t){let r=G(t,"disabled",3,!1);var a=Sa(),n=k(a);ma(n,{get messages(){return t.messages}});var i=O(n,2);xa(i,{get onSend(){return t.onSend},get disabled(){return r()}}),m(a),N(e,a)}var Ta=M("<button> </button>"),ka=M('<div class="flex h-full flex-col"><div class="flex gap-0.5 border-b border-[#2a2e3b] px-3 pt-2"></div> <div class="flex-1 overflow-y-auto p-3"><!></div></div>');function Ea(e,t){j(t,!0);let r=G(t,"activeTab",31,()=>{var l;return ve(((l=t.tabs[0])==null?void 0:l.id)??"")});function a(l){var u;r(l),(u=t.onTabChange)==null||u.call(t,l)}var n=ka(),i=k(n);Q(i,21,()=>t.tabs,se,(l,u)=>{var f=Ta(),b=k(f,!0);m(f),F(()=>{q(f,1,`border-b-2 px-3.5 py-2 text-[13px] transition-colors ${r()===c(u).id?"border-[#3bd0ee] text-[#3bd0ee]":"border-transparent text-[#7a8194] hover:text-[#c9cdd6]"}`),B(b,c(u).label)}),V("click",f,()=>a(c(u).id)),N(l,f)}),m(i);var o=O(i,2),s=k(o);Cr(s,()=>t.children),m(o),m(n),N(e,n),U()}pe(["click"]);var Aa=M("<span> </span>");function Na(e,t){const r={root:"bg-[#4f8cf7] text-white",research:"bg-[#7c3aed] text-white",browser:"bg-[#0ea5e9] text-white",analysis:"bg-[#10b981] text-white"};let a=R(()=>r[t.type]??"bg-[#64748b] text-white");var n=Aa(),i=k(n,!0);m(n),F(()=>{q(n,1,`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${c(a)??""}`),B(i,t.type)}),N(e,n)}const Nt=(e,t=mr,r)=>{let a=rt(()=>wr(r==null?void 0:r(),!1));var n=Ia(),i=k(n),o=k(i);Na(o,{get type(){return t().type}});var s=O(o,2),l=k(s,!0);m(s);var u=O(s,2),f=k(u,!0);m(u),m(i);var b=O(i,2),d=k(b,!0);m(b);var w=O(b,2);{var h=T=>{var v=Ca();Q(v,21,()=>t().children,se,(p,I)=>{Nt(p,()=>c(I))}),m(v),N(T,v)};_e(w,T=>{t().children.length>0&&T(h)})}m(n),F((T,v)=>{q(n,1,`${c(a)?"":"ml-4 border-l-2 border-[#2a2e3b] pl-2.5"} mb-2`),B(l,T),q(u,1,`ml-auto text-[11px] ${t().status==="running"?"text-[#fbbf24]":t().status==="completed"?"text-[#4ade80]":t().status==="error"?"text-[#f87171]":"text-[#7a8194]"}`),B(f,t().status),B(d,v)},[()=>t().id.slice(0,8),()=>P(t().goal)]),N(e,n)};var Ca=M('<div class="mt-1"></div>'),Ia=M('<div><div class="flex items-center gap-2 rounded-md bg-[#1e212b] px-2.5 py-1.5"><!> <span class="text-[11px] text-[#7a8194]"> </span> <span> </span></div> <div class="px-2.5 py-0.5 text-[12px] text-[#7a8194]"> </div> <!></div>'),Oa=M('<div class="p-3 text-sm text-[#7a8194]">No agents running yet.</div>');function Ma(e,t){j(t,!0);var r=ie(),a=oe(r);{var n=o=>{var s=Oa();N(o,s)},i=o=>{Nt(o,()=>t.tree,()=>!0)};_e(a,o=>{var s;(s=t.tree)!=null&&s.id?o(i,-1):o(n)})}N(e,r),U()}var La=M("<span> </span>");function Pa(e,t){j(t,!0);const r={thought:"bg-[#4f46e5] text-white",tool_call:"bg-[#fbbf24] text-black",tool_result:"bg-[#4ade80] text-black",agent_spawned:"bg-[#4f8cf7] text-white",agent_completed:"bg-[#64748b] text-white",stream:"bg-[#3bd0ee] text-black",error:"bg-[#f87171] text-white",message:"bg-[#8b5cf6] text-white",file_created:"bg-[#10b981] text-white"};let a=R(()=>t.type.replace(/_/g," ")),n=R(()=>r[t.type]??"bg-[#64748b] text-white");var i=La(),o=k(i,!0);m(i),F(()=>{q(i,1,`min-w-[70px] rounded px-1 py-0.5 text-center text-[10px] font-bold uppercase ${c(n)??""}`),B(o,c(a))}),N(e,i),U()}var Da=M('<div class="flex gap-2.5 rounded px-2 py-1.5 text-[12px] hover:bg-[#1e212b]"><span class="min-w-[60px] text-[#7a8194]"> </span> <!> <span class="min-w-[90px] text-[#3bd0ee]"> </span> <span class="flex-1 break-words"></span></div>'),za=M('<div class="flex flex-col gap-1"><!> <div></div></div>');function Ra(e,t){j(t,!0);let r=z(null);ne(()=>{var s;t.events,(s=c(r))==null||s.scrollIntoView({behavior:"smooth"})});function a(s){return s.type==="thought"?`[${P(s.step||"think")}] ${P(s.content||"")}`:s.type==="tool_call"?`${P(s.tool_name||"")}(${JSON.stringify(s.arguments||{})})`:s.type==="tool_result"?`${P(s.tool_name||"")} → <pre class="mt-1 rounded bg-[#0f1117] p-1.5 text-[11px]">${P(JSON.stringify(s.result,null,2))}</pre>`:s.type==="agent_spawned"?`Spawned ${P(s.agent_type||"")}: ${P(s.goal||"")}`:s.type==="agent_completed"?`Completed with status: ${P(s.status||"")}`:s.type==="file_created"?`Created ${P(s.tool_name||"file")}: ${P(s.content||"")}`:s.type==="error"?P(s.error||""):s.type==="stream"?P(s.content||""):P(s.content||JSON.stringify(s))}var n=za(),i=k(n);Q(i,17,()=>t.events,se,(s,l)=>{const u=R(()=>c(l).agent_id?`${"└ ".repeat(c(l).depth??0)}${c(l).agent_id.slice(0,8)}`:"");var f=Da(),b=k(f),d=k(b,!0);m(b);var w=O(b,2);Pa(w,{get type(){return c(l).type}});var h=O(w,2),T=k(h,!0);m(h);var v=O(h,2);_t(v,()=>a(c(l)),!0),m(v),m(f),F(p=>{B(d,p),B(T,c(u))},[()=>la(c(l).timestamp)]),N(s,f)});var o=O(i,2);pt(o,s=>A(r,s),()=>c(r)),m(n),N(e,n),U()}var Wa=M('<div class="p-3 text-sm text-[#7a8194]">No files yet.</div>'),Ha=M('<li class="py-0.5 text-[12px]"><a target="_blank" rel="noreferrer" class="text-[#c9cdd6] hover:text-[#4f8cf7] hover:underline"> </a></li>'),Fa=M('<div><div class="mb-1 rounded bg-[#1e212b] px-2 py-1 text-[12px] font-bold text-[#3bd0ee]"> </div> <ul class="pl-2"></ul></div>'),ja=M('<div class="flex flex-col gap-3"></div>');function Ua(e,t){j(t,!0);const r=R(()=>Object.keys(t.files));var a=ie(),n=oe(a);{var i=s=>{var l=Wa();N(s,l)},o=s=>{var l=ja();Q(l,21,()=>c(r),se,(u,f)=>{var b=Fa(),d=k(b),w=k(d,!0);m(d);var h=O(d,2);Q(h,21,()=>t.files[c(f)],se,(T,v)=>{const p=R(()=>Qr(t.sessionId,c(v))),I=R(()=>c(v).endsWith(".png")||c(v).endsWith(".jpg")||c(v).endsWith(".jpeg"));var E=Ha(),S=k(E),D=k(S);m(S),m(E),F(x=>{re(S,"href",c(p)),B(D,`${c(I)?"🖼 ":"📄 "}${x??""}`)},[()=>P(c(v))]),N(T,E)}),m(h),m(b),F(T=>B(w,T),[()=>c(f).slice(0,8)]),N(u,b)}),m(l),N(s,l)};_e(n,s=>{c(r).length===0?s(i):s(o,-1)})}N(e,a),U()}var Ba=M('<div class="flex h-full flex-col border-t border-[#2a2e3b] bg-[#161922]"><!></div>');function Va(e,t){let r=z("tree");var a=Ba(),n=k(a);Ea(n,{tabs:[{id:"tree",label:"Agent Tree"},{id:"events",label:"Event Stream"},{id:"files",label:"Files"}],get activeTab(){return c(r)},set activeTab(i){A(r,i,!0)},children:(i,o)=>{var s=ie(),l=oe(s);{var u=d=>{Ma(d,{get tree(){return t.tree}})},f=d=>{Ra(d,{get events(){return t.events}})},b=d=>{Ua(d,{get sessionId(){return t.sessionId},get files(){return t.files}})};_e(l,d=>{c(r)==="tree"?d(u):c(r)==="events"?d(f,1):c(r)==="files"&&d(b,2)})}N(i,s)},$$slots:{default:!0}}),m(a),N(e,a)}var Ya=M('<div class="flex h-full"><!> <main class="flex min-w-0 flex-1 flex-col"><!> <div class="h-[320px] shrink-0"><!></div></main></div>');function en(e,t){j(t,!0);let r=z(ve([])),a=z(null),n=z(ve([])),i=z(ve([])),o=z(!1),s=z(null),l=z(ve({})),u=R(()=>{var g;return(g=c(a))==null?void 0:g.id}),f=z(null);ne(()=>{const g=new ea;return g.connect(b),A(f,g,!0),()=>g.disconnect()}),ne(()=>{const g=c(u);g&&c(f)&&(c(f).subscribe(g),T(g),w(g),h(g),A(i,[],!0))}),Mt(()=>{d()});function b(g){if(g.session_id===c(u))switch(A(i,[...c(i),g],!0),g.type){case"message":{const _=g.role,W=g.content;_&&W&&A(n,[...c(n),{id:`${Date.now()}-${Math.random()}`,role:_,content:W,agent_id:g.agent_id,timestamp:new Date().toISOString()}],!0);break}case"agent_spawned":case"agent_completed":{const _=c(u);_&&w(_);break}case"file_created":{const _=c(u);_&&h(_);break}case"session_updated":{g.status&&c(a)&&A(a,{...c(a),status:g.status},!0);break}}}async function d(){A(r,await Jr(),!0)}async function w(g){A(s,await Xr(g),!0)}async function h(g){A(l,await Zr(g),!0)}async function T(g){const _=await Kr(g);_&&(A(a,_,!0),A(n,_.messages||[],!0))}function v(g){const _=c(r).find(W=>W.id===g);_&&(A(a,_,!0),A(n,_.messages||[],!0),A(i,[],!0))}async function p(g){const _=await Gr({title:g});A(r,[...c(r),_],!0),A(a,_,!0),A(n,[],!0),A(i,[],!0)}async function I(g){if(c(u)){A(o,!0),A(n,[...c(n),{id:`${Date.now()}-${Math.random()}`,role:"user",content:g,timestamp:new Date().toISOString()}],!0);try{await qr(c(u),{content:g})}catch(_){A(n,[...c(n),{id:`${Date.now()}-${Math.random()}`,role:"system",content:_ instanceof Error?_.message:"Failed to send",timestamp:new Date().toISOString()}],!0)}finally{A(o,!1)}}}var E=Ya(),S=k(E);ga(S,{get sessions(){return c(r)},get activeId(){return c(u)},onSelect:v,onCreate:p});var D=O(S,2),x=k(D);{let g=R(()=>c(o)||!c(u));ya(x,{get messages(){return c(n)},onSend:I,get disabled(){return c(g)}})}var y=O(x,2),L=k(y);{let g=R(()=>c(u)??"");Va(L,{get tree(){return c(s)},get events(){return c(i)},get sessionId(){return c(g)},get files(){return c(l)}})}m(y),m(D),m(E),N(e,E),U()}export{en as component,$a as universal};
