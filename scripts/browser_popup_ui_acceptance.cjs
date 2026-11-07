// Real browser DOM/component acceptance. Runtime replies and clipboard are
// controlled synthetic fixtures; this is not native approval or OS clipboard proof.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const playwright = require(process.env.LOCKLARK_TEST_PLAYWRIGHT || "../web/node_modules/playwright");
const root = path.resolve(process.env.LOCKLARK_TEST_SOURCE_ROOT || path.join(__dirname, ".."));
const observe = process.argv.includes("--observe-baseline");
const family = process.env.LOCKLARK_TEST_BROWSER || "chromium";
const results = [];
(async () => {
 const browser = await playwright[family].launch({headless:true,args:family==="chromium"?["--no-sandbox"]:[]});
 async function popup(count=4, theme="light", width=390) {
  const context=await browser.newContext({viewport:{width,height:640},colorScheme:theme});
  await context.route("**/*", async route=>{
   const url=new URL(route.request().url()), name=url.pathname.slice(1);
   if(url.origin!=="https://ui.locklark.test" || !["popup.html","popup.css","popup.js","core.js"].includes(name)) return route.abort();
   return route.fulfill({body:fs.readFileSync(path.join(root,"browser-extension",name)),contentType:name.endsWith(".js")?"text/javascript":name.endsWith(".css")?"text/css":"text/html"});
  });
  await context.addInitScript(({count})=>{
   const c=globalThis.__popupFixture={connected:true, hidden:false, pending:false, copies:[], requests:[], held:[], defer:new Set(), metadata:[]};
   for(let n=1;n<=count;n++) c.metadata.push({id:n.toString(16).padStart(32,"0"),revision:"a".repeat(64),kind:"login",category:"login",title:"Synthetic account "+n,subtitle:"demo@example.test",urls:["https://example.test"],tags:[],state:"active",favorite:false});
   const clone=v=>structuredClone(v);
   const state=()=>({connected:c.connected,pending:c.pending,status:c.connected?"Connected":"Locked",origin:"https://example.test",candidates:[],vaultItems:c.connected?c.metadata:[],passkeyManagementSupported:true,offerSaveLogins:true,autoLogin:false});
   c.resolve=type=>{const h=c.held.find(h=>h.type===type);if(!h)throw Error("No held reply");c.held.splice(c.held.indexOf(h),1);h.resolve(clone(h.reply));};
   const listeners={addListener(){}};
   Object.defineProperty(document,"visibilityState",{configurable:true,get:()=>c.hidden?"hidden":"visible"});
   Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:async value=>{c.copies.push(value);}}});
   const originalInterval=globalThis.setInterval.bind(globalThis);
   globalThis.setInterval=(fn,delay)=>{if(delay===500){c.poll=fn;return 77;}return originalInterval(fn,delay);};
   globalThis.chrome={
    runtime:{onMessage:listeners,openOptionsPage:async()=>{},sendMessage:async m=>{
     c.requests.push({type:m.type,id:m.id,revision:m.revision});
     let reply;
     if(m.type==="lock" || m.type==="disconnect") c.connected=false;
     if(m.type==="item-get") {
      const item=c.metadata.find(i=>i.id===m.id);
      reply={...state(),detail:{...item,has_password:true,fields:[
       {id:"username",label:"Username",type:"text",value:"demo@example.test"},
       {id:"password",label:"Password",type:"concealed",value:"",concealed:true,has_value:true,revealable:true}
      ],notes:"",sections:[],attachments:[]}};
     } else if(m.type==="item-state") reply={...state(),itemState:{item_id:m.id,revision:"b".repeat(64)}};
     else if(m.type==="item-save") reply={...state(),saved:{item_id:c.metadata[0].id,revision:"b".repeat(64)}};
     else if(m.type==="generate") reply={generatedPassword:"Synthetic-generated-canary"};
     else if(m.type==="copy-field") reply={copiedField:{value:"Synthetic-private-canary",clearAfterSeconds:30}};
     else if(m.type==="reveal-field") reply={revealedField:{field:"password",value:"Synthetic-private-canary",expires_in_seconds:30}};
     else reply=state();
     if(c.defer.has(m.type))return new Promise(resolve=>c.held.push({type:m.type,resolve,reply:clone(reply)}));
     return clone(reply);
    }},
    storage:{local:{get:async()=>({}),set:async()=>{}},onChanged:listeners},
    commands:{getAll:async()=>[]},tabs:{create:async()=>{}}
   };
  },{count});
  const page=await context.newPage();
  const errors=[];page.on("pageerror",e=>errors.push(e.message));
  await page.goto("https://ui.locklark.test/popup.html");
  await page.locator("#vault-list .vault-item").first().waitFor();
  return {page,errors,close:()=>context.close()};
 }
 async function check(name, fn) {
  try {const metrics=await fn();results.push({name,...(observe?{observed:true}:{pass:true}),...metrics});}
  catch(error){results.push({name,...(observe?{observed:true,assertionFailed:true}:{pass:false}),error:error.message});if(!observe)throw error;}
 }
 const flush=page=>page.evaluate(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();await Promise.resolve();});
 const open=async page=>{await page.locator("#vault-list .vault-item").first().click();await page.locator("#detail-view").waitFor({state:"visible"});};
 const password='[data-field-id="password"]';
 try {
  await check("vault metadata updates independently of unchanged website candidates", async()=>{
   const h=await popup();try{
    await h.page.evaluate(async()=>{const c=__popupFixture;c.metadata[0].title="Updated metadata";c.metadata[0].revision="b".repeat(64);c.poll();});
    await flush(h.page);
    const updated=h.page.locator('#vault-list [data-item-id="00000000000000000000000000000001"]');
    assert.equal(await updated.locator(".vault-item-title").textContent(),"Updated metadata");
    await updated.click();await h.page.locator("#detail-view").waitFor({state:"visible"});
    const request=await h.page.evaluate(()=>__popupFixture.requests.filter(r=>r.type==="item-get").at(-1));
    assert.equal(request.revision,"b".repeat(64));
    assert.deepEqual(h.errors,[]);
   }finally{await h.close();}
  });
  for(const count of [100,500]) await check("unchanged metadata retains focused rows across 100 state changes ("+count+" rows)",async()=>{
   const h=await popup(count);try{
    const m=await h.page.evaluate(async()=>{
     const list=document.querySelector("#vault-list"), first=list.firstElementChild;
     first.focus();list.scrollTop=40;const scroll=list.scrollTop;let added=0,removed=0;
     const mo=new MutationObserver(rs=>{for(const r of rs){added+=r.addedNodes.length;removed+=r.removedNodes.length;}});
     mo.observe(list,{childList:true,subtree:true});
     const start=performance.now();
     for(let n=0;n<100;n++){__popupFixture.pending=!!(n%2);__popupFixture.poll();await Promise.resolve();await Promise.resolve();await Promise.resolve();}
     await Promise.resolve();mo.disconnect();
     return {durationMs:performance.now()-start,added,removed,retained:list.firstElementChild===first,focused:document.activeElement===first,scrollRetained:list.scrollTop===scroll};
    });
    if(!observe){assert.equal(m.added,0);assert.equal(m.removed,0);assert(m.retained&&m.focused&&m.scrollRetained);}
    return {count,...m};
   }finally{await h.close();}
  });
  await check("search Enter opens the first result through standard DOM activation",async()=>{
   const h=await popup();try{
    await h.page.locator("#search-input").focus();await h.page.keyboard.press("Enter");await flush(h.page);
    assert.equal(await h.page.locator("#detail-view").isVisible(),true);
   }finally{await h.close();}
  });
  await check("late copy after lock never writes the clipboard",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>__popupFixture.defer.add("copy-field"));
    await h.page.locator(password+' [data-action="copy-field"]').click();
    await h.page.locator("#lock-btn").click();await flush(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("copy-field"));await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.copies.length),0);
    assert.equal(await h.page.locator("#detail-fields").textContent(),"");
   }finally{await h.close();}
  });
  await check("header lock preempts a pending detail RPC and stale completion stays hidden",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>__popupFixture.defer.add("item-get"));
    await h.page.locator("#vault-list .vault-item").first().click();
    assert.equal(await h.page.locator("#lock-btn").isEnabled(),true);
    await h.page.locator("#lock-btn").click();await flush(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("item-get"));await flush(h.page);
    assert.equal(await h.page.locator("#locked-view").isVisible(),true);
    assert.equal(await h.page.locator("#detail-fields").textContent(),"");
   }finally{await h.close();}
  });
  await check("old reveal cannot revive after returning to the same account",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>__popupFixture.defer.add("reveal-field"));
    await h.page.locator(password+' [data-action="toggle-reveal"]').click();
    await h.page.locator("#detail-back").click();await open(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("reveal-field"));await flush(h.page);
    assert(!String(await h.page.locator(password+" .field-value").textContent()).includes("Synthetic-private"));
   }finally{await h.close();}
  });
  await check("visibility invalidation removes revealed plaintext from the live DOM",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.locator(password+' [data-action="toggle-reveal"]').click();await flush(h.page);
    assert.equal(await h.page.locator(password+" .field-value").textContent(),"Synthetic-private-canary");
    await h.page.evaluate(()=>{__popupFixture.hidden=true;document.dispatchEvent(new Event("visibilitychange"));});
    assert(!String(await h.page.locator(password+" .field-value").textContent()).includes("Synthetic-private"));
   }finally{await h.close();}
  });
  await check("pagehide invalidates pending copies and delayed state replies",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>{__popupFixture.defer.add("copy-field");__popupFixture.defer.add("state");__popupFixture.poll();});
    await h.page.locator(password+' [data-action="copy-field"]').click();
    await h.page.evaluate(()=>{window.dispatchEvent(new PageTransitionEvent("pagehide",{persisted:true}));__popupFixture.resolve("copy-field");__popupFixture.resolve("state");});
    await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.copies.length),0);
    assert.equal(await h.page.locator("#detail-fields").textContent(),"");
   }finally{await h.close();}
  });
  await check("empty snapshots and changed origin-matching URLs invalidate cached rows",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>{for(const row of __popupFixture.metadata)row.urls=["https://different.test"];__popupFixture.poll();});
    await flush(h.page);assert.equal(await h.page.locator("#vault-list .vault-item").count(),0);
    await h.page.evaluate(()=>{__popupFixture.metadata=[];__popupFixture.poll();});
    await flush(h.page);assert.equal(await h.page.locator("#vault-list .vault-item").count(),0);
   }finally{await h.close();}
  });
  await check("filter tabs use standard ArrowRight and Home keyboard activation",async()=>{
   const h=await popup();try{
    const tab=h.page.locator('#filter-tabs [data-filter="suggested"]');
    await tab.focus();await h.page.keyboard.press("ArrowRight");await flush(h.page);
    assert.equal(await h.page.locator('#filter-tabs [data-filter="all"]').getAttribute("aria-selected"),"true");
    await h.page.keyboard.press("Home");await flush(h.page);
    assert.equal(await tab.getAttribute("aria-selected"),"true");
    assert.equal(await h.page.locator('#filter-tabs [tabindex="0"]').count(),1);
   }finally{await h.close();}
  });
  await check("Favorites stays a distinct filter and returns only favorites",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>{__popupFixture.metadata[1].favorite=true;});
    await h.page.locator('#filter-tabs [data-filter="favorites"]').click();await flush(h.page);
    assert.equal(await h.page.locator('#filter-tabs [data-filter="favorites"]').getAttribute("aria-selected"),"true");
    assert.equal(await h.page.locator("#vault-list .vault-item").count(),1);
   }finally{await h.close();}
  });
  await check("late search results cannot reconnect a locked popup",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>__popupFixture.defer.add("vault-search"));
    await h.page.locator('#filter-tabs [data-filter="all"]').click();
    await h.page.locator("#lock-btn").click();await flush(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("vault-search"));await flush(h.page);
    assert.equal(await h.page.locator("#locked-view").isVisible(),true);
    assert.equal(await h.page.locator("#vault-list .vault-item").count(),0);
   }finally{await h.close();}
  });
  await check("late committed save cannot restore an editor after external lock",async()=>{
   const h=await popup();try{
    await h.page.locator("#new-item-btn").click();await h.page.locator('#new-item-menu [data-category="login"]').click();
    await h.page.locator('#editor-fields input[data-field="title"]').fill("Synthetic editor");
    await h.page.evaluate(()=>__popupFixture.defer.add("item-save"));
    await h.page.locator("#editor-save").click();
    await h.page.evaluate(()=>{__popupFixture.connected=false;__popupFixture.poll();});await flush(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("item-save"));await flush(h.page);
    assert.equal(await h.page.locator("#locked-view").isVisible(),true);
    assert.equal(await h.page.locator("#editor-fields").textContent(),"");
    assert.equal(await h.page.locator("#detail-view").isVisible(),false);
   }finally{await h.close();}
  });
  await check("a superseded reveal cannot override the later explicit Hide",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>__popupFixture.defer.add("reveal-field"));
    await h.page.locator(password+' [data-action="toggle-reveal"]').click();
    await h.page.locator(password+' [data-action="toggle-reveal"]').click();
    await h.page.evaluate(()=>{const c=__popupFixture,h=c.held.pop();h.resolve(structuredClone(h.reply));});await flush(h.page);
    await h.page.locator(password+' [data-action="toggle-reveal"]').click();
    await h.page.evaluate(()=>__popupFixture.resolve("reveal-field"));await flush(h.page);
    assert(!String(await h.page.locator(password+" .field-value").textContent()).includes("Synthetic-private"));
   }finally{await h.close();}
  });
  await check("late favorite acknowledgement cannot overwrite another account detail",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>__popupFixture.defer.add("item-state"));
    await h.page.locator("#detail-favorite").click();
    await h.page.locator("#detail-back").click();
    await h.page.locator("#vault-list .vault-item").nth(1).click();
    await h.page.evaluate(()=>__popupFixture.resolve("item-state"));await flush(h.page);
    assert.equal(await h.page.locator("#detail-title").textContent(),"Synthetic account 2");
    assert.equal(await h.page.locator("#detail-favorite").getAttribute("aria-pressed"),"false");
   }finally{await h.close();}
  });
  await check("copy permission is revoked when visibility becomes hidden",async()=>{
   const h=await popup();try{
    await open(h.page);await h.page.evaluate(()=>__popupFixture.defer.add("copy-field"));
    await h.page.locator(password+' [data-action="copy-field"]').click();
    await h.page.evaluate(()=>{__popupFixture.hidden=true;document.dispatchEvent(new Event("visibilitychange"));__popupFixture.resolve("copy-field");});
    await flush(h.page);assert.equal(await h.page.evaluate(()=>__popupFixture.copies.length),0);
   }finally{await h.close();}
  });
  for(const width of [320,390]) for(const theme of ["light","dark"]) await check("visible search and themed generator at "+width+"px "+theme,async()=>{
   const h=await popup(4,theme,width);try{
    const m=await h.page.evaluate(()=>({top:document.querySelector("#search-input").getBoundingClientRect().top,scrollWidth:document.documentElement.scrollWidth,width:innerWidth}));
    if(!observe){assert(m.top<320);assert(m.scrollWidth<=m.width);}
    if(process.env.LOCKLARK_TEST_UI_ARTIFACTS) {
     const folder=path.resolve(process.env.LOCKLARK_TEST_UI_ARTIFACTS);fs.mkdirSync(folder,{recursive:true});
     await h.page.screenshot({path:path.join(folder,family+"-"+theme+"-"+width+"-vault.png")});
    }
    if((await h.page.locator("#generator-section").evaluate(e=>e.tagName))==="DETAILS")await h.page.locator("#generator-section > summary").click();
    const ratio=await h.page.locator("#generator-section").evaluate(el=>{
     const rgb=v=>v.match(/[\d.]+/g).slice(0,3).map(Number).map(n=>{n/=255;return n<=.04045?n/12.92:((n+.055)/1.055)**2.4;});
     const luminance=v=>{const c=rgb(v);return .2126*c[0]+.7152*c[1]+.0722*c[2];};
     const s=getComputedStyle(el),a=luminance(s.color),b=luminance(s.backgroundColor);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
    });
    if(!observe) assert(ratio>=4.5,"Generator contrast below 4.5:1");
    return {...m,generatorContrast:ratio};
   }finally{await h.close();}
  });
 } finally {await browser.close();console.log(JSON.stringify({family,componentOnly:true,results},null,2));}
 if(!observe && results.some(r=>!r.pass))process.exitCode=1;
})().catch(e=>{console.error("Popup DOM acceptance failed:",e.message);process.exitCode=1});
