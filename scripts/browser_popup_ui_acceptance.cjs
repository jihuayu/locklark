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
   const c=globalThis.__popupFixture={connected:true, hidden:false, pending:false, copies:[], requests:[], held:[], defer:new Set(), metadata:[], stateOverride:{}, generatedCounter:0, olderGeneratedHistory:[]};
   for(let n=1;n<=count;n++) c.metadata.push({id:n.toString(16).padStart(32,"0"),revision:"a".repeat(64),kind:"login",category:"login",title:"Synthetic account "+n,subtitle:"demo@example.test",urls:["https://example.test"],tags:[],state:"active",favorite:false});
   const clone=v=>structuredClone(v);
   const state=()=>({connected:c.connected,pending:c.pending,status:c.connected?"Connected":"Locked",origin:"https://example.test",candidates:[],vaultItems:c.connected?c.metadata:[],passkeyManagementSupported:true,offerSaveLogins:true,autoLogin:false,...c.stateOverride});
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
     if(m.type==="connect") c.connected=true;
     if(m.type==="item-get") {
      const item=c.metadata.find(i=>i.id===m.id);
      reply={...state(),detail:{...item,has_password:true,fields:[
       {id:"username",label:"Username",type:"text",value:"demo@example.test"},
       {id:"password",label:"Password",type:"concealed",value:"",concealed:true,has_value:true,revealable:true}
      ],notes:"",sections:[],attachments:[]}};
     } else if(m.type==="item-state") reply={...state(),itemState:{item_id:m.id,revision:"b".repeat(64)}};
     else if(m.type==="item-save") reply={...state(),saved:{item_id:c.metadata[0].id,revision:"b".repeat(64)}};
     else if(m.type==="generate") {
      const password="Synthetic-generated-canary-"+(++c.generatedCounter);
      reply={...state(),password,profile:{entropy_bits_floor:80,mode:"random"},generatedPassword:password,
       generatedHistory:[{id:c.metadata[0].id,password,origin:"https://example.test",username:"demo@example.test"},...c.olderGeneratedHistory]};
     }
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
  await check("Lock immediately forgets generated preview and history before the lock reply",async()=>{
   const h=await popup();try{
    await h.page.locator("#generator-section > summary").click();
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    await h.page.locator("#gen-copy").click();await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.copies.length),1);
    await h.page.evaluate(()=>__popupFixture.defer.add("lock"));
    await h.page.locator("#lock-btn").click();await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"");
    assert.equal(await h.page.locator("#gen-history").textContent(),"");
    assert.equal(await h.page.locator("#gen-copy").isDisabled(),true);
    await h.page.evaluate(()=>{__popupFixture.stateOverride={connected:true,password:"Synthetic-old-generated",profile:{entropy_bits_floor:80},generatedHistory:[]};__popupFixture.poll();});
    await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"");
    assert.equal(await h.page.locator("#gen-copy").isDisabled(),true);
    assert.equal(await h.page.evaluate(()=>__popupFixture.copies.length),1);
    await h.page.evaluate(()=>{__popupFixture.stateOverride={};__popupFixture.resolve("lock");});await flush(h.page);
   }finally{await h.close();}
  });
  await check("superseded generation cannot revive after Lock while fresh offline generation remains usable",async()=>{
   const h=await popup();try{
    await h.page.locator("#generator-section > summary").click();
    await h.page.evaluate(()=>__popupFixture.defer.add("generate"));
    await h.page.locator("#gen-regenerate").click();
    await h.page.locator("#lock-btn").click();await flush(h.page);
    await h.page.evaluate(()=>{__popupFixture.defer.delete("generate");__popupFixture.resolve("generate");});await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"");
    assert.equal(await h.page.locator("#gen-regenerate").isEnabled(),true);
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"Synthetic-generated-canary-2");
    await h.page.evaluate(()=>__popupFixture.poll());await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"Synthetic-generated-canary-2");
    assert.equal(await h.page.locator("#gen-copy").isEnabled(),true);
   }finally{await h.close();}
  });
  await check("persisted restore owns a new search and ignores the older search finalizer",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>__popupFixture.defer.add("vault-search"));
    await h.page.locator('#filter-tabs [data-filter="all"]').click();await flush(h.page);
    assert.equal(await h.page.locator("#search-input").isDisabled(),true);
    await h.page.evaluate(()=>{window.dispatchEvent(new PageTransitionEvent("pagehide",{persisted:true}));window.dispatchEvent(new PageTransitionEvent("pageshow",{persisted:true}));});await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.held.filter(h=>h.type==="vault-search").length),2);
    await h.page.evaluate(()=>__popupFixture.resolve("vault-search"));await flush(h.page);
    assert.equal(await h.page.locator("#search-input").isDisabled(),true);
    await h.page.evaluate(()=>__popupFixture.resolve("vault-search"));await flush(h.page);
    assert.equal(await h.page.locator("#search-input").isEnabled(),true);
   }finally{await h.close();}
  });
  await check("persisted restore releases canceled action busy without accepting its generated reply",async()=>{
   const h=await popup();try{
    await h.page.locator("#generator-section > summary").click();
    await h.page.evaluate(()=>__popupFixture.defer.add("generate"));
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    await h.page.evaluate(()=>{window.dispatchEvent(new PageTransitionEvent("pagehide",{persisted:true}));window.dispatchEvent(new PageTransitionEvent("pageshow",{persisted:true}));});await flush(h.page);
    assert.equal(await h.page.locator("#gen-regenerate").isEnabled(),true);
    await h.page.evaluate(()=>{__popupFixture.defer.delete("generate");__popupFixture.resolve("generate");});await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"");
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"Synthetic-generated-canary-2");
   }finally{await h.close();}
  });
  await check("fresh generation after restore cannot rehydrate older background password history",async()=>{
   const h=await popup();try{
    await h.page.locator("#generator-section > summary").click();
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    await h.page.evaluate(()=>{
     __popupFixture.olderGeneratedHistory=[{id:"f".repeat(32),password:"Synthetic-old-history-canary",origin:"https://example.test",username:"older"}];
     window.dispatchEvent(new PageTransitionEvent("pagehide",{persisted:true}));
     window.dispatchEvent(new PageTransitionEvent("pageshow",{persisted:true}));
    });await flush(h.page);
    await h.page.locator("#gen-regenerate").click();await flush(h.page);
    assert.equal(await h.page.locator("#gen-preview").textContent(),"Synthetic-generated-canary-2");
    assert.equal(await h.page.locator("#gen-copy").isEnabled(),true);
    assert.equal(await h.page.locator("#gen-history").textContent(),"");
    assert.deepEqual(h.errors,[]);
   }finally{await h.close();}
  });
  await check("older lock acknowledgement cannot overwrite a reconnected popup",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>__popupFixture.defer.add("lock"));
    await h.page.locator("#lock-btn").click();
    await h.page.locator("#lock-btn").click();await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.held.filter(h=>h.type==="lock").length),2);
    await h.page.evaluate(()=>{
     const c=__popupFixture,locks=c.held.filter(h=>h.type==="lock"),newer=locks[1];
     c.held.splice(c.held.indexOf(newer),1);newer.resolve(structuredClone(newer.reply));
    });await flush(h.page);
    await h.page.locator("#unlock-connect").click();await flush(h.page);
    assert.equal(await h.page.locator("#locked-view").isVisible(),false);
    await h.page.evaluate(()=>__popupFixture.resolve("lock"));await flush(h.page);
    assert.equal(await h.page.locator("#locked-view").isVisible(),false);
    assert.equal(await h.page.locator("#vault-list .vault-item").count(),4);
    assert.deepEqual(h.errors,[]);
   }finally{await h.close();}
  });
  await check("an unrelated action cannot suppress the restored popup's fresh metadata read",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>{
     const c=__popupFixture;c.defer.add("state");c.defer.add("vault-search");
     window.dispatchEvent(new PageTransitionEvent("pagehide",{persisted:true}));
     window.dispatchEvent(new PageTransitionEvent("pageshow",{persisted:true}));
     // Same standard activation as the existing Refresh handler, during restore.
     document.querySelector("#refresh").click();
    });await flush(h.page);
    await h.page.evaluate(()=>__popupFixture.resolve("state"));await flush(h.page);
    assert.equal(await h.page.evaluate(()=>__popupFixture.held.filter(h=>h.type==="vault-search").length),1);
    await h.page.evaluate(()=>__popupFixture.resolve("vault-search"));await flush(h.page);
    assert.equal(await h.page.locator("#search-input").isEnabled(),true);
    assert.deepEqual(h.errors,[]);
   }finally{await h.close();}
  });
  await check("a pending detail read cannot replace a new editor draft",async()=>{
   const h=await popup();try{
    await h.page.evaluate(()=>__popupFixture.defer.add("item-get"));
    await h.page.locator("#vault-list .vault-item").first().click();
    await h.page.locator("#new-item-btn").click();await h.page.locator('#new-item-menu [data-category="login"]').click();
    await h.page.locator('#editor-fields input[data-field="title"]').fill("New draft wins");
    await h.page.evaluate(()=>__popupFixture.resolve("item-get"));await flush(h.page);
    assert.equal(await h.page.locator("#editor-view").isVisible(),true);
    assert.equal(await h.page.locator('#editor-fields input[data-field="title"]').inputValue(),"New draft wins");
    assert.equal(await h.page.locator("#detail-view").isVisible(),false);
   }finally{await h.close();}
  });
  // Firefox measures the real extension panel with a 0-width viewport before it
  // lays the popup out. body{width:390px;max-width:100vw} was circular there:
  // 100vw resolved to that 0 width, so the body collapsed to 0 while the fixed
  // 320/390 headless pages above still looked correct. Reproduce that initial
  // measurement with a same-origin iframe that loads the real popup.css and
  // assert the intrinsic 390px body survives it.
  await check('popup body keeps its intrinsic 390px width in a 0-width initial panel viewport',async()=>{
   const h=await popup();try{
    const m=await h.page.evaluate(async()=>{
     const frame=document.createElement('iframe');
     frame.title='popup zero-width viewport probe';
     frame.style.cssText='display:block;width:0;height:640px;border:0';
     const loaded=new Promise(resolve=>frame.addEventListener('load',resolve,{once:true}));
     frame.srcdoc='<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/popup.css"></head><body><main><h1>Locklark</h1></main></body></html>';
     document.body.appendChild(frame);
     try{
      await loaded;
      const win=frame.contentWindow;
      const cssReady=()=>{try{const sheets=win.document.styleSheets;return sheets.length>0&&sheets[0].cssRules.length>0;}catch{return false;}};
      for(let n=0;n<100&&!cssReady();n++)await new Promise(r=>setTimeout(r,50));
      if(!cssReady())throw new Error('popup.css did not load inside the 0-width probe iframe');
      const body=win.document.body,style=win.getComputedStyle(body),rect=body.getBoundingClientRect();
      return {innerWidth:win.innerWidth,computedWidth:style.width,maxWidth:style.maxWidth,rectWidth:rect.width,
       narrowBand:win.matchMedia('(min-width:320px) and (max-width:389px)').matches,
       docScrollWidth:win.document.documentElement.scrollWidth};
     }finally{frame.remove();}
    });
    if(!observe){
     assert.equal(m.innerWidth,0,'probe must reproduce the 0-width viewport of the initial Firefox panel');
     assert.equal(m.narrowBand,false,'a 0-width viewport must not enter the supported 320-389px band');
     assert.equal(m.computedWidth,'390px','body must keep the intrinsic 390px width at a 0-width viewport');
     assert.equal(m.rectWidth,390,'body must lay out at 390px at a 0-width viewport');
     assert.equal(m.maxWidth,'none','no viewport-relative max-width may clamp the intrinsic width');
    }
    return m;
   }finally{await h.close();}
  });
  for(const width of [320,389,390]) for(const theme of ["light","dark"]) await check("visible search and themed generator at "+width+"px "+theme,async()=>{
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
