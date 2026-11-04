import { expect, test } from "bun:test";
const run=async (value:string)=>{
 const child=Bun.spawn([process.execPath,"run",import.meta.dir+"/index.ts"],{stdin:new Blob([value]),stdout:"pipe",stderr:"pipe"});
 return [await child.exited,await new Response(child.stdout).text(),await new Response(child.stderr).text()] as const;
};
test("proposes only the fixed action",async()=>{
 const [status,out,err]=await run('{"repo":"123","number":7}');
 expect(status).toBe(0);expect(JSON.parse(out)).toEqual({v:1,action:"github.pulls.get",repo:"123",number:7});expect(err).toBe("");
});
test("rejects URL, extra fields, invalid ids, trailing and oversized input without echo",async()=>{
 for(const value of ['{"repo":"SYNTHETIC_PRIVATE","number":7}','{"repo":"123","number":0}','{"repo":"123","number":7,"url":"SYNTHETIC_PRIVATE"}','{}{}'," ".repeat(4097)]){
 const [status,out,err]=await run(value);expect(status).not.toBe(0);expect(out).toBe("");expect(err).not.toContain("SYNTHETIC_PRIVATE");}
});
