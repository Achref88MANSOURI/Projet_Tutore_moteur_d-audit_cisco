// Exercise the report's real JavaScript against a small DOM adapter.
// This checks filters and pagination without replacing its rendering logic.
const fs=require('fs'); const path=require('path'); const vm=require('vm'); const assert=require('assert');
const root=path.resolve(__dirname,'..');const out=path.join(root,'outputs','diagnostic_pipeline');
const html=fs.readFileSync(path.join(out,'RAPPORT_DIAGNOSTIC.html'),'utf8');
const json=html.match(/<script id="dataset" type="application\/json">([\s\S]*?)<\/script>/)[1];
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];assert.equal(scripts.length,1);
const data=JSON.parse(json);assert.equal(data.rows.length,1359);assert.equal(data.rules.length,272);
class Element {
  constructor(tag){this.tagName=tag;this.children=[];this.value='';this.textContent='';this.listeners={};}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];}
  addEventListener(name,callback){(this.listeners[name]??=[]).push(callback);}
}
const ids=new Map();for(const id of ['dataset','q','cause','file','status','reset','count','prev','next','size','rows','ruleq','rules'])ids.set(id,new Element(id));
ids.get('size').value='50';ids.get('dataset').textContent=json;
const context=vm.createContext({document:{getElementById:id=>{assert(ids.has(id),id);return ids.get(id);},createElement:tag=>new Element(tag)}});
new vm.Script(scripts[0][1],{filename:'RAPPORT_DIAGNOSTIC.html'}).runInContext(context);
const render=()=>vm.runInContext('render()',context);
const reset=()=>{for(const id of ['q','cause','file','status'])ids.get(id).value='';vm.runInContext('page=0',context);render();};
assert.equal(ids.get('rows').children.length,50);assert.equal(ids.get('rules').children.length,272);
assert(ids.get('count').textContent.startsWith('1359 occurrence(s)'));
ids.get('cause').value='normalized_schema_field';render();assert(ids.get('count').textContent.startsWith('601 occurrence(s)'));
reset();ids.get('cause').value='family_dispatch_gap';render();assert.equal(ids.get('rows').children.length,1);assert(ids.get('count').textContent.startsWith('1 occurrence(s)'));
reset();ids.get('cause').value='template_variant_missing';render();assert.equal(ids.get('rows').children.length,6);
reset();ids.get('status').value='preserved_uninterpreted';render();assert(ids.get('count').textContent.startsWith('582 occurrence(s)'));
reset();ids.get('q').value='no mop enabled';render();assert(ids.get('count').textContent.startsWith('32 occurrence(s)'));
reset();ids.get('q').value='string-that-occurs-nowhere-000999';render();assert.equal(ids.get('rows').children.length,0);assert(ids.get('next').disabled&&ids.get('prev').disabled);
reset();ids.get('next').listeners.click[0]();assert(ids.get('count').textContent.includes('page 2 /'));ids.get('prev').listeners.click[0]();assert(ids.get('count').textContent.includes('page 1 /'));
ids.get('ruleq').value='if_duplex';vm.runInContext('renderRules()',context);assert.equal(ids.get('rules').children.length,1);
// All static report links must resolve locally, except explicit external URLs.
let links=0;for(const file of ['RAPPORT_DIAGNOSTIC.md','RAPPORT_DIAGNOSTIC.html']){
 const source=fs.readFileSync(path.join(out,file),'utf8');
 const targets=file.endsWith('.md')?[...source.matchAll(/\]\(([^)]+)\)/g)].map(x=>x[1]):[...source.matchAll(/href="([^"]+)"/g)].map(x=>x[1]);
 for(const target of targets){if(target.startsWith('http')||target.startsWith('#'))continue;assert(fs.existsSync(path.resolve(out,target)),target);links++;}
}
const summary={dataset_rows:1359,rules:272,initial_page_rows:50,filters_and_pagination_passed:true,static_links_checked:links};
fs.writeFileSync(path.join(out,'report_ui_verification.json'),JSON.stringify(summary,null,2)+'\n','utf8');console.log(JSON.stringify(summary));
