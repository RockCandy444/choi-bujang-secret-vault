import {lstat,realpath,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join,dirname,isAbsolute,parse,relative} from 'node:path';
import {createHash} from 'node:crypto';
import {buildPackageQueries,createOsvClient,OSV_QUERY_BATCH_URL} from './osv.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const samePath=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const stamp=stat=>[stat.dev,stat.ino,stat.size,stat.mode,stat.nlink,stat.mtimeNs,stat.ctimeNs].map(String).join(':');
const directoryStamp=stat=>[stat.dev,stat.ino,stat.mode].map(String).join(':');
const check=signal=>{if(signal.aborted)throw Error('scan unavailable');};
const unavailable=checkedAt=>({status:'unverifiable',code:'LOCKFILE_UNVERIFIABLE',checkedAt,packages:[]});
const key=query=>query.package.name+'\n'+query.version;
const unknown=(query,checkedAt,vulnerabilities=[])=>({name:query.package.name,version:query.version,status:'unverifiable',vulnerabilities,source:OSV_QUERY_BATCH_URL,checkedAt});
const iso=value=>typeof value==='string'&&value.length<=40&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)&&Number.isFinite(Date.parse(value))&&Number.isFinite(Date.parse(value.slice(0,10)+'T00:00:00Z'))&&new Date(Date.parse(value.slice(0,10)+'T00:00:00Z')).toISOString().slice(0,10)===value.slice(0,10);
const findingId=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(value)&&!/(?:sk-[A-Za-z0-9_-]{8,}|password|private\s*key)/i.test(value)&&(!/^CVE-/i.test(value)||/^CVE-\d{4}-\d{4,}$/.test(value))&&(!/^GHSA-/i.test(value)||/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(value));

function json(bytes){
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text),stack=[];
  // JSON.parse alone accepts duplicate names; conflicting installation metadata is ambiguous.
  for(let i=0;i<text.length;i++){
    const c=text[i];
    if(c==='"'){
      let end=i+1;for(;end<text.length;end++){if(text[end]==='\\'){end++;continue;}if(text[end]==='"')break;}
      const top=stack.at(-1);if(top?.object&&top.nextKey){const name=JSON.parse(text.slice(i,end+1));if(top.keys.has(name))throw Error('ambiguous metadata');top.keys.add(name);top.nextKey=false;}i=end;
    }else if(c==='{')stack.push({object:true,nextKey:true,keys:new Set()});
    else if(c==='[')stack.push({object:false});
    else if(c==='}'||c===']')stack.pop();
    else if(c===','&&stack.at(-1)?.object)stack.at(-1).nextKey=true;
  }
  return value;
}
function installedPath(path){
  if(typeof path!=='string'||path.length>512||path!==path.normalize('NFC')||/[\\:\u0000-\u001f\u007f<>"|?*]/.test(path)||path.startsWith('/'))throw Error('invalid installation path');
  const parts=path.split('/');
  if(parts.some(part=>!part||part==='.'||part==='..'||/[. ]$/.test(part)||/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)))throw Error('invalid installation path');
  return parts;
}
async function directories(path,signal){
  const root=parse(path).root,paths=[root];let current=root;
  for(const part of path.slice(root.length).split(/[\\/]/).filter(Boolean)){current=join(current,part);paths.push(current);}
  const proof=[];
  for(const entry of paths){check(signal);const stat=await lstat(entry,{bigint:true});check(signal);if(!stat.isDirectory()||stat.isSymbolicLink()||!samePath(await realpath(entry),entry))throw Error('invalid directory');proof.push({path:entry,stamp:directoryStamp(stat)});}
  return proof;
}
async function readMetadata(root,file,maxBytes,signal){
  const rel=relative(root,file);if(rel.startsWith('..')||isAbsolute(rel)||file===root)throw Error('invalid file boundary');
  const parents=await directories(dirname(file),signal);check(signal);
  const before=await lstat(file,{bigint:true});if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1n||before.size>BigInt(maxBytes)||!samePath(await realpath(file),file))throw Error('invalid metadata');
  check(signal);const handle=await open(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    check(signal);const opened=await handle.stat({bigint:true});if(stamp(opened)!==stamp(before))throw Error('metadata changed');
    const buffer=Buffer.alloc(Number(opened.size)+1);let length=0;
    while(length<buffer.length){check(signal);const {bytesRead}=await handle.read(buffer,length,Math.min(65536,buffer.length-length),length);if(!bytesRead)break;length+=bytesRead;}
    const bytes=Buffer.from(buffer.subarray(0,length));check(signal);const after=await handle.stat({bigint:true}),last=await lstat(file,{bigint:true});
    if(bytes.length>maxBytes||BigInt(bytes.length)!==opened.size||stamp(after)!==stamp(before)||stamp(last)!==stamp(before)||last.isSymbolicLink())throw Error('metadata changed');
    await currentDirectories(parents,signal);return {path:file,bytes,sha256:sha(bytes),stamp:stamp(before),parents};
  }finally{await handle.close();}
}
async function currentDirectories(proof,signal){
  for(const row of proof){check(signal);const stat=await lstat(row.path,{bigint:true});if(!stat.isDirectory()||stat.isSymbolicLink()||directoryStamp(stat)!==row.stamp||!samePath(await realpath(row.path),row.path))throw Error('directory changed');}
}
async function currentFile(root,proof,maxBytes,signal){
  const current=await readMetadata(root,proof.path,maxBytes,signal);
  if(current.stamp!==proof.stamp||current.sha256!==proof.sha256||current.parents.length!==proof.parents.length||current.parents.some((row,i)=>row.path!==proof.parents[i].path||row.stamp!==proof.parents[i].stamp))throw Error('metadata changed');
}
function publicResult(value,query,checkedAt){
  if(!plain(value)||value.name!==query.package.name||value.version!==query.version||value.source!==OSV_QUERY_BATCH_URL||!['known_vulnerabilities','none_found','unverifiable'].includes(value.status)
    ||!iso(value.checkedAt)||!Array.isArray(value.vulnerabilities))return unknown(query,checkedAt);
  const findings=[];const ids=new Set();
  for(const row of value.vulnerabilities){if(!plain(row)||!findingId(row.id)||!iso(row.modified)||ids.has(row.id))return unknown(query,checkedAt);ids.add(row.id);findings.push({id:row.id,modified:row.modified});}
  if(value.status==='none_found'&&findings.length||value.status==='known_vulnerabilities'&&!findings.length)return unknown(query,checkedAt,findings);
  return {name:query.package.name,version:query.version,status:value.status,vulnerabilities:findings,source:OSV_QUERY_BATCH_URL,checkedAt:value.checkedAt};
}

export function createProjectScanner({projectDirectory,approvedPublicPackages=[],client=createOsvClient()}={}){
  // Host approval is snapshotted. Neither installation metadata nor browser data can enlarge it.
  const approved=Array.isArray(approvedPublicPackages)?approvedPublicPackages.filter(value=>typeof value==='string'):[];
  return Object.freeze({async scan({signal:externalSignal}={}){
    const checkedAt=new Date().toISOString();
    if(typeof projectDirectory!=='string'||!isAbsolute(projectDirectory))return{status:'not_configured',code:'PROJECT_NOT_CONFIGURED',checkedAt,packages:[]};
    const directory=resolve(projectDirectory),controller=new AbortController(),signal=controller.signal;
    let selected,packages=[],timer,cancel;
    const partial=()=>selected?{status:'partial',lockfileVersion:selected.lockfileVersion,lockfileHash:selected.lockfileHash,excluded:selected.excluded,checkedAt,packages:selected.queries.map((query,i)=>unknown(query,packages[i]?.checkedAt??checkedAt,packages[i]?.vulnerabilities??[]))}:unavailable(checkedAt);
    const stopped=new Promise(resolveStop=>{cancel=()=>{controller.abort();resolveStop(partial());};timer=setTimeout(cancel,10000);externalSignal?.addEventListener('abort',cancel,{once:true});if(externalSignal?.aborted)cancel();});
    const work=async()=>{
      check(signal);const lockProof=await readMetadata(directory,join(directory,'package-lock.json'),2097152,signal),lock=json(lockProof.bytes);
      const selection=buildPackageQueries(lock,{approvedPublicPackages:approved});if(![2,3].includes(selection.lockfileVersion)||Object.keys(lock.packages).length>4096)throw Error('invalid lock');
      if(!selection.queries.length){await currentFile(directory,lockProof,2097152,signal);check(signal);return{status:'not_checked',code:'NO_APPROVED_PACKAGES',lockfileVersion:selection.lockfileVersion,lockfileHash:lockProof.sha256,excluded:selection.excluded,checkedAt,packages:[]};}
      if(selection.queries.length>256)throw Error('too many packages');
      selected={...selection,lockfileHash:lockProof.sha256};packages=selected.queries.map(query=>unknown(query,checkedAt));
      const groups=new Map(selected.queries.map(query=>[key(query),{query,paths:[],proofs:[],valid:true}]));
      for(const [path,row] of Object.entries(lock.packages)){
        if(path==='')continue;const match=buildPackageQueries({lockfileVersion:lock.lockfileVersion,packages:{[path]:row}},{approvedPublicPackages:approved}).queries[0];
        if(match)groups.get(key(match)).paths.push(path);
      }
      for(const group of groups.values()){
        for(const path of group.paths){
          check(signal);try{const proof=await readMetadata(directory,join(directory,...installedPath(path),'package.json'),1048576,signal),metadata=json(proof.bytes);if(!plain(metadata)||metadata.name!==group.query.package.name||metadata.version!==group.query.version||metadata.private===true)throw Error('installation mismatch');const {bytes,...record}=proof;group.proofs.push(record);}catch{check(signal);group.valid=false;}
        }
      }
      await currentFile(directory,lockProof,2097152,signal);
      for(const group of groups.values())if(group.valid)try{for(const proof of group.proofs)await currentFile(directory,proof,1048576,signal);}catch{check(signal);group.valid=false;}
      await currentFile(directory,lockProof,2097152,signal);
      check(signal);const proven=[...groups.values()].filter(group=>group.valid&&group.proofs.length===group.paths.length&&group.paths.length>0);
      if(proven.length){
        const response=await client.lookupPackages(proven.map(group=>structuredClone(group.query)),{signal});check(signal);
        if(Array.isArray(response)&&response.length===proven.length){const resultMap=new Map(proven.map((group,i)=>[key(group.query),publicResult(response[i],group.query,checkedAt)]));packages=selected.queries.map(query=>resultMap.get(key(query))??unknown(query,checkedAt));}
      }
      // Preserve received findings, but revoke any clean/current assertion if the source changed.
      await currentFile(directory,lockProof,2097152,signal);
      for(const group of proven)for(const proof of group.proofs)await currentFile(directory,proof,1048576,signal);
      await currentFile(directory,lockProof,2097152,signal);
      check(signal);return {status:packages.some(row=>row.status==='unverifiable')?'partial':'complete',lockfileVersion:selected.lockfileVersion,lockfileHash:selected.lockfileHash,excluded:selected.excluded,checkedAt,packages};
    };
    try{return await Promise.race([work().catch(()=>partial()),stopped]);}
    finally{clearTimeout(timer);externalSignal?.removeEventListener('abort',cancel);controller.abort();}
  }});
}
