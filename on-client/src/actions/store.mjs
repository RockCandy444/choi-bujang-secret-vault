import {DatabaseSync} from 'node:sqlite';
import {lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';

const error=code=>Object.assign(new Error(code),{code});
export function existingDatabasePath(path){
  try{const stat=lstatSync(path);return typeof path==='string'&&isAbsolute(path)&&stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1;}catch{return false;}
}
const decode=row=>row?{...row,scope:JSON.parse(row.scope_json),command:JSON.parse(row.command_json),result:row.result_json?JSON.parse(row.result_json):null}:null;

/** Additive tables in the explicitly supplied existing application SQLite DB. No secret plaintext. */
export function createActionStore({databasePath}={}){
  if(!existingDatabasePath(databasePath))throw error('ACTION_UNSUPPORTED');
  const open=()=>{if(!existingDatabasePath(databasePath))throw error('ACTION_STORE_FAILED');const db=new DatabaseSync(databasePath);try{db.exec('PRAGMA busy_timeout=0; PRAGMA foreign_keys=ON');return db;}catch(err){db.close();throw err;}};
  const schema=db=>db.exec(`
    CREATE TABLE IF NOT EXISTS alekov_action_intents (
      request_id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE,
      scope_json TEXT NOT NULL, command_json TEXT NOT NULL,
      confirmation_hash TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alekov_action_state (
      request_id TEXT PRIMARY KEY REFERENCES alekov_action_intents(request_id),
      status TEXT NOT NULL CHECK(status IN ('prepared','reserved','pending','unknown','denied','succeeded','failed')),
      version INTEGER NOT NULL CHECK(version>0), confirmation_consumed INTEGER NOT NULL CHECK(confirmation_consumed IN(0,1)),
      dispatcher_id TEXT, result_json TEXT, updated_at_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alekov_action_audit (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL REFERENCES alekov_action_intents(request_id),
      version INTEGER NOT NULL, status TEXT NOT NULL, code TEXT NOT NULL, at_ms INTEGER NOT NULL, result_json TEXT,
      UNIQUE(request_id,version)
    );
    CREATE TRIGGER IF NOT EXISTS alekov_action_intents_no_update BEFORE UPDATE ON alekov_action_intents
      BEGIN SELECT RAISE(ABORT,'ACTION_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS alekov_action_intents_no_delete BEFORE DELETE ON alekov_action_intents
      BEGIN SELECT RAISE(ABORT,'ACTION_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS alekov_action_audit_no_update BEFORE UPDATE ON alekov_action_audit
      BEGIN SELECT RAISE(ABORT,'ACTION_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS alekov_action_audit_no_delete BEFORE DELETE ON alekov_action_audit
      BEGIN SELECT RAISE(ABORT,'ACTION_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS alekov_action_state_no_delete BEFORE DELETE ON alekov_action_state
      BEGIN SELECT RAISE(ABORT,'ACTION_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS alekov_action_state_monotonic BEFORE UPDATE ON alekov_action_state
      WHEN NEW.version!=OLD.version+1 BEGIN SELECT RAISE(ABORT,'ACTION_VERSION_INVALID'); END;
  `);
  const select=(db,id)=>decode(db.prepare('SELECT i.*,s.* FROM alekov_action_intents i JOIN alekov_action_state s USING(request_id) WHERE request_id=?').get(id));
  const transaction=fn=>{
    let db;
    try{db=open();db.exec('BEGIN IMMEDIATE');schema(db);const result=fn(db);db.exec('COMMIT');return result;}
    catch(err){if(db?.isTransaction)try{db.exec('ROLLBACK');}catch{}throw error(err?.code==='ACTION_CONFIRMATION_INVALID'||err?.code==='ACTION_CONFIRMATION_EXPIRED'?err.code:'ACTION_STORE_FAILED');}
    finally{db?.close();}
  };
  const audit=(db,id,version,status,code,at,result=null)=>db.prepare('INSERT INTO alekov_action_audit(request_id,version,status,code,at_ms,result_json) VALUES(?,?,?,?,?,?)').run(id,version,status,code,at,result?JSON.stringify(result):null);
  return Object.freeze({
    insert({requestId,receiptId,scope,command,confirmationHash,expiresAtMs,at}){
      return transaction(db=>{
        db.prepare('INSERT INTO alekov_action_intents VALUES(?,?,?,?,?,?,?)').run(requestId,receiptId,JSON.stringify(scope),JSON.stringify(command),confirmationHash,expiresAtMs,at);
        db.prepare("INSERT INTO alekov_action_state VALUES(?,'prepared',1,0,NULL,NULL,?)").run(requestId,at);
        audit(db,requestId,1,'prepared','ACTION_PREPARED',at);return select(db,requestId);
      });
    },
    get(requestId){
      let db;
      try{db=open();if(!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='alekov_action_intents'").get())return null;return select(db,requestId);}
      catch{throw error('ACTION_STORE_FAILED');}finally{db?.close();}
    },
    reserve({requestId,confirmationHash,dispatcherId,at}){
      return transaction(db=>{
        const row=select(db,requestId);
        if(!row||row.confirmation_hash!==confirmationHash)throw error('ACTION_CONFIRMATION_INVALID');
        if(row.confirmation_consumed)return {reserved:false,row};
        if(at>=row.expires_at_ms)throw error('ACTION_CONFIRMATION_EXPIRED');
        const version=row.version+1;
        const changed=db.prepare("UPDATE alekov_action_state SET status='reserved',version=?,confirmation_consumed=1,dispatcher_id=?,updated_at_ms=? WHERE request_id=? AND version=? AND confirmation_consumed=0 AND status='prepared'").run(version,dispatcherId,at,requestId,row.version);
        if(changed.changes!==1)return {reserved:false,row:select(db,requestId)};
        audit(db,requestId,version,'reserved','ACTION_DISPATCH_RESERVED',at);return {reserved:true,row:select(db,requestId)};
      });
    },
    transition({requestId,status,code,at,result=null,allowStates,expectedVersion}){
      return transaction(db=>{
        const row=select(db,requestId);if(!row||allowStates&&!allowStates.includes(row.status))return row;
        if(expectedVersion!==undefined&&row.version!==expectedVersion
          ||result?.observedAt&&row.result?.observedAt&&Date.parse(result.observedAt)<Date.parse(row.result.observedAt))return {...row,superseded:true};
        if(result?.observedAt&&row.result?.observedAt&&Date.parse(result.observedAt)===Date.parse(row.result.observedAt)
          &&(status!==row.status||result.effectApplied!==row.result.effectApplied))return {...row,superseded:true};
        const version=row.version+1;
        const changed=db.prepare('UPDATE alekov_action_state SET status=?,version=?,result_json=?,updated_at_ms=? WHERE request_id=? AND version=?').run(status,version,result?JSON.stringify(result):null,at,requestId,row.version);
        if(changed.changes!==1)throw error('ACTION_STORE_FAILED');
        audit(db,requestId,version,status,code,at,result);return select(db,requestId);
      });
    },
  });
}
