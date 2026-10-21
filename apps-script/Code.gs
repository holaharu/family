/* family: Google Drive is the source of truth. No user data belongs in GitHub. */
const FAMILY_FOLDER_ID = '1dv88wcnwE5AKbr8ZeTuDawi9v82jcFJG';
const FAMILY_ORIGIN = 'https://holaharu.github.io';
const FAMILY_URL = FAMILY_ORIGIN + '/family/';
const PEOPLE = [{id:'mom',name:'엄마'},{id:'dad',name:'아빠'},{id:'haru',name:'나'},{id:'husband',name:'캥거루'}];
const CATEGORIES = ['계정·비밀번호','금융·보험','생활 정보','중요 메모'];
const SESSION_MS = 365 * 86400000;

// Run once, in the Apps Script editor, as momothebestdog@gmail.com.
function provisionFamily() {
  const lock=LockService.getScriptLock(); lock.waitLock(30000);
  try {
    const p=PropertiesService.getScriptProperties();
    const root=DriveApp.getFolderById(FAMILY_FOLDER_ID);
    if(!p.getProperty('STATE_FILE_ID')) {
      const at=new Date().toISOString();
      const data={schema:2,revision:1,createdAt:at,updatedAt:at,folders:PEOPLE.map((x,i)=>({...x,note:x.name+'의 중요한 정보',position:i,revision:1})),members:PEOPLE.map(x=>({...x,enabled:true,revision:1,credential:null})),entries:[],sessions:[],favorites:{},attempts:{}};
      const state=root.createFile('family-vault.json',JSON.stringify(data),MimeType.PLAIN_TEXT);
      p.setProperty('STATE_FILE_ID',state.getId());
      p.setProperty('PHOTOS_FOLDER_ID',root.createFolder('photos').getId());
      p.setProperty('BACKUPS_FOLDER_ID',root.createFolder('backups').getId());
      p.setProperty('PEPPER',random_());
      const raw=Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,random_());
      const key=Utilities.base64Encode(raw);
      p.setProperty('DATA_KEY',key);
      // Keep a recovery copy in the owner's private Drive, separate from GitHub.
      root.createFile('family-recovery-key.json',JSON.stringify({schema:2,algorithm:'AES-GCM',key:key,note:'개인 보관용 복구 키. 공개하거나 GitHub에 올리지 마세요.'}),MimeType.PLAIN_TEXT);
    }
    const db=load_();
    if(!db.members.find(x=>x.id==='haru').credential) {
      let setup=p.getProperty('SETUP_TOKEN');
      if(!setup){setup=random_();p.setProperties({SETUP_TOKEN:setup,SETUP_TOKEN_HASH:hash_(setup)});}
      console.log('최초 관리자 설정: '+FAMILY_URL+'#setup='+setup);
    }
    console.log('가족금고 전용 폴더: '+root.getUrl());
  } finally {lock.releaseLock();}
}

function doGet() {
  return json_({ok:true,data:{service:'family',version:'2.0.0',ready:!!PropertiesService.getScriptProperties().getProperty('STATE_FILE_ID')}});
}
function doPost(e) {
  let request;
  try {if(!e||!e.postData||e.postData.contents.length>5500000)fail_(413,'사진 크기가 너무 커요.');request=JSON.parse(e.postData.contents);} catch(err){return json_({ok:false,status:err.status||400,error:err.status?err.message:'요청 형식을 확인해 주세요.'});}
  return json_(rpc_(request));
}
function rpc_(request) {
  const lock=LockService.getScriptLock();
  if(!lock.tryLock(25000))return {ok:false,status:503,error:'다른 저장이 진행 중이에요. 잠시 후 다시 시도해 주세요.'};
  try {
    if(!PropertiesService.getScriptProperties().getProperty('STATE_FILE_ID'))fail_(503,'구글 저장소를 연결하는 중이에요.');
    const db=load_();const at=Date.now();let dirty=false;
    const mark=()=>{dirty=true;};
    const out=dispatch_(db,request,at,mark);
    if(dirty)save_(db);
    return {ok:true,data:out};
  } catch(err) {
    if(err.persistDb)save_(err.persistDb);
    return {ok:false,status:err.status||500,error:err.status?err.message:'구글 저장을 완료하지 못했어요. 새로고침 전에 다시 시도해 주세요.'};
  } finally {lock.releaseLock();}
}
function dispatch_(db,r,at,mark) {
  if(!r||typeof r.path!=='string'||r.path.length>250)fail_(400,'요청을 확인해 주세요.');
  const body=r.data||{},path=r.path,method=r.method||'GET';
  const props=PropertiesService.getScriptProperties();
  if(r.scope==='auth'&&path==='status'&&method==='GET') {
    const a=actorOptional_(db,r.token,at);
    return {setupNeeded:!db.members.find(x=>x.id==='haru').credential,authenticated:!!a,people:db.members.map(m=>({id:m.id,name:m.name,salt:m.credential?m.credential.salt:null})),dataKey:a?props.getProperty('DATA_KEY'):null};
  }
  if(r.scope==='auth'&&path==='setup'&&method==='POST') {
    const owner=db.members.find(x=>x.id==='haru');if(owner.credential)fail_(409,'이미 관리자 설정이 완료되었어요.');
    if(!equal_(hash_(String(body.token||'')),props.getProperty('SETUP_TOKEN_HASH')||''))fail_(403,'관리자 설정 링크를 확인해 주세요.');
    owner.credential=credential_(body);owner.revision++;mark();
    const session=newSession_(db,owner.id,body.deviceName,at);
    // Token is invalidated by the persisted owner credential, even if property deletion fails.
    return {token:session.token,dataKey:props.getProperty('DATA_KEY')};
  }
  if(r.scope==='auth'&&path==='login'&&method==='POST') {
    const id=String(body.memberId||'');const m=db.members.find(x=>x.id===id);if(!m)fail_(401,'이름과 비밀번호를 확인해 주세요.');
    const attempt=db.attempts[id]||{count:0,until:0};
    if(attempt.until>at)fail_(429,'입력이 여러 번 틀렸어요. 15분 뒤 다시 시도해 주세요.');
    if(!m.enabled||!m.credential||!equal_(hash_(String(body.proof||'')),m.credential.hash)) {
      const count=(attempt.until&&attempt.until<=at)?1:attempt.count+1;
      db.attempts[id]={count:count,until:count>=8?at+900000:0};
      const err=new Error('이름과 비밀번호를 확인해 주세요.');err.status=401;err.persistDb=db;throw err;
    }
    delete db.attempts[id];const session=newSession_(db,id,body.deviceName,at);mark();
    return {token:session.token,dataKey:props.getProperty('DATA_KEY')};
  }
  const actor=actorOptional_(db,r.token,at);if(!actor)fail_(401,'처음 한 번 가족 비밀번호를 입력해 주세요.');
  const admin=()=>{if(!actor.admin)fail_(403,'관리자만 수정할 수 있어요.');};
  const seg=path.split('/'),id=seg[1];
  const entry=(includeTrash=false)=>{const x=db.entries.find(x=>x.id===id);if(!x||(!includeTrash&&x.deletedAt)||(!actor.admin&&(!x.shared.includes(actor.id)||x.deletedAt)))fail_(404,'정보가 없거나 열람 권한이 없어요.');return x;};
  const rev=x=>{if(!Number.isInteger(body.revision)||x.revision!==body.revision)fail_(409,'다른 화면에서 변경된 정보예요. 새로 불러온 뒤 수정해 주세요.');};
  if(r.scope==='auth') {
    if(path==='logout'&&method==='POST'){db.sessions=db.sessions.filter(s=>s.id!==actor.session.id);mark();return {ok:true};}
    if(path==='devices'&&method==='GET')return {devices:db.sessions.filter(s=>s.expires>at&&(actor.admin||s.memberId===actor.id)).map(s=>({id:s.id,name:db.members.find(m=>m.id===s.memberId).name,deviceName:s.deviceName,createdAt:s.createdAt,lastSeen:s.lastSeen,current:s.id===actor.session.id}))};
    if(seg[0]==='devices'&&method==='DELETE') {
      const session=db.sessions.find(s=>s.id===id);if(!session||(!actor.admin&&session.memberId!==actor.id))fail_(404,'기기를 찾을 수 없어요.');
      db.sessions=db.sessions.filter(s=>s.id!==id);mark();return {current:id===actor.session.id};
    }
    if(seg[0]==='members') {
      admin();const m=db.members.find(x=>x.id===id);if(!m)fail_(404,'가족을 찾을 수 없어요.');
      if(method==='GET')return {id:m.id,name:m.name,enabled:m.enabled,revision:m.revision,configured:!!m.credential};
      if(method==='PUT') {
        rev(m);const reset=!!body.proof;m.name=text_(body.name,40,true);m.enabled=id==='haru'?true:body.enabled===true;m.revision++;
        if(reset)m.credential=credential_(body);else if(!m.credential)fail_(400,'첫 비밀번호를 정해 주세요.');
        if(reset||!m.enabled){db.sessions=db.sessions.filter(s=>s.memberId!==id||(id===actor.id&&s.id===actor.session.id));delete db.attempts[id];}
        mark();return {devicesReset:reset};
      }
    }
  } else if(r.scope==='vault') {
    if(path==='state'&&method==='GET') {
      if(at-new Date(actor.session.lastSeen).getTime()>86400000){actor.session.lastSeen=new Date(at).toISOString();actor.session.expires=at+SESSION_MS;mark();}
      const visible=db.entries.filter(x=>!x.deletedAt&&(actor.admin||x.shared.includes(actor.id)));
      const folderIds=visible.map(x=>x.folder);
      const list=x=>{const copy=Object.assign({},x);delete copy.secret;delete copy.attachments;copy.photoCount=(x.attachments||[]).filter(a=>!a.removed).length;copy.star=(db.favorites[actor.id]||[]).includes(x.id);return copy;};
      return {actor:{id:actor.id,name:actor.name,admin:actor.admin},folders:db.folders.filter(f=>actor.admin||folderIds.includes(f.id)),members:db.members.map(m=>({id:m.id,name:m.name,enabled:m.enabled,linked:!!m.credential,revision:m.revision})),entries:visible.map(list),trash:actor.admin?db.entries.filter(x=>x.deletedAt).map(list):[],serverTime:new Date(at).toISOString(),version:'2.0.0'};
    }
    if(seg[0]==='entries') {
      if(method==='GET'&&id&&!seg[2])return entry();
      if(method==='POST'&&!id) {
        admin();validEntry_(db,body);const stamp=new Date(at).toISOString();const x={id:random_(),folder:body.folder||'',meta:body.meta,secret:body.secret,category:body.category,shared:[...new Set(body.shared)],revision:1,createdAt:stamp,updatedAt:stamp,deletedAt:null,attachments:[]};db.entries.push(x);mark();return {id:x.id};
      }
      const x=entry(seg[2]==='restore'||(seg[2]==='photos'&&method==='GET'&&actor.admin));
      if(seg[2]==='favorite'&&method==='POST'){if(typeof body.star!=='boolean')fail_(400,'즐겨찾기를 확인해 주세요.');const ids=(db.favorites[actor.id]||[]).filter(v=>v!==id);if(body.star)ids.push(id);db.favorites[actor.id]=ids;mark();return {ok:true};}
      if(seg[2]==='photos') {
        if(seg[3]&&method==='GET') {
          const photo=(x.attachments||[]).find(p=>p.id===seg[3]&&!p.removed);if(!photo)fail_(404,'사진을 찾을 수 없어요.');
          return {id:photo.id,payload:DriveApp.getFileById(photo.fileId).getBlob().getDataAsString()};
        }
        admin();rev(x);
        if(method==='POST'&&!seg[3]) {
          if((x.attachments||[]).filter(p=>!p.removed).length>=10)fail_(400,'정보 하나에 사진은 10장까지 보관할 수 있어요.');
          const payload=text_(body.payload,5000000,true);let parsed;try{parsed=JSON.parse(payload);}catch(_){fail_(400,'사진 형식을 확인해 주세요.');}cipher_(parsed);
          const photoId=random_();const file=DriveApp.getFolderById(props.getProperty('PHOTOS_FOLDER_ID')).createFile(photoId+'.json',payload,MimeType.PLAIN_TEXT);
          (x.attachments||(x.attachments=[])).push({id:photoId,fileId:file.getId(),name:text_(body.name,150,true),createdAt:new Date(at).toISOString()});
        }else if(method==='DELETE'&&seg[3]) {
          const photo=x.attachments.find(p=>p.id===seg[3]&&!p.removed);if(!photo)fail_(404,'사진을 찾을 수 없어요.');photo.removed=new Date(at).toISOString();
        }else fail_(404,'요청한 사진 기능이 없어요.');
        x.revision++;x.updatedAt=new Date(at).toISOString();mark();return {ok:true,revision:x.revision};
      }
      admin();rev(x);
      if(method==='PUT'&&!seg[2]){validEntry_(db,body);Object.assign(x,{folder:body.folder||'',meta:body.meta,secret:body.secret,category:body.category,shared:[...new Set(body.shared)]});}
      else if(method==='DELETE'&&!seg[2])x.deletedAt=new Date(at).toISOString();
      else if(method==='POST'&&seg[2]==='restore')x.deletedAt=null;
      else fail_(404,'요청한 기능이 없어요.');
      x.revision++;x.updatedAt=new Date(at).toISOString();mark();return {ok:true};
    }
    if(seg[0]==='folders') {
      admin();
      if(method==='POST'&&!id){const f={id:random_(),name:text_(body.name,40,true),note:text_(body.note||'',300),position:db.folders.reduce((v,f)=>Math.max(v,f.position),-1)+1,revision:1};db.folders.push(f);mark();return {id:f.id};}
      const f=db.folders.find(x=>x.id===id);if(!f)fail_(404,'보관함이 없어요.');rev(f);
      if(method==='PUT'){f.name=text_(body.name,40,true);f.note=text_(body.note||'',300);f.revision++;}
      else if(method==='DELETE'){db.folders=db.folders.filter(x=>x.id!==id);db.entries.filter(x=>x.folder===id).forEach(x=>{x.folder='';x.revision++;});}
      else fail_(404,'요청한 기능이 없어요.');mark();return {ok:true};
    }
    if(path==='export'&&method==='GET'){admin();return {schema:2,folders:db.folders,entries:db.entries,exportedAt:new Date(at).toISOString()};}
  }
  fail_(404,'요청한 기능을 찾을 수 없어요.');
}
function validEntry_(db,b) {
  cipher_(b.meta);cipher_(b.secret);
  if(!CATEGORIES.includes(b.category))fail_(400,'분류를 확인해 주세요.');
  if(b.folder&&!db.folders.some(f=>f.id===b.folder))fail_(400,'보관함을 다시 선택해 주세요.');
  if(!Array.isArray(b.shared)||b.shared.some(id=>!['mom','dad','husband'].includes(id)))fail_(400,'함께 볼 가족을 확인해 주세요.');
}
function cipher_(v) {if(!v||v.v!==1||typeof v.iv!=='string'||!/^[A-Za-z0-9+/]{16}$/.test(v.iv)||typeof v.data!=='string'||v.data.length<24||v.data.length>5000000||!/^[A-Za-z0-9+/]+=*$/.test(v.data))fail_(400,'암호화된 저장 내용을 확인해 주세요.');}
function credential_(b) {
  if(typeof b.salt!=='string'||!/^[A-Za-z0-9+/]{22}==$/.test(b.salt)||typeof b.proof!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(b.proof))fail_(400,'비밀번호 등록 정보를 확인해 주세요.');
  return {salt:b.salt,hash:hash_(b.proof),algorithm:'PBKDF2-SHA256',iterations:210000};
}
function actorOptional_(db,token,at) {
  if(typeof token!=='string'||token.length<40||token.length>150)return null;
  const hash=hash_(token);const session=db.sessions.find(s=>equal_(s.hash,hash)&&s.expires>at);if(!session)return null;
  const member=db.members.find(m=>m.id===session.memberId&&m.enabled);return member?{id:member.id,name:member.name,admin:member.id==='haru',session:session}:null;
}
function newSession_(db,id,name,at) {const token=random_();db.sessions=db.sessions.filter(s=>s.expires>at);db.sessions.push({id:random_(),memberId:id,hash:hash_(token),deviceName:text_(name||'등록 기기',60),createdAt:new Date(at).toISOString(),lastSeen:new Date(at).toISOString(),expires:at+SESSION_MS});return {token:token};}
function load_() {const p=PropertiesService.getScriptProperties();return JSON.parse(DriveApp.getFileById(p.getProperty('STATE_FILE_ID')).getBlob().getDataAsString());}
function save_(db) {
  const p=PropertiesService.getScriptProperties(),file=DriveApp.getFileById(p.getProperty('STATE_FILE_ID'));
  // Copy the PREVIOUS committed state before changing the current state. Never purge old copies automatically.
  const folder=DriveApp.getFolderById(p.getProperty('BACKUPS_FOLDER_ID'));
  file.makeCopy('family-'+new Date().toISOString().replace(/[:.]/g,'-')+'-r'+db.revision+'.json',folder);
  db.revision++;db.updatedAt=new Date().toISOString();file.setContent(JSON.stringify(db));
  if(db.members.find(x=>x.id==='haru').credential){p.deleteProperty('SETUP_TOKEN');p.deleteProperty('SETUP_TOKEN_HASH');}
}
function text_(s,max,required){if(typeof s!=='string'||s.length>max||(required&&!s.trim()))fail_(400,'입력 길이와 내용을 확인해 주세요.');return s;}
function hash_(s){return Utilities.base64Encode(Utilities.computeHmacSha256Signature(s,PropertiesService.getScriptProperties().getProperty('PEPPER')||'unprovisioned'));}
function equal_(a,b){a=String(a);b=String(b);let diff=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)diff|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return diff===0;}
function random_(){return Utilities.getUuid().replace(/-/g,'')+Utilities.getUuid().replace(/-/g,'');}
function fail_(status,message){const e=new Error(message);e.status=status;throw e;}
function json_(data){return ContentService.createTextOutput(JSON.stringify(data)).setMimeType(ContentService.MimeType.JSON);}
