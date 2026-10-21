/* Browser encryption + cross-origin Apps Script transport. No ChatGPT integration. */
const FamilyStore=(()=>{
  const TOKEN_KEY='family.device.v2';
  let rawKey=null,cryptoKey=null,people=[],volatileToken='';
  const encoder=new TextEncoder(),decoder=new TextDecoder();
  const b64=bytes=>{let s='';for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);return btoa(s);};
  const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  function token(){try{return localStorage.getItem(TOKEN_KEY)||volatileToken;}catch{return volatileToken;}}
  function setToken(value){volatileToken=value||'';try{value?localStorage.setItem(TOKEN_KEY,value):localStorage.removeItem(TOKEN_KEY);}catch{}}
  async function setKey(key){rawKey=key||null;cryptoKey=key?await crypto.subtle.importKey('raw',bytes(key),'AES-GCM',false,['encrypt','decrypt']):null;}
  async function encrypt(value,context){if(!cryptoKey)throw Error('금고의 열쇠를 다시 불러와 주세요.');const iv=crypto.getRandomValues(new Uint8Array(12));const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(context)},cryptoKey,encoder.encode(JSON.stringify(value)));return {v:1,iv:b64(iv),data:b64(data)};}
  async function decrypt(value,context){if(!cryptoKey)throw Error('금고의 열쇠를 다시 불러와 주세요.');try{return JSON.parse(decoder.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(value.iv),additionalData:encoder.encode(context)},cryptoKey,bytes(value.data))));}catch{throw Error('암호화된 내용을 열지 못했어요. 원본을 덮어쓰지 말고 관리자에게 알려 주세요.');}}
  async function call(scope,path,method='GET',data){
    const url=window.FAMILY_CONFIG?.apiUrl;
    if(!url||!/^https:\/\/script\.google\.com\/macros\/s\/[\w-]+\/exec$/.test(url))throw Error('구글 저장 서버의 배포 연결이 아직 완료되지 않았어요. 기존 금고 기록은 그대로 보관 중이에요.');
    let response;
    try{response=await fetch(url,{method:'POST',redirect:'follow',credentials:'omit',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify({scope,path,method,data,token:token()}),signal:AbortSignal.timeout(45000)});}catch{throw Error('구글 저장소에 연결하지 못했어요. 입력 내용은 화면에 남겨 두었어요. 연결을 확인한 뒤 다시 시도해 주세요.');}
    let result;try{result=await response.json();}catch{throw Error('구글 배포의 비로그인 접근 설정을 확인해야 해요.');}
    if(!response.ok||!result.ok){const error=Error(result.error||'구글 저장을 완료하지 못했어요.');error.status=result.status||response.status;if(error.status===401){setToken('');await setKey(null);}throw error;}
    return result.data;
  }
  async function proof(password,salt){
    if(typeof password!=='string'||password.length<8)throw Error('비밀번호는 8글자 이상으로 정해 주세요.');
    const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
    return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:bytes(salt),iterations:210000},key,256));
  }
  async function auth(path,method='GET',data){
    let body=data?{...data}:undefined;
    if(method==='POST'&&path==='login'){
      const status=await call('auth','status');people=status.people;
      const salt=people.find(x=>x.id===body.memberId)?.salt;
      if(!salt){const error=Error('이 가족의 비밀번호가 아직 등록되지 않았어요. 관리자에게 확인해 주세요.');error.status=401;throw error;}
      body.proof=await proof(body.password,salt);delete body.password;
    }else if((path==='setup'||path.startsWith('members/'))&&body?.password){
      body.salt=b64(crypto.getRandomValues(new Uint8Array(16)));body.proof=await proof(body.password,body.salt);delete body.password;
    }else if(body)delete body.password;
    const result=await call('auth',path,method,body);
    if(path==='status')people=result.people;
    if(result.token)setToken(result.token);
    if(result.dataKey)await setKey(result.dataKey);
    if(path==='logout'){setToken('');await setKey(null);}
    return result;
  }
  async function unpack(entry,detail=false){const value={...entry,...await decrypt(entry.meta,'entry.meta')};delete value.meta;if(detail)value.secret=await decrypt(entry.secret,'entry.secret');return value;}
  async function vault(path,method='GET',data){
    let body=data?{...data}:undefined;
    if((method==='POST'&&path==='entries')||(method==='PUT'&&/^entries\/[^/]+$/.test(path))){
      body.meta=await encrypt({title:body.title,username:body.username,note:body.note},'entry.meta');
      body.secret=await encrypt(body.secret||'','entry.secret');delete body.title;delete body.username;delete body.note;
    }
    const result=await call('vault',path,method,body);
    if(path==='state')return {...result,entries:await Promise.all(result.entries.map(x=>unpack(x))),trash:await Promise.all(result.trash.map(x=>unpack(x)))};
    if(method==='GET'&&/^entries\/[^/]+$/.test(path))return unpack(result,true);
    return result;
  }
  async function imagePayload(file){
    if(!['image/jpeg','image/png','image/webp','image/gif'].includes(file.type))throw Error('JPG·PNG·WebP·GIF 사진을 선택해 주세요.');
    if(file.size>20000000)throw Error('사진은 한 장에 20MB 이하로 선택해 주세요.');
    const bitmap=await createImageBitmap(file);const scale=Math.min(1,1600/Math.max(bitmap.width,bitmap.height));
    const canvas=document.createElement('canvas');canvas.width=Math.max(1,Math.round(bitmap.width*scale));canvas.height=Math.max(1,Math.round(bitmap.height*scale));
    const ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.drawImage(bitmap,0,0,canvas.width,canvas.height);bitmap.close();
    const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',0.88));if(!blob||blob.size>3000000)throw Error('사진 용량을 줄인 뒤 다시 선택해 주세요.');
    return JSON.stringify(await encrypt({mime:'image/jpeg',data:b64(await blob.arrayBuffer())},'photo'));
  }
  async function upload(id,revision,file){const payload=await imagePayload(file);return vault('entries/'+id+'/photos','POST',{revision,name:file.name,payload});}
  async function photo(id,photoId){const result=await vault('entries/'+id+'/photos/'+photoId);const value=await decrypt(JSON.parse(result.payload),'photo');if(value.mime!=='image/jpeg')throw Error('사진 형식을 확인해 주세요.');return URL.createObjectURL(new Blob([bytes(value.data)],{type:value.mime}));}
  async function exportVault(){
    const result=await vault('export');const entries=[];
    for(const x of result.entries){const entry=await unpack(x,true);const photos=[];for(const p of x.attachments||[]){if(p.removed)continue;const value=await vault('entries/'+x.id+'/photos/'+p.id);photos.push({name:p.name,...await decrypt(JSON.parse(value.payload),'photo')});}delete entry.attachments;entries.push({...entry,photos});}
    return {schema:2,exportedAt:result.exportedAt,folders:result.folders,entries};
  }
  return {auth,vault,upload,photo,exportVault};
})();
