/* ============ helpers ============ */
const $=i=>document.getElementById(i);
const e=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const api=async(path,body,method)=>{const o={method:method||(body===undefined?"GET":"POST"),headers:{},credentials:"same-origin"};
 if(body!==undefined){o.headers["Content-Type"]="application/json";o.body=JSON.stringify(body)}
 try{return await fetch("/api"+path,o)}catch(x){return null}};
const J=async r=>{try{return await r.json()}catch(x){return{}}};
const fmt=t=>{const d=new Date(t);return d.toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})+", "+d.toTimeString().slice(0,5)};
const tm=t=>new Date(t).toTimeString().slice(0,8);
const M=h=>$("modal").innerHTML=h?`<div class="modal"><div>${h}</div></div>`:"";
const EMAIL=/^\S+@\S+\.\S+$/;

/* ============ state + UI data ============ */
const NAV=[["home","🏠","Home"],["shares","🗂️","My Shares"],["audit","🛡️","Audit Logs"],["received","📥","Received"],["downloaded","⬇️","Downloaded"],["settings","⚙️","Settings"]];
const S={view:"home",me:null,data:[],st:null,stTok:null,mode:"in",file:null,link:null,qr:null,err:null,lerr:"",gerr:"",uerr:"",tv:""};
const pill=s=>`<span class="pill ${{"In use":"p-ok",Opened:"p-ok",Success:"p-ok",Expired:"p-bad",Denied:"p-bad",Failed:"p-bad",Revoked:"p-bad","Not opened":"p-warn"}[s]||"p-info"}">${e(s)}</span>`;
const table=(h,rows)=>`<div class="tbl"><table><tr>${h.map(x=>`<th>${x}</th>`).join("")}</tr>${rows.join("")||`<tr><td colspan="${h.length}">Nothing here yet.</td></tr>`}</table></div>`;
const head=(t,s)=>`<span class="status">Online</span><h1>${t}</h1><p class="sub">${s}</p>`;
const errBox=()=>S.err?`<div class="msg err"><b>${e(S.err.b)}</b><br>${e(S.err.s)}</div>`:"";

/* ============ Countdown Timer ============ */
let cdInt = null, stLast = 0;
async function fetchStatus(tk){
  const r = await api("/links/"+tk+"/status"); stLast = Date.now();
  if(r && r.ok){ const j = await J(r); if(S.stTok === tk) S.st = j; }
}
function updateCd(){
  const el = $("cd_text"); if(!el) return;
  const tk = tokOf($("tok").value.trim());
  if(!tk) { el.innerHTML = ""; return; }
  if(S.stTok !== tk){ S.stTok = tk; S.st = null; stLast = 0; }
  if(Date.now() - stLast > 10000){ stLast = Date.now(); fetchStatus(tk).then(updateCd); }
  const r = S.st; if(!r){ el.innerHTML = ""; return; }
  const bad = t => el.innerHTML = `<span class='pill p-bad'>${t}</span>`;
  if(r.state === "invalid") return bad("Invalid link");
  if(r.state === "revoked") return bad("Revoked");
  if(r.state === "locked") return bad("Locked (Too Many Failed Attempts)");
  if(r.state === "limit") return bad("Download Limit Reached");
  const left = r.expiry - Date.now();
  if(left <= 0 || r.state === "expired") return bad("Expired");
  const m = Math.floor(left/60000), s = Math.floor((left%60000)/1000);
  const dlRem = r.remaining === null ? "" : ` • ${r.remaining} dl left`;
  el.innerHTML = `<span class='pill p-warn'>🕒 Expires in ${m}m ${s}s${dlRem}</span>`;
}

/* ============ Live Camera Scanner ============ */
function startLiveCameraScan() {
  M(`
    <h2>📷 Live QR Scanner</h2>
    <p class="sub" style="margin-bottom:12px">Center the QR code inside the box</p>
    <div style="position:relative;width:100%;max-width:300px;height:300px;margin:0 auto;overflow:hidden;border-radius:16px;background:#000;">
      <video id="qrVideo" playsinline muted style="width:100%;height:100%;object-fit:cover;display:block;"></video>
      <div style="position:absolute;inset:40px;border:3px dashed #7d68ff;border-radius:12px;box-shadow:0 0 0 9999px rgba(0,0,0,0.4);pointer-events:none"></div>
    </div>
    <div class="row" style="justify-content:center;margin-top:16px;gap:10px">
      <button class="btn ghost" id="stopCameraBtn">Cancel</button>
    </div>
  `);

  const video = $("qrVideo");
  let stream = null;
  let animId = null;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    M("");
    S.err = { b: "Camera Unavailable", s: "Camera access requires HTTPS or is unsupported on this browser." };
    render();
    return;
  }

  navigator.mediaDevices.getUserMedia({ 
    video: { 
      facingMode: "environment",
      width: { ideal: 1280 },
      height: { ideal: 720 }
    } 
  })
    .then(s => {
      stream = s;
      video.srcObject = stream;
      video.play().then(() => {
        animId = requestAnimationFrame(scanFrame);
      });
    })
    .catch(err => {
      stopCamera();
      M("");
      S.err = { b: "Camera Access Denied", s: "Please allow camera permissions to use live scan." };
      render();
    });

  function scanFrame() {
    if (video && video.readyState === video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
      const scale = Math.min(1, 640 / video.videoWidth);
      canvas.width = video.videoWidth * scale;
      canvas.height = video.videoHeight * scale;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: "attemptBoth",
      });

      if (code && code.data) {
        stopCamera();
        M("");
        S.tv = code.data;
        if ($("tok")) $("tok").value = S.tv;
        updateCd();
        if ($("apin")) $("apin").focus();
        return;
      }
    }
    animId = requestAnimationFrame(scanFrame);
  }

  function stopCamera() {
    if (animId) cancelAnimationFrame(animId);
    if (stream) stream.getTracks().forEach(track => track.stop());
  }

  $("stopCameraBtn").onclick = () => { stopCamera(); M(""); };
}

/* ============ PHASE 4: receiver / decryption logic ============ */
const tokOf=v=>{
  if(!v) return null;
  const m = v.match(/token=([A-Za-z0-9]{6})/i);
  if (m) return m[1].toUpperCase();
  return /^[A-Za-z0-9]{6}$/.test(v.trim()) ? v.trim().toUpperCase() : null;
};

async function doAccess(t){
 const p=$("apin"),btn=$("dl");if(btn)btn.disabled=true;
 const r=await api("/links/"+t+"/download",{pin:p?p.value.trim():""});
 if(btn)btn.disabled=false;
 if(!r){S.err={b:"Network error",s:"Could not reach the server."};return render()}
 if(!r.ok){const j=await J(r);S.err={b:j.b||"Error",s:j.s||"Request failed."};return render()}
 const name=decodeURIComponent(r.headers.get("X-File-Name")||"download"),blob=await r.blob();
 const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(a.href),10000);
 S.err=null;fetchStatus(t);
 M(`<div class="tick">✓</div><h2>${e(name)}</h2><div class="sub">Decrypted and downloaded</div><div class="doc"><i style="width:60%"></i><i></i><i></i><i style="width:80%"></i></div><button class="btn" id="x">Close</button>`);
 $("x").onclick=()=>{M("");S.err=null;S.tv="";render()}}

/* ============ screens ============ */
const accessCard=()=>`<h2>⬇️ Access File</h2><div class="sub" style="margin:0 0 14px">Paste the link or scan a QR code to download and open the file.</div>
 <div class="row">
   <input type="text" id="tok" placeholder="Paste link here…" value="${e(S.tv)}" style="flex:1">
   <button class="btn ghost" id="btnScanQr" style="padding:11px 14px" title="Scan with Camera">📷</button>
   <button class="btn ghost" id="btnUploadQr" style="padding:11px 14px" title="Upload QR Image">📁</button>
   <input type="file" id="qrFileInput" accept="image/*" hidden>
 </div>
 <div id="cd_text" style="text-align:right;margin-top:6px;min-height:24px"></div>
 <input type="password" id="apin" inputmode="numeric" maxlength="4" placeholder="4-digit PIN" style="margin-top:4px">${errBox()}
 <button class="btn wide" id="dl" style="margin-top:12px">Download File</button>`;

const V={
login:()=>{const up=S.mode==="up";return`<div class="narrow card" style="max-width:420px;margin-top:6vh"><div class="center"><div class="tick">🔐</div><h2>${up?"Create account":"Welcome back"}</h2><div class="sub">${up?"Sign up to share files securely.":"Log in to share files securely."}</div></div>
 <label class="sub" for="em">Email</label><input type="email" id="em" autocomplete="email">
 <label class="sub" for="pw" style="display:block;margin-top:12px">Password</label><input type="password" id="pw" autocomplete="${up?"new-password":"current-password"}">
 ${up?`<label class="sub" for="pw2" style="display:block;margin-top:12px">Confirm password</label><input type="password" id="pw2" autocomplete="new-password">`:""}
 <button class="btn wide" id="auth" style="margin-top:16px">${up?"Sign up":"Log in"}</button>
 ${S.lerr?`<div class="msg err">${e(S.lerr)}</div>`:""}
 <p class="center sub" style="margin:14px 0 0"><a href="#" id="sw">${up?"Have an account? Log in":"Need an account? Sign up"}</a></p></div>`},
public:()=>`<div class="narrow" style="margin-top:4vh"><span class="status">Online</span><h1>Secure File</h1><p class="sub">Someone shared a protected file with you. Enter the PIN they gave you.</p><div class="card">${accessCard()}</div>
 <p class="center sub" style="margin-top:14px"><a href="#" id="toLogin">Log in or sign up</a> if the sender restricted this file to specific emails.</p></div>`,
home:()=>head("Share Files Securely","Encrypt your files and share them with a time-limited link. Your data, our priority.")+`
<div class="grid">
 <div class="card"><h2>☁️ Upload File</h2><div class="sub" style="margin:0">Choose a file to encrypt and share securely.</div>
  <div class="drop" id="drop"><div class="ic">📄</div><p><b>Drag &amp; drop your file here</b><br>or</p>
  <button class="btn" id="choose">Choose File</button><input type="file" id="f" hidden></div>
  <p class="center sub" style="margin:12px 0 0;font-size:13px">Supported: PDF, TXT, DOCX, Images (max 2MB)</p>${S.uerr?`<div class="msg err">${e(S.uerr)}</div>`:""}</div>
 <div class="card">${accessCard()}</div>
</div>`,

generate:()=>head("Generate Secure Share","Your file is ready. Set how long the link should work.")+`
<div class="narrow card">
 <div class="center"><div class="tick">✓</div><h2>Done</h2><div class="sub">${e(S.file.name)} selected</div></div>
 <label class="sub" for="exp">Expires in</label>
 <select id="exp"><option value="1">1 minute</option><option value="5">5 minutes</option><option value="10">10 minutes</option><option value="30" selected>30 minutes</option><option value="60">1 hour</option><option value="1440">24 hours</option></select>
 <label class="sub" for="maxDl" style="display:block;margin-top:12px">Allowed Downloads</label>
 <select id="maxDl"><option value="1">1 download</option><option value="2">2 downloads</option><option value="5">5 downloads</option><option value="10">10 downloads</option><option value="-1" selected>Unlimited</option></select>
 <label class="sub" for="pin" style="display:block;margin-top:12px">Secret PIN (4 digits)</label>
 <input type="password" id="pin" inputmode="numeric" maxlength="4" placeholder="e.g. 1234">
 <label class="sub" for="who" style="display:block;margin-top:12px">Who can open it (optional)</label>
 <input type="text" id="who" placeholder="asha@mail.com, ravi@mail.com">
 
 <div class="row" style="margin-top:16px">
   <button class="btn wide" id="genLink">🔗 Generate Link</button>
   <button class="btn wide" id="genQr">📱 Generate QR</button>
 </div>
 
 ${S.gerr?`<div class="msg err">${e(S.gerr)}</div>`:""}
 
 ${S.link?`<div class="linkbox"><b>✅ Link created successfully!</b>
  <div class="row" style="margin-top:10px"><input type="text" readonly value="${e(S.link)}" id="lk"><button class="btn ghost" id="cp">Copy</button></div>
  <div class="sub" style="margin:10px 0 0;font-size:13px">This link will expire in ${e(S.exp)}. Send the PIN separately.</div></div>`:""}
 
 ${S.qr?`<div class="linkbox center"><b>✅ QR Code created successfully!</b>
  <div style="margin:14px 0"><img id="qrImg" src="${e(S.qr)}" style="border-radius:10px;border:1px solid var(--line);max-width:100%"></div>
  <button class="btn ghost" id="dlQr">Download QR</button>
  <div class="sub" style="margin:10px 0 0;font-size:13px">This QR will expire in ${e(S.exp)}. Send the PIN separately.</div></div>`:""}
 
 <p class="center" style="margin:16px 0 0"><button class="btn ghost" id="back">Choose a different file</button></p>
</div>`,

shares:()=>head("My Shares","Files you uploaded and shared.")+`<div class="card">${table(["Time","File name","Downloads","Status"],S.data.map(r=>{
  const dlTxt = r.maxDownloads === -1 ? `${r.downloads} / ∞` : `${r.downloads} / ${r.maxDownloads}`;
  const acts = r.status === "In use" ? `<div class="act"><button class="dot">⋮</button><div class="menu"><button data-act="rev" data-tk="${r.token}" class="red">Revoke access</button><button data-act="exp" data-tk="${r.token}">Expire link</button></div></div>` : "";
  return `<tr><td>${fmt(r.created)}</td><td>${e(r.fileName)}</td><td>${dlTxt}</td><td>${pill(r.status)}${acts}</td></tr>`
 }))}</div>`,

audit:()=>{const R=S.data;
 return head("Audit Logs","Who opened your files, when, and who was allowed.")+`<div style="text-align:right;margin-bottom:14px"><button class="btn ghost" id="dlAudit">📥 Download CSV</button></div><div class="card">${table(["Time","File name","Opened by","Opened at","Allowed to open","Status"],R.map(r=>`<tr><td>${fmt(r.ts)}</td><td>${e(r.file)}<br><span class="mt">${e(r.action)}</span></td><td>${e(r.by)}</td><td>${r.acc?tm(r.ts):"—"}</td><td>${e(r.allowed)}</td><td>${pill(r.status)}</td></tr>`))}</div>`},
received:()=>head("Received","Files other people shared with you.")+`<div class="card">${table(["Time","File name","Status"],S.data.map(r=>`<tr><td>${fmt(r.ts)}</td><td>${e(r.n)}</td><td>${pill(r.st)}</td></tr>`))}</div>`,
downloaded:()=>head("Downloaded","Files saved from secure links.")+`<div class="card">${table(["File name","Time",""],S.data.map((r)=>`<tr><td>${e(r.n)}</td><td>${fmt(r.ts)}</td><td><button class="btn danger" data-del="${r.id}">Delete</button></td></tr>`))}</div>`,
settings:()=>head("Settings","Manage your profile and session.")+`<div class="card narrow" style="margin:0">
 <div class="row" style="gap:16px;padding-bottom:12px"><div class="av">${e(S.me[0].toUpperCase())}</div><div><h2 style="margin:0">${e(S.me.split("@")[0])}</h2><div class="sub" style="margin:0">${e(S.me)}</div></div></div>
 <div class="set"><span>Profile<br><small class="sub">Change your password</small></span><button class="btn ghost" id="edit">Edit profile</button></div>
 <div class="set"><span>Appearance<br><small class="sub">Switch between light and dark</small></span><button class="btn ghost" id="theme">Toggle theme</button></div>
 <div class="set" style="border:0"><span>Session<br><small class="sub">Sign out on this device</small></span><button class="btn danger" id="out">Log out</button></div></div>`};

/* ============ render + navigation ============ */
function nav(){$("nav").innerHTML=S.me?NAV.map(([k,i,l])=>`<button data-k="${k}" class="${(S.view===k||(k==="home"&&S.view==="generate"))?"on":""}"><span class="ic2">${i}</span>${l}</button>`).join(""):"";
 document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>go(b.dataset.k))}
async function load(v){
 const ep={shares:"/shares",audit:"/audit",received:"/received",downloaded:"/downloaded"}[v];S.data=[];if(!ep)return;
 const r=await api(ep);if(r&&r.status===401){S.me=null;return}
 if(r&&r.ok)S.data=await J(r)}
async function go(v){S.view=v;S.err=null;S.lerr="";S.uerr="";await load(v);render()}
function render(){
 if(!S.me&&S.view!=="public")S.view="login";else if(S.me&&(S.view==="login"||S.view==="public"))S.view="home";
 document.body.className=S.me?"":"pub"; // Hides sidebar on login page
 nav();$("main").innerHTML=V[S.view]();bind();$("main").scrollTop=0}

/* ============ event wiring ============ */
document.addEventListener("click", ev => {
  // Handle dropdown menus
  const isDot = ev.target.closest('.dot');
  document.querySelectorAll('.act.open').forEach(el => {
    if(!isDot || el !== isDot.closest('.act')) el.classList.remove('open');
  });
  if(isDot) isDot.closest('.act').classList.toggle('open');

  // Handle menu actions
  const btn = ev.target.closest('[data-act]');
  if(btn) {
    api("/shares/"+btn.dataset.tk+"/"+(btn.dataset.act === 'rev' ? "revoke" : "expire"), {}).then(() => go("shares"));
  }
});

function bind(){
 if($("sw"))$("sw").onclick=ev=>{ev.preventDefault();S.mode=S.mode==="up"?"in":"up";S.lerr="";render()};
 if($("toLogin"))$("toLogin").onclick=ev=>{ev.preventDefault();S.view="login";render()};
 if($("auth"))$("auth").onclick=async()=>{const em=$("em").value.trim().toLowerCase(),pw=$("pw").value,up=S.mode==="up";
  const fail=m=>{S.lerr=m;render()};
  if(!EMAIL.test(em))return fail("Enter a valid email address.");
  if(up){if(pw.length<8)return fail("Password must be at least 8 characters.");
   if(pw!==$("pw2").value)return fail("Passwords do not match.")}
  const r=await api(up?"/signup":"/login",{email:em,password:pw});
  if(!r)return fail("Could not reach the server.");
  const j=await J(r);if(!r.ok)return fail(j.s||"Something went wrong.");
  S.me=j.email;S.lerr="";go("home")};

 if($("tok")){
   $("tok").oninput=()=>{S.tv=$("tok").value;updateCd()};
   if(cdInt) clearInterval(cdInt);
   cdInt = setInterval(updateCd, 1000);
   updateCd();
   
   if(S.tv && tokOf(S.tv) && $("apin")) {
       setTimeout(() => $("apin").focus(), 100);
   }
 }

 if($("btnScanQr")) $("btnScanQr").onclick=()=>startLiveCameraScan();
 if($("btnUploadQr")) $("btnUploadQr").onclick=()=>{ if($("qrFileInput")) $("qrFileInput").click(); };

 if($("qrFileInput")){
   $("qrFileInput").onchange=ev=>{
     const file = ev.target.files[0];
     if(!file) return;
     const reader = new FileReader();
     reader.onload = e => {
       const img = new Image();
       img.onload = () => {
         const cvs = document.createElement("canvas");
         cvs.width = img.width; cvs.height = img.height;
         const ctx = cvs.getContext("2d");
         ctx.drawImage(img, 0, 0);
         const imgData = ctx.getImageData(0, 0, img.width, img.height);
         const code = jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "attemptBoth" });
         if(code && code.data){
           S.tv = code.data;
           if($("tok")) $("tok").value = S.tv;
           updateCd();
           if($("apin")) $("apin").focus();
         } else {
           S.err = {b:"QR Scan Failed", s:"No valid QR code was detected in the image."};
           render();
         }
       };
       img.src = e.target.result;
     };
     reader.readAsDataURL(file);
   };
 }

 if($("dl"))$("dl").onclick=()=>{S.tv=$("tok").value.trim();const t=tokOf(S.tv);
  if(!t){S.err={b:"Paste a valid link first.",s:"Access denied."};return render()}
  doAccess(t)};

 if($("choose")){const f=$("f"),d=$("drop");$("choose").onclick=()=>f.click();
  const pick=file=>{if(!file)return;
   if(file.size>2e6){S.uerr="That file is too large. The limit is 2MB.";return render()}
   S.file=file;S.link=null;S.qr=null;S.gerr="";go("generate")};
  f.onchange=()=>pick(f.files[0]);
  d.ondragover=ev=>{ev.preventDefault();d.classList.add("over")};d.ondragleave=()=>d.classList.remove("over");
  d.ondrop=ev=>{ev.preventDefault();pick(ev.dataTransfer.files[0])}}

 /* ============ PHASE 3: encryption logic ============ */
 if($("genLink") || $("genQr")){
  const generateShare = async (isQr) => {
   const pin=$("pin").value.trim(),bad=m=>{S.gerr=m;render()};
   if(!/^\d{4}$/.test(pin))return bad("PIN must be exactly 4 digits.");
   const who=$("who").value.split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
   if(who.some(x=>!EMAIL.test(x)))return bad("Check the email addresses in “Who can open it”.");
   const mins=+$("exp").value;S.exp=$("exp").selectedOptions[0].text;
   const maxDl=+$("maxDl").value;
   const btn=$(isQr?"genQr":"genLink");btn.disabled=true;
   try{
    const url=await new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok(r.result);r.onerror=no;r.readAsDataURL(S.file)});
    const r=await api("/shares",{name:S.file.name,mime:S.file.type,data:url.slice(url.indexOf(",")+1),pin,minutes:mins,maxDownloads:maxDl,allowed:who});
    if(!r){btn.disabled=false;return bad("Could not reach the server.")}
    const j=await J(r);if(!r.ok){btn.disabled=false;return bad(j.s||"Could not create the share.")}
    S.gerr="";S.link=isQr?null:j.link;S.qr=isQr?j.qr:null;render()
   }
   catch(err){btn.disabled=false;bad("Could not read this file.")}
  };

  if($("genLink")) $("genLink").onclick=()=>generateShare(false);
  if($("genQr")) $("genQr").onclick=()=>generateShare(true);
  $("back").onclick=()=>go("home");
  if($("cp"))$("cp").onclick=()=>{try{navigator.clipboard.writeText($("lk").value)}catch(x){$("lk").select()}$("cp").textContent="Copied"}
  if($("dlQr"))$("dlQr").onclick=()=>{const a=document.createElement("a");a.href=$("qrImg").src;a.download="Secure_File_QR.png";document.body.appendChild(a);a.click();a.remove()}
 }
 
  if($("dlAudit"))$("dlAudit").onclick=()=>{location.href="/api/audit.csv"};

 document.querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{await api("/downloaded/"+b.dataset.del,undefined,"DELETE");go("downloaded")});
 if($("theme"))$("theme").onclick=()=>{const r=document.documentElement,dark=getComputedStyle(r).getPropertyValue("--bg").trim()==="#151232";r.dataset.theme=dark?"light":"dark"};
 if($("edit"))$("edit").onclick=()=>{
  M(`<h2>Change password</h2><input type="password" id="c1" placeholder="Current password" style="margin:10px 0"><input type="password" id="c2" placeholder="New password (8+ characters)"><div id="cm"></div><div class="row" style="justify-content:center;margin-top:14px"><button class="btn ghost" id="cx">Cancel</button><button class="btn" id="cs">Save</button></div>`);
  $("cx").onclick=()=>M("");
  $("cs").onclick=async()=>{const n=$("c2").value,m=(c,t)=>$("cm").innerHTML=`<div class="msg ${c}">${t}</div>`;
   if(n.length<8)return m("err","New password must be at least 8 characters.");
   const r=await api("/password",{current:$("c1").value,next:n});if(!r)return m("err","Could not reach the server.");
   const j=await J(r);r.ok?m("ok","Password updated."):m("err",e(j.s||"Failed."))}};
 if($("out"))$("out").onclick=()=>{
  M(`<h2>Log out?</h2><p class="sub">You will need to sign in again to share files.</p><div class="row" style="justify-content:center"><button class="btn ghost" id="no">Stay signed in</button><button class="btn danger" id="yes">Log out</button></div>`);
  $("no").onclick=()=>M("");
  $("yes").onclick=async()=>{await api("/logout",{});S.me=null;
   M(`<div class="tick">👋</div><h2>You are logged out</h2><button class="btn" id="in">Sign in again</button>`);
   $("in").onclick=()=>{M("");go("home")}}}}

document.addEventListener("keydown",ev=>{if(ev.key==="Enter"&&!$("modal").innerHTML){const b=$("auth")||$("dl")||$("genLink")||$("genQr");if(b&&ev.target.tagName==="INPUT")b.click()}});

/* ============ start ============ */
(async function(){
  const t=new URLSearchParams(location.search).get("token");
  if(t)S.tv=window.location.href;
  const r=await api("/me");if(r&&r.ok)S.me=(await J(r)).email;
  S.view=S.me?"home":(t?"public":"login");
  render();
})();
