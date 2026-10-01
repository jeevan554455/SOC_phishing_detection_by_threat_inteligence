const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
function block(title,items){return `<div class="ioc"><h3>${esc(title)}</h3>${items?.length?items.map(x=>`<div>${esc(x)}</div>`).join(""):"<div>None detected</div>"}</div>`}
function vtHtml(v){
 if(v.status==="not_configured")return `<p class="warn">VirusTotal is not configured. Local detection still works. Add your own key to .env to enable reputation checks.</p>`;
 if(v.status==="error")return `<p class="bad">VirusTotal error: ${esc(v.message)}</p>`;
 let rows=[];
 for(const g of ["urls","ips","hashes"])(v[g]||[]).forEach(r=>{
   const cls=r.malicious>0?"bad":r.suspicious>0?"warn":"good";
   rows.push(`<div class="vtrow"><span>${esc(r.indicator)}</span><strong class="${cls}">${r.malicious} malicious / ${r.suspicious} suspicious</strong></div>`);
 });
 return rows.length?rows.join(""):"<p>No reputation record returned.</p>";
}
$("analyze").onclick=async()=>{
 const text=$("input").value.trim();if(!text)return;
 $("status").textContent="Analyzing...";
 try{
  const res=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
  const d=await res.json();if(!res.ok)throw Error(d.error||"Analysis failed");
  $("results").classList.remove("hidden");
  $("verdict").textContent=d.verdict;$("severity").textContent=d.severity;
  $("score").textContent=d.risk_score+"/100";
  const all=Object.values(d.iocs).flat();$("count").textContent=all.length;
  $("signals").innerHTML=(d.signals.length?d.signals:["No obvious phishing signals detected."]).map(x=>`<li>${esc(x)}</li>`).join("");
  $("iocs").innerHTML=block("URLs",d.iocs.urls)+block("IP addresses",d.iocs.ips)+block("Emails",d.iocs.emails)+block("SHA-256",d.iocs.sha256)+block("SHA-1",d.iocs.sha1)+block("MD5",d.iocs.md5)+block("Attachments",d.iocs.attachments);
  $("vt").innerHTML=vtHtml(d.virustotal);
  $("conclusion").textContent=`Local triage extracted ${all.length} IOC(s), calculated ${d.risk_score}/100 risk and classified the input as ${d.verdict}. Validate with SIEM/EDR/email telemetry before escalation or containment.`;
  $("status").textContent="Done";
 }catch(e){$("status").textContent=e.message}
};
