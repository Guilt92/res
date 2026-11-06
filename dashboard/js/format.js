/* Pure formatting helpers shared by the dashboard (no DOM, no state). */
"use strict";

export const pad = n => String(n).padStart(2, "0");

export function fmtClock(ms){ const d=new Date(ms); return pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds()); }

export function fmtAgo(secs){
  if (secs==null) return "never";
  if (secs < 60) return secs+"s ago";
  if (secs < 3600) return Math.floor(secs/60)+"m ago";
  if (secs < 86400) return Math.floor(secs/3600)+"h ago";
  return Math.floor(secs/86400)+"d ago";
}

export function fmtUptime(secs){
  const d=Math.floor(secs/86400), h=Math.floor(secs%86400/3600), m=Math.floor(secs%3600/60);
  if (d) return d+"d "+h+"h";
  if (h) return h+"h "+m+"m";
  return m+"m "+(secs%60)+"s";
}

export function rateClass(rate){
  if (rate == null) return "";
  if (rate >= 0.99) return "ok-num";
  if (rate >= 0.95) return "warn-num";
  return "bad-num";
}

export function fmtVal(v, unit){
  if (v==null || !isFinite(v)) return "N/A";
  if (unit==="B") return fmtBytes(v);
  const a = Math.abs(v);
  let s;
  if (unit==="%" || unit==="ms") s = a<10 ? v.toFixed(1) : v.toFixed(a<100?1:0);
  else if (unit==="qps") s = a<10 ? v.toFixed(1) : v.toFixed(0);
  else if (unit==="MB") s = v.toFixed(0);
  else s = a<10 ? v.toFixed(1) : v.toFixed(0);
  return s + (unit==="%" ? "%" : unit==="ms" ? "ms" : unit==="MB" ? "MB" : unit==="qps" ? "" : "");
}

export function fmtPct(v, digits){
  if (v==null || !isFinite(v)) return "N/A";
  return (v*100).toFixed(digits==null?1:digits)+"%";
}

export function fmtBytes(n){
  if (n==null || !isFinite(n)) return "N/A";
  if (n >= 1048576) return (n/1048576).toFixed(1)+" MB";
  if (n >= 1024) return (n/1024).toFixed(1)+" KB";
  return Math.round(n)+" B";
}

export function intOf(v){ return (v==null || !isFinite(v)) ? 0 : v; }

export function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

export function median(arr){
  if (!arr.length) return null;
  const a=[...arr].sort((x,y)=>x-y), m=Math.floor(a.length/2);
  return a.length%2 ? a[m] : (a[m-1]+a[m])/2;
}

export function lastVal(points){
  for (let i=points.length-1;i>=0;i--) if (points[i][1]!=null) return points[i][1];
  return null;
}

export function prevVal(points){
  let seen=false;
  for (let i=points.length-1;i>=0;i--){
    if (points[i][1]==null) continue;
    if (seen) return points[i][1];
    seen=true;
  }
  return null;
}

export function seriesFrom(payload, key){
  return (payload && payload.series && payload.series[key]) || [];
}

