#!/usr/bin/env python3
"""v11 URL-Param binding + combo fuzz lab — webpack, ajax, axios styles"""

import json, subprocess, sys, threading, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"

class LabServer(ThreadingHTTPServer):
    def __init__(self, h): super().__init__(("127.0.0.1", 0), h); self.hits = []
    @property
    def url(self): return f"http://127.0.0.1:{self.server_address[1]}"

class BaseLabHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"
    def log_message(self, f, *a): return
    def record(self): self.server.hits.append((self.command, self.path))
    def s(self, st, b, ct="text/plain", ex=None):
        data = b if isinstance(b, bytes) else b.encode()
        self.send_response(st); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (ex or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def j(self, o, st=200): self.s(st, json.dumps(o, ensure_ascii=False), "application/json")
    def nf(self): self.s(404, b"not found")
    def do_POST(self): self.do_GET()

# ===== Target 1: Webpack SPA =====
class W1(BaseLabHandler):
    def do_GET(self):
        self.record(); p = urlparse(self.path); q = parse_qs(p.query)
        if p.path == "/": return self.s(200, '<!doctype html><html><head><title>SmartPark</title><link rel=preload href=/js/vendor.js as=script><link rel=preload href=/js/common.js as=script></head><body><div id=app></div><script src=/js/vendor.js></script><script src=/js/common.js></script><script src=/js/app.js></script></body></html>', "text/html")
        if p.path == "/js/vendor.js": return self.s(200, b"", "application/javascript")
        if p.path == "/js/common.js": return self.s(200, 'var api={baseURL:"/prod-api"};var request=function(o){return fetch(api.baseURL+o.url,{method:o.method||"GET",body:JSON.stringify(o.data),headers:o.headers})};', "application/javascript")
        if p.path == "/js/app.js": return self.s(200, '''var userApi={listUser:function(p){return request({url:"/user/list",method:"POST",data:{pageNum:p.pageNum||1,pageSize:p.pageSize||20,orgId:p.orgId,keyword:p.keyword}})},getUserDetail:function(id){return request({url:"/user/detail",data:{userId:id}})},exportUser:function(ids){return request({url:"/user/export",data:{ids:ids,format:"xlsx"}})}};
var deviceApi={listDevice:function(p){return fetch("/prod-api/device/list?"+new URLSearchParams({pageNum:p.pageNum||1,pageSize:p.pageSize||15,deviceType:p.deviceType}))},getStreamUrl:function(did,cid){return request({url:"/device/stream/play",data:{deviceId:did,channelId:cid,protocol:"rtsp"}})}};
var fileCenter={download:function(fid){window.open("/prod-api/fileCenter/download?fileId="+fid)},preview:function(ac){return request({url:"/fileCenter/preview",data:{assetCode:ac}})}};
window.__PROD_CONFIG__={"VUE_APP_BASE_API":"/prod-api"};''', "application/javascript")
        if p.path == "/prod-api/user/list":
            if q.get("pageNum"): return self.j({"code":0,"data":[{"userId":1,"userName":"ZhangSan","phone":"13800000001","orgId":101},{"userId":2,"userName":"LiSi","phone":"13900000002","orgId":102}],"total":2})
            return self.j({"code":400,"msg":"pageNum required"})
        if p.path == "/prod-api/user/detail":
            if q.get("userId")==["1"]: return self.j({"code":0,"data":{"userId":1,"userName":"ZhangSan","phone":"13800000001","idCard":"320102199001011234","address":"Nanjing Gulou"}})
            return self.j({"code":400})
        if p.path == "/prod-api/user/export":
            if q.get("ids"): return self.s(200,b"%PDF-1.4\n"+b"0"*2048,"application/pdf",{"Content-Disposition":'attachment; filename="users.pdf"'})
            return self.j({"code":400})
        if p.path == "/prod-api/device/list": return self.j({"code":0,"data":[{"deviceId":1,"deviceName":"EastCamera","deviceType":"camera","status":1},{"deviceId":2,"deviceName":"WestGate","deviceType":"access","status":1}]})
        if p.path == "/prod-api/device/stream/play":
            if q.get("deviceId") and q.get("channelId"): return self.j({"code":0,"data":{"streamUrl":"rtsp://192.168.1.100:554/live/"+q["channelId"][0]}})
            return self.j({"code":400})
        if p.path == "/prod-api/fileCenter/download":
            if q.get("fileId")==["1001"]: return self.s(200,b"%PDF-1.4\n"+b"0"*4096,"application/pdf",{"Content-Disposition":'attachment; filename="report.pdf"'})
            return self.j({"code":400})
        if p.path == "/prod-api/fileCenter/preview":
            if q.get("assetCode"): return self.s(200,b"\x89PNG\r\n\x1a\n"+b"0"*1024,"image/png")
            return self.j({"code":400})
        return self.nf()

# ===== Target 2: jQuery Ajax =====
class W2(BaseLabHandler):
    def do_GET(self):
        self.record(); p = urlparse(self.path); q = parse_qs(p.query)
        if p.path == "/": return self.s(200, '<!doctype html><html><head><title>GovOA</title><script src=/js/jq.js></script><script src=/js/biz.js></script></head><body><div class=login-box><input name=username><input name=password type=password><button id=btn>Login</button></div></body></html>', "text/html")
        if p.path == "/js/jq.js": return self.s(200, b"", "application/javascript")
        if p.path == "/js/biz.js": return self.s(200, '''$(function(){$("#btn").click(function(){$.ajax({url:"/api/login",type:"POST",data:{username:$("input[name=username]").val(),password:$("input[name=password]").val(),captcha:""}})});});
function loadTree(orgId){$.get("/api/dept/tree",{orgId:orgId},function(r){console.log(r)});}
function searchStaff(kw,did,pn){$.ajax({url:"/api/staff/search",data:{keyword:kw,deptId:did,page:pn||1,size:20}});}
function dlFile(aid){window.location.href="/api/attach/download?id="+aid;}
function previewDoc(fp){$.post("/api/doc/preview",{path:fp,format:"html"});}''', "application/javascript")
        if p.path == "/api/staff/search": return self.j({"code":0,"data":{"total":45,"rows":[{"staffId":1,"name":"WangWu","deptId":201,"phone":"13700000003"}]}})
        if p.path == "/api/dept/tree": return self.j({"code":0,"data":[{"id":1,"name":"HQ","children":[{"id":201,"name":"Tech"}]}]})
        if p.path == "/api/attach/download":
            if q.get("id")==["9999"]: return self.s(200,b"PK\x03\x04"+b"0"*3072,"application/zip",{"Content-Disposition":'attachment; filename="archive.zip"'})
            return self.j({"code":400})
        if p.path == "/api/doc/preview":
            if q.get("path"): return self.s(200,b"%PDF-1.4\n"+b"0"*1024,"application/pdf")
            return self.j({"code":400})
        return self.nf()

# ===== Target 3: Axios SPA =====
class W3(BaseLabHandler):
    def do_GET(self):
        self.record(); p = urlparse(self.path); q = parse_qs(p.query)
        if p.path == "/": return self.s(200, '<!doctype html><html><head><title>DigitalGov</title><script src=/js/ax.js></script><script src=/js/build.js></script></head><body></body></html>', "text/html")
        if p.path == "/js/ax.js": return self.s(200, b"", "application/javascript")
        if p.path == "/js/build.js": return self.s(200, '''var http=axios.create({baseURL:"/api/v1",timeout:15000});
var api={queryUsers:function(p){return http.post("/users/page",{query:{name:p.name,status:p.status},pageable:{page:p.page||1,size:p.size||20,sort:"id,desc"}})},getUser:function(id){return http.get("/users/"+id)},exportUsers:function(f,fd){return http.post("/users/export",{filter:f,fields:fd,format:"xlsx"},{responseType:"blob"})},getDeviceList:function(p){return http.get("/devices",{params:{status:p.status,type:p.type,ownerId:p.ownerId,projectCode:p.projectCode}})},playRecord:function(did,st,et){return http.get("/records/playback",{params:{deviceId:did,start:st,end:et,stream:"main"}})}};''', "application/javascript")
        if p.path == "/api/v1/users/page":
            if q.get("page") and q.get("size"):
                return self.j({"code":200,"data":{"content":[{"id":1,"name":"ZhaoLiu","idCard":"320102198501012345","phone":"13800000004"}],"totalElements":1}})
            return self.j({"code":400,"msg":"page required"})
        if p.path == "/api/v1/users/1": return self.j({"code":200,"data":{"id":1,"name":"ZhaoLiu","idCard":"320102198501012345","phone":"13800000004","address":"Nanjing Xuanwu","bankCard":"6222021234567890"}})
        if p.path == "/api/v1/users/export":
            if q.get("filter"): return self.s(200,b"%PDF-1.4\n"+b"0"*4096,"application/pdf",{"Content-Disposition":'attachment; filename="users.pdf"'})
            return self.j({"code":400})
        if p.path == "/api/v1/devices": return self.j({"code":200,"data":[{"id":1,"name":"Camera01","status":"online","streamUrl":"rtsp://10.0.0.1/live"}]})
        if p.path == "/api/v1/records/playback":
            if q.get("deviceId"): return self.j({"code":200,"data":{"url":"rtsp://10.0.0.1:554/playback?start="+q.get("start",[""])[0]}})
            return self.j({"code":400})
        return self.nf()

# ===== Run =====
def ss(h): s=LabServer(h);t=threading.Thread(target=s.serve_forever,daemon=True);t.start();return s
def fl(r): return [fi for h in r.get("findings",[]) for fi in h.get("findings",[])]

def main():
    svrs = [ss(W1), ss(W2), ss(W3)]
    try:
        tgs = [{"url":s.url,"title":n,"score":100} for s,n in zip(svrs,["webpack","jquery","axios"])]
        with tempfile.TemporaryDirectory() as tmp:
            tf, od = Path(tmp)/"t.json", Path(tmp)/"out"
            tf.write_text(json.dumps(tgs), encoding="utf-8")
            proc = subprocess.run([sys.executable, str(SCANNER),"--input",str(tf),"--outdir",str(od),"--workers","8","--timeout","3","--no-proxy","--file-max-probes","4","--param-max-probes","12"],text=True,capture_output=True,timeout=120)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                raise SystemExit(proc.returncode)
            r = json.loads((od/"report.json").read_text(encoding="utf-8"))
            fs = fl(r)
            urls = {fi.get("url","") for fi in fs}
            data = [fi for fi in fs if fi.get("data_count") or fi.get("data_keys")]
            assert any("user" in u and ("list" in u or "page" in u) for u in urls), "user list missing"
            assert any("device" in u.lower() and "list" in u.lower() for u in urls), "device list missing"
            assert any("stream" in u.lower() or "play" in u.lower() for u in urls), "stream missing"
            assert any("/prod-api/user/list?" in u and "pageNum=1" in u and "pageSize=10" in u for u in urls), "bound combo for webpack user/list missing"
            assert any("/api/v1/users/page?" in u and "page=1" in u and "size=10" in u for u in urls), "bound combo for axios users/page missing"
            bad_values = ("/device/stream/play", "/user/detail", "/users/export")
            for u in urls:
                parsed = urlparse(u)
                values = [v for vals in parse_qs(parsed.query).values() for v in vals]
                assert not any(any(bad in value for bad in bad_values) for value in values), (
                    f"path seed leaked into query value: {u}"
                )
            print("LAB PASS")
            print(f"t={r.get('targets')} l={r.get('live')} v={r.get('vulnerable')} f={len(fs)} data={len(data)}")
            for fi in data[:10]:
                print(f"  {fi.get('method')} {fi.get('url','')[:80]}")
                if fi.get('data_keys'): print(f"    keys={fi['data_keys'][:5]}")
    finally:
        for s in svrs: s.shutdown(); s.server_close()

if __name__ == "__main__": main()
