#!/usr/bin/env python3
"""Mini WebDAV server for CyberGate (native python, stdlib only).
Serves the phone's shared storage over WebDAV. Configure via env vars:
  CYBERGATE_WEBDAV_PORT (default 58080), CYBERGATE_WEBDAV_ROOT (default /sdcard)."""
import os, sys, html, urllib.parse, socketserver, shutil
from http.server import BaseHTTPRequestHandler

ROOT = os.environ.get("CYBERGATE_WEBDAV_ROOT", "/sdcard")
PORT = int(os.environ.get("CYBERGATE_WEBDAV_PORT", "58080"))

def _size_fmt(n):
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

class DavHandler(BaseHTTPRequestHandler):
    def _safe_path(self, rel):
        rel = urllib.parse.unquote(rel)
        p = os.path.normpath(os.path.join(ROOT, rel.lstrip("/")))
        if not (p == ROOT or p.startswith(ROOT + os.sep)):
            return None
        return p

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("DAV", "1,2")
        self.end_headers()
        if body: self.wfile.write(body)

    def _listing(self, path, rel):
        rows = []
        try:
            entries = sorted(os.listdir(path), key=str.lower)
        except PermissionError:
            entries = []
        if rel.strip("/"):
            rows.append('<tr><td>📁 ..</td><td></td><td><a href="{u}">上级目录</a></td></tr>'.format(
                u="/" + os.path.dirname(rel.strip("/")).strip("/")))
        for name in entries:
            full = os.path.join(path, name)
            r = urllib.parse.quote(f"/{rel.strip('/')}/{name}".replace("//", "/"))
            if os.path.isdir(full):
                rows.append(f'<tr><td>📁 <a href="{r}/">{html.escape(name)}/</a></td><td>目录</td><td><a href="{r}" onclick="del(this.href);return false">删除</a></td></tr>')
            else:
                sz = os.path.getsize(full)
                rows.append(f'<tr><td>📄 <a href="{r}">{html.escape(name)}</a></td>'
                            f'<td>{_size_fmt(sz)}</td>'
                            f'<td><a href="{r}" onclick="del(this.href);return false">删除</a></td></tr>')
        rel_disp = "/" + rel.strip("/") if rel.strip("/") else "/"
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>CyberGate 网盘 {html.escape(rel_disp)}</title><style>
body{{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0;padding:20px}}
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td{{padding:8px;border-bottom:1px solid #21262d}}
h1{{font-size:20px}} .bar{{background:#161b22;padding:14px;border-radius:10px}}
input{{background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:6px}}
button{{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:6px 14px}}
td a.del{{color:#f85149}}
</style><script>function del(u){{if(confirm("确认删除?")){{var x=new XMLHttpRequest();x.open("DELETE",u);x.onload=()=>location.reload();x.send();}}}}</script>
</head><body><div class="bar"><h1>💾 CyberGate 网盘 {html.escape(rel_disp)}</h1>
<form method="POST" enctype="multipart/form-data" action="{rel_disp}">
<input type="file" name="f" required><button>上传到当前目录</button></form></div>
<table><tr><th>名称</th><th>大小</th><th>操作</th></tr>{''.join(rows)}</table></body></html>"""

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("DAV", "1,2")
        self.send_header("Allow", "GET,PUT,DELETE,PROPFIND,MKCOL,OPTIONS,MOVE,COPY")
        self.end_headers()

    def do_PROPFIND(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None or not os.path.exists(p):
            return self._send(404, b"not found")
        self._send(207, b"", "text/xml")

    def do_MKCOL(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None: return self._send(403, b"forbidden")
        try: os.makedirs(p, exist_ok=True); self._send(201, b"created")
        except Exception as e: self._send(500, str(e).encode())

    def do_DELETE(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None or p == ROOT: return self._send(403, b"forbidden")
        try:
            if os.path.isdir(p): shutil.rmtree(p)
            else: os.remove(p)
            self._send(204, b"deleted")
        except Exception as e: self._send(500, str(e).encode())

    def do_GET(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None: return self._send(403, b"forbidden")
        if os.path.isdir(p):
            rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
            self._send(200, self._listing(p, rel).encode("utf-8"))
        elif os.path.isfile(p):
            try:
                with open(p, "rb") as f: data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(p)}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e: self._send(500, str(e).encode())
        else: self._send(404, b"not found")

    def do_PUT(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None: return self._send(403, b"forbidden")
        try:
            length = int(self.headers.get("Content-Length", 0))
            with open(p, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk: break
                    f.write(chunk); remaining -= len(chunk)
            self._send(201, b"created")
        except Exception as e: self._send(500, str(e).encode())

    def do_POST(self):
        # multipart 上传（浏览器表单）
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None: return self._send(403, b"forbidden")
        try:
            ctype = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            import re
            m = re.search(rb'filename="([^"]+)"', body)
            if m:
                fname = m.group(1).decode("utf-8", errors="replace")
                start = body.find(b"\r\n\r\n") + 4
                end = body.rfind(b"\r\n--")
                data = body[start:end]
                with open(os.path.join(p, fname), "wb") as f: f.write(data)
            self.send_response(303)
            self.send_header("Location", self.path)
            self.end_headers()
        except Exception as e: self._send(500, str(e).encode())

    def log_message(self, *a): pass

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    print(f"WebDAV serving {ROOT} on :{PORT}")
    Server(("0.0.0.0", PORT), DavHandler).serve_forever()
