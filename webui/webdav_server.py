#!/usr/bin/env python3
"""Mini WebDAV server for CyberGate (native python, stdlib only).
Serves the phone's shared storage over WebDAV. Configure via env vars:
  CYBERGATE_WEBDAV_PORT (default 58080), CYBERGATE_WEBDAV_ROOT (default /sdcard)."""
import os
import re
import html
import shutil
import socketserver
import urllib.parse
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler
from xml.sax.saxutils import escape as xml_escape

ROOT = os.path.abspath(os.environ.get("CYBERGATE_WEBDAV_ROOT", "/sdcard"))
PORT = int(os.environ.get("CYBERGATE_WEBDAV_PORT", "58080"))
CHUNK_SIZE = 65536


def _size_fmt(n):
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


class DavHandler(BaseHTTPRequestHandler):
    def _safe_path(self, rel):
        rel = urllib.parse.unquote(rel)
        p = os.path.abspath(os.path.join(ROOT, rel.lstrip("/")))
        if not (p == ROOT or p.startswith(ROOT + os.sep)):
            return None
        return p

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("DAV", "1,2")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _drain_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _listing(self, path, rel):
        rows = []
        try:
            entries = sorted(os.listdir(path), key=str.lower)
        except OSError:
            entries = []
        norm_rel = "" if rel in (".", "/") else rel.strip("/")
        if norm_rel:
            parent = "/" + os.path.dirname(norm_rel).strip("/")
            rows.append('<tr><td>📁 ..</td><td></td><td><a href="{u}">上级目录</a></td></tr>'.format(
                u=urllib.parse.quote(parent if parent != "/" else "/")))
        for name in entries:
            full = os.path.join(path, name)
            r = urllib.parse.quote(f"/{norm_rel}/{name}".replace("//", "/"))
            if os.path.isdir(full):
                rows.append(
                    f'<tr><td>📁 <a href="{r}/">{html.escape(name)}/</a></td><td>目录</td>'
                    f'<td><a class="del" href="{r}" onclick="del(this.href);return false">删除</a></td></tr>'
                )
            else:
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    sz = 0
                rows.append(
                    f'<tr><td>📄 <a href="{r}">{html.escape(name)}</a></td>'
                    f'<td>{_size_fmt(sz)}</td>'
                    f'<td><a class="del" href="{r}" onclick="del(this.href);return false">删除</a></td></tr>'
                )
        rel_disp = "/" + norm_rel if norm_rel else "/"
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
<form method="POST" enctype="multipart/form-data" action="{html.escape(rel_disp)}">
<input type="file" name="f" required><button>上传到当前目录</button></form></div>
<table><tr><th>名称</th><th>大小</th><th>操作</th></tr>{''.join(rows)}</table></body></html>"""

    def _propfind_response(self, fs_path, href_rel):
        is_dir = os.path.isdir(fs_path)
        try:
            st = os.stat(fs_path)
            mtime = formatdate(st.st_mtime, usegmt=True)
            size = st.st_size
        except OSError:
            mtime = formatdate(0, usegmt=True)
            size = 0

        clean_rel = "/" + href_rel.strip("/") if href_rel.strip("/") else "/"
        if is_dir and not clean_rel.endswith("/"):
            clean_rel += "/"
        href_quoted = urllib.parse.quote(clean_rel, safe="/")
        disp_name = "/" if clean_rel == "/" else os.path.basename(fs_path.rstrip(os.sep))

        if is_dir:
            res_type = "<D:resourcetype><D:collection/></D:resourcetype>"
            len_tag = ""
        else:
            res_type = "<D:resourcetype/>"
            len_tag = f"<D:getcontentlength>{size}</D:getcontentlength>"

        return (
            "<D:response>"
            f"<D:href>{xml_escape(href_quoted)}</D:href>"
            "<D:propstat>"
            "<D:prop>"
            f"<D:displayname>{xml_escape(disp_name)}</D:displayname>"
            f"{res_type}"
            f"{len_tag}"
            f"<D:getlastmodified>{xml_escape(mtime)}</D:getlastmodified>"
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>"
            "</D:response>"
        )

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("DAV", "1,2")
        self.send_header("Allow", "GET,HEAD,PUT,DELETE,PROPFIND,MKCOL,OPTIONS")
        self.end_headers()

    def do_HEAD(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(403, b"")
        if os.path.isdir(p):
            rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
            body = self._listing(p, rel).encode("utf-8")
            return self._send(200, body)
        if os.path.isfile(p):
            try:
                sz = os.path.getsize(p)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(p)}"')
                self.send_header("Content-Length", str(sz))
                self.send_header("DAV", "1,2")
                self.end_headers()
            except Exception as e:
                self._send(500, str(e).encode())
            return
        self._send(404, b"")

    def do_PROPFIND(self):
        self._drain_body()
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(403, b"forbidden", "text/plain; charset=utf-8")
        if not os.path.exists(p):
            return self._send(404, b"not found", "text/plain; charset=utf-8")

        depth = (self.headers.get("Depth") or "1").strip().lower()
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        if rel == ".":
            rel = ""

        responses = [self._propfind_response(p, rel)]
        if os.path.isdir(p) and depth != "0":
            try:
                entries = sorted(os.listdir(p), key=str.lower)
            except OSError:
                entries = []
            for name in entries:
                child_fs = os.path.join(p, name)
                child_rel = f"{rel}/{name}" if rel else name
                responses.append(self._propfind_response(child_fs, child_rel))

        xml_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<D:multistatus xmlns:D="DAV:">'
            + "".join(responses)
            + "</D:multistatus>"
        ).encode("utf-8")
        self._send(207, xml_body, "application/xml; charset=utf-8")

    def do_MKCOL(self):
        self._drain_body()
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(403, b"forbidden")
        try:
            os.makedirs(p, exist_ok=True)
            self._send(201, b"created")
        except Exception as e:
            self._send(500, str(e).encode())

    def do_DELETE(self):
        self._drain_body()
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None or p == ROOT:
            return self._send(403, b"forbidden")
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            self._send(204, b"")
        except FileNotFoundError:
            self._send(404, b"not found")
        except Exception as e:
            self._send(500, str(e).encode())

    def do_GET(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(403, b"forbidden")
        if os.path.isdir(p):
            rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
            self._send(200, self._listing(p, rel).encode("utf-8"))
        elif os.path.isfile(p):
            try:
                sz = os.path.getsize(p)
                with open(p, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(p)}"')
                    self.send_header("Content-Length", str(sz))
                    self.send_header("DAV", "1,2")
                    self.end_headers()
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                self._send(500, str(e).encode())
        else:
            self._send(404, b"not found")

    def do_PUT(self):
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None or p == ROOT or os.path.isdir(p):
            self._drain_body()
            return self._send(403, b"forbidden")
        try:
            length = int(self.headers.get("Content-Length", 0))
            parent = os.path.dirname(p)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(p, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
            self._send(201, b"created")
        except Exception as e:
            self._send(500, str(e).encode())

    def do_POST(self):
        # 流式 multipart 上传（防止大文件 OOM；严格 basename 过滤防路径穿越）
        p = self._safe_path(urllib.parse.urlparse(self.path).path)
        if p is None or not os.path.isdir(p):
            self._drain_body()
            return self._send(403, b"forbidden")
        try:
            ctype = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            m_b = re.search(r'boundary=([^\s;]+)', ctype, re.IGNORECASE)
            if not m_b or length <= 0:
                self._drain_body()
                return self._send(400, b"invalid multipart upload")

            boundary = m_b.group(1).strip('"')
            end_marker = b"\r\n--" + boundary.encode("latin-1")

            remaining = length
            header_buf = bytearray()
            header_end = -1
            while remaining > 0 and len(header_buf) < 65536:
                chunk = self.rfile.read(min(4096, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                header_buf.extend(chunk)
                idx = header_buf.find(b"\r\n\r\n")
                if idx != -1:
                    header_end = idx + 4
                    break

            if header_end == -1:
                while remaining > 0:
                    c = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not c:
                        break
                    remaining -= len(c)
                return self._send(400, b"malformed multipart headers")

            part_headers = bytes(header_buf[:header_end])
            m_fn = re.search(rb'filename="([^"]+)"', part_headers)
            if not m_fn:
                while remaining > 0:
                    c = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not c:
                        break
                    remaining -= len(c)
                return self._send(400, b"missing filename")

            raw_name = m_fn.group(1).decode("utf-8", errors="replace")
            safe_name = os.path.basename(raw_name.replace("\\", "/")).strip()
            if not safe_name or safe_name in (".", ".."):
                while remaining > 0:
                    c = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not c:
                        break
                    remaining -= len(c)
                return self._send(400, b"invalid filename")

            dest = os.path.abspath(os.path.join(p, safe_name))
            if not dest.startswith(p + os.sep) and not (p == ROOT and dest.startswith(ROOT + os.sep)):
                while remaining > 0:
                    c = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not c:
                        break
                    remaining -= len(c)
                return self._send(403, b"forbidden")

            tail_keep = len(end_marker)
            buf = bytearray(header_buf[header_end:])
            with open(dest, "wb") as f:
                while True:
                    pos = buf.find(end_marker)
                    if pos != -1:
                        if pos > 0:
                            f.write(buf[:pos])
                        break
                    if len(buf) > tail_keep:
                        flush_len = len(buf) - tail_keep
                        f.write(buf[:flush_len])
                        del buf[:flush_len]
                    if remaining <= 0:
                        if buf:
                            f.write(buf)
                        break
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        if buf:
                            f.write(buf)
                        break
                    remaining -= len(chunk)
                    buf.extend(chunk)

            # Drain trailing multipart footer if any
            while remaining > 0:
                c = self.rfile.read(min(CHUNK_SIZE, remaining))
                if not c:
                    break
                remaining -= len(c)

            self.send_response(303)
            self.send_header("Location", self.path)
            self.end_headers()
        except Exception as e:
            self._send(500, str(e).encode())

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    print(f"WebDAV serving {ROOT} on :{PORT}")
    Server(("0.0.0.0", PORT), DavHandler).serve_forever()
