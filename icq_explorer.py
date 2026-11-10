#!/usr/bin/env python3
r"""
ICQ Explorer - turns an ICQ New profile folder (...\ICQ\0001) into ONE self-contained
HTML file: all conversations, avatars, global search, date jump, export.

Usage:
    python icq_explorer.py                      (folder picker: choose ...\ICQ\0001)
    python icq_explorer.py "C:\\...\\ICQ\\0001"
    python icq_explorer.py path\\to\\_db6        (a single conversation)
Options:  --my-uin 123456789   --out file.html   --no-open
"""
import os, re, sys, json, base64, struct, hashlib, argparse, webbrowser

# ---------------------------------------------------------------- _db6 parsing
def parse_tlv(buf, s, e):
    out = []
    while s + 8 <= e:
        t, l = struct.unpack_from("<II", buf, s)
        if s + 8 + l > e:
            break
        out.append((t, buf[s + 8:s + 8 + l]))
        s += 8 + l
    return out

def read_records(data):
    """Yield (raw_payload, tlv_list) for every record whose header and footer agree."""
    p, n = 0, len(data)
    def valid(q):
        if q + 16 > n: return False
        a, b = struct.unpack_from("<II", data, q)
        if a != b or q + 16 + a > n: return False
        return struct.unpack_from("<II", data, q + 8 + a) == (a, a)
    while p + 8 <= n:
        if valid(p):
            a = struct.unpack_from("<I", data, p)[0]
            yield data[p + 8:p + 8 + a], parse_tlv(data, p + 8, p + 8 + a)
            p += 16 + a
            continue
        p += 1

def decode(data):
    msgs, seen = [], set()
    for raw, tl in read_records(data):
        h = hashlib.md5(raw).digest()
        dup = 1 if h in seen else 0      # byte-for-byte identical record stored twice
        seen.add(h)
        d = {}
        for t, v in tl:
            d.setdefault(t, v)
        text = d.get(5, b"").decode("utf-8", "replace")
        ts = struct.unpack_from("<I", d[3], 0)[0] if 3 in d and len(d[3]) >= 4 else 0
        flag = struct.unpack_from("<I", d[2], 0)[0] if 2 in d and len(d[2]) >= 4 else 0
        key = struct.unpack_from("<II", d[1], 0) if 1 in d and len(d[1]) >= 8 else None
        title, pv = "", {}
        if 53 in d:
            for t, v in parse_tlv(d[53], 0, len(d[53])):
                x = v.decode("utf-8", "replace") if t in (6, 8, 59, 60) else ""
                if t == 59: title = x
                elif t == 6: pv["u"] = x
                elif t == 8: pv["i"] = x
                elif t == 60: pv["d"] = x
        if text or title:
            msgs.append([ts, 1 if flag == 4 else 0, text, title, 0, pv, dup, key])   # [time, isMe, text, link title, attachments, raw preview, duplicate flag]
    msgs.sort(key=lambda m: m[0])
    return msgs

# ---------------------------------------------------------------- content.cache
def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def sniff(path):
    """Return 'image', 'video' or '' from the file's first bytes."""
    try:
        h = open(path, "rb").read(16)
    except OSError:
        return ""
    if h[:3] == b"\xff\xd8\xff" or h[:8] == b"\x89PNG\r\n\x1a\n" or h[:4] == b"GIF8" or h[:2] == b"BM" \
            or (h[:4] == b"RIFF" and h[8:12] == b"WEBP") or h[4:12] in (b"ftypavif", b"ftypavis"):
        return "image"
    if h[4:8] == b"ftyp" or h[:4] == b"\x1a\x45\xdf\xa3" or (h[:4] == b"RIFF" and h[8:12] == b"AVI "):
        return "video"
    return ""

def is_image(path):
    return sniff(path) == "image"

def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024

def all_strings(o):
    if isinstance(o, str): yield o
    elif isinstance(o, dict):
        for v in o.values(): yield from all_strings(v)
    elif isinstance(o, list):
        for v in o: yield from all_strings(v)

class Cache:
    """ICQ's content.cache: <md5(url)>lm.json = link/file metadata, <md5(url)>lp = link preview image,
    <md5(url)> = cached image. Matching is by md5 of the URL."""
    def __init__(self, folders, base, stickers=None):
        self.base, self.stickers = base, stickers
        self.dirs = [f for f in folders if f and os.path.isdir(f)]
        self.files, self.sizes, self.count = {}, {}, 0
        for folder in self.dirs:                    # first folder wins when a name exists in several
            for n in os.listdir(folder):
                fp = os.path.join(folder, n)
                self.count += 1
                self.files.setdefault(n, fp)
                if "." in n:
                    self.files.setdefault(n.rsplit(".", 1)[0], fp)
                if not n.endswith(".json"):
                    try: self.sizes.setdefault(os.path.getsize(fp), []).append(fp)
                    except OSError: pass
        self.by_md5 = {}
        self.used, self.stats = set(), dict(msgs=0, meta=0, img=0, files=0, unresolved=0)
        self.unresolved = []

    def rel(self, fp):
        """Path of a cached file as the HTML page should reference it."""
        try:
            return os.path.relpath(fp, self.base).replace("\\", "/")
        except ValueError:                           # different drive: use an absolute file:// URL
            import pathlib
            return pathlib.Path(os.path.abspath(fp)).as_uri()

    def img(self, url):
        for suf in ("lp", ""):
            for v in (url, url.rstrip("/")):
                n = md5(v) + suf
                f = self.files.get(n)
                if f and is_image(f):
                    self.used.add(n)
                    return f
        return ""

    def full_file(self, md5hex, size):
        """The downloaded original: its content md5 equals the 'md5' field in the file's JSON."""
        key = (md5hex, size)
        if key in self.by_md5:
            return self.by_md5[key]
        found = ""
        for fp in self.sizes.get(size, []):
            try:
                h = hashlib.md5()
                with open(fp, "rb") as fh:
                    for blk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(blk)
                if h.hexdigest() == md5hex:
                    found = fp; break
            except OSError:
                pass
        self.by_md5[key] = found
        return found

    def meta(self, url):
        for v in (url, url.rstrip("/")):
            f = self.files.get(md5(v) + "lm")
            if f and f.endswith(".json"):
                try:
                    self.used.add(md5(v) + "lm")
                    return json.load(open(f, encoding="utf-8"))
                except Exception:
                    pass
        return None

    def attach(self, m):
        text, pv = m[2], m[5]
        urls = list(dict.fromkeys(re.findall(r"https?://[^\s<>\"]+", text) + [pv.get("u", ""), pv.get("i", "")]))
        atts = []
        for u in [x for x in urls if x]:
            mm = re.search(r"files\.icq\.net/get/(\w+)$", u)
            if mm and self.stickers:
                sk = self.stickers.lookup(mm.group(1))
                if sk:
                    atts.append(sk); self.stats["stickers"] = self.stats.get("stickers", 0) + 1
                    continue
            meta = self.meta(u)
            extra = [u]
            a = {}
            if meta:
                info = (meta.get("result") or {}).get("info")
                doc = meta.get("doc")
                if info:
                    a = dict(k="file", t=info.get("file_name", ""), d=f"{human(info.get('file_size', 0))} \u00b7 {info.get('mime', '')}", u=info.get("dlink", ""))
                    fn = self.full_file(info.get("md5", ""), info.get("file_size", -1)) if info.get("md5") else ""
                    if fn:
                        kind = sniff(fn)
                        a["p"] = self.rel(fn)
                        a["k"] = "img" if kind == "image" else ("vid" if kind == "video" else "file")
                        if a["k"] == "img": a["t"], a["d"] = "", ""
                        self.stats["files"] += 1
                elif doc:
                    a = dict(k="link", t=doc.get("title", ""), d=doc.get("snippet", ""), u=meta.get("url") or u)
                extra += [x for x in all_strings(meta) if x.startswith("http")]
                self.stats["meta"] += 1
            for x in ([] if a.get("p") else extra):
                im = self.img(x)
                if im:
                    a = a or dict(k="img", u=u)
                    a["p"] = self.rel(im)
                    break
            if not a and "files.icq.net/get/" in u:
                self.stats["unresolved"] += 1
                self.unresolved.append(u)
            if a:
                atts.append(a)
        if not atts and pv.get("u"):
            atts.append(dict(k="link", t=m[3], d=pv.get("d", ""), u=pv["u"]))
        if atts:
            self.stats["msgs"] += 1
            self.stats["img"] += sum(1 for a in atts if a.get("p") and a["k"] == "img")
            m[4] = atts
        m.pop(5)
        return m

# ---------------------------------------------------------------- side files
def contact_name(folder):
    try:
        st = open(os.path.join(folder, "_ste6"), "rb").read()
        L = struct.unpack_from("<I", st, 0)[0]
        for t, v in parse_tlv(st, 8, 8 + L):
            if t == 12 and v:
                return v.decode("utf-8", "replace")
    except Exception:
        pass
    return ""

def contact_list_names(prof):
    names = {}
    try:
        j = json.load(open(os.path.join(prof, "contacts", "cache.cl"), encoding="utf-8"))
        for g in j.get("groups", []):
            for b in g.get("buddies", []):
                nm = b.get("friendly") or b.get("nick")
                if b.get("aimId") and nm:
                    names[str(b["aimId"])] = nm
    except Exception:
        pass
    return names

def avatar(avatars_dir, uin):
    d = os.path.join(avatars_dir, str(uin))
    if not os.path.isdir(d):
        return ""
    for f in sorted(os.listdir(d), key=lambda f: (f.lower() != "128.jpg", f)):
        mime = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif"}.get(os.path.splitext(f)[1].lower())
        if mime:
            return f"data:image/{mime};base64," + base64.b64encode(open(os.path.join(d, f), "rb").read()).decode()
    return ""

def guess_my_uin(folders, avatars_dir):
    from collections import Counter
    c = Counter()
    for fo in folders:
        uin = os.path.basename(fo)
        try:
            for m in set(re.findall(rb"(?<!\d)(\d{7,10})(?!\d)", open(os.path.join(fo, "_gc4"), "rb").read())):
                if m.decode() != uin:
                    c[m.decode()] += 1
        except OSError:
            pass
    return c.most_common(1)[0][0] if c else ""


def mark_repeats(msgs, W=4, MINLEN=40):
    """Flag (2) messages that belong to a run of W messages identical (sender + text) to an earlier run."""
    seen = {}
    n = len(msgs)
    for i in range(n - W + 1):
        win = msgs[i:i + W]
        key = tuple((m[1], m[2]) for m in win)
        if sum(len(k[1]) for k in key) < MINLEN or len(set(k[1] for k in key)) < 2:
            continue
        if key in seen and seen[key] + W <= i:
            for m in win:
                if not m[5]: m[5] = 2
        else:
            seen.setdefault(key, i)

def data_uri(path):
    ext = os.path.splitext(path)[1].lower()
    mime = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".webp": "webp"}.get(ext)
    return f"data:image/{mime};base64," + base64.b64encode(open(path, "rb").read()).decode() if mime else ""

class Stickers:
    """stickers\\meta.js lists the packs; stickers\\<stickerId>\\sticker.lottie is a cached animated sticker."""
    def __init__(self, folders):
        self.dirs = [f for f in ([folders] if isinstance(folders, str) else folders) if f and os.path.isdir(f)]
        self.sid2pack, self.packs, self.assets = {}, {}, {}
        for folder in self.dirs:
            try:
                raw = open(os.path.join(folder, "meta.js"), "rb").read().decode("utf-8", "replace").rstrip("\x00")
                for pk in json.loads(raw)["result"]["sticker_packs"]:
                    pid = str(pk["id"])
                    icon = ""
                    ic = os.path.join(folder, pid, "icons")
                    if os.path.isdir(ic):
                        for f in sorted(os.listdir(ic)):
                            icon = data_uri(os.path.join(ic, f))
                            if icon: break
                    if pid not in self.packs or (icon and not self.packs[pid]["i"]):
                        self.packs[pid] = dict(t=pk.get("title", ""), i=icon)
                    for sid in pk.get("stickers", []):
                        self.sid2pack.setdefault(sid, pid)
            except Exception:
                pass

    def lookup(self, sid):
        pid = self.sid2pack.get(sid)
        if sid not in self.assets:
            asset = None
            for base in self.dirs:
                d = os.path.join(base, sid)
                if asset or not os.path.isdir(d):
                    continue
                # best version first: animation, then the biggest still image
                rank = lambda f: (0 if f.lower().endswith((".lottie", ".json")) else
                                  {"xlarge": 1, "large": 2, "medium": 3}.get(os.path.splitext(f)[0].lower(), 5 if "small" in f.lower() else 4), f)
                for f in sorted(os.listdir(d), key=rank):
                    fp = os.path.join(d, f)
                    try:
                        if f.lower().endswith((".lottie", ".json")):
                            txt = open(fp, "rb").read().decode("utf-8")
                            json.loads(txt)
                            asset = dict(l=txt); break
                        uri = data_uri(fp)
                        if uri:
                            asset = dict(i=uri); break
                    except Exception:
                        pass
            self.assets[sid] = asset
        if pid or self.assets[sid]:
            return dict(k="stk", id=sid, g=pid or "")
        return None

CALL_TYPES = {}   # call type code -> label; the codes aren't known yet, so they are shown as numbers

def read_calls(prof):
    out = []
    try:
        d = open(os.path.join(prof, "calls", "call_log.cache"), "rb").read()
        L = struct.unpack_from("<I", d, 0)[0]
        for t, item in parse_tlv(d, 8, 8 + L):
            f = {}
            for t2, v in parse_tlv(item, 0, len(item)):
                if t2 == 9:
                    for t3, v3 in parse_tlv(v, 0, len(v)):
                        f[("n", t3)] = v3
                else:
                    f[t2] = v
            ts = struct.unpack_from("<I", f[3], 0)[0]
            uin = (f.get(92) or f.get(("n", 29)) or b"").decode("utf-8", "replace")
            typ = struct.unpack_from("<I", f[("n", 27)], 0)[0] if ("n", 27) in f else None
            out.append(dict(ts=ts, uin=uin, typ=typ, name=f.get(("n", 28), b"").decode("utf-8", "replace")))
    except Exception:
        pass
    return out

def read_me(prof):
    try:
        j = json.load(open(os.path.join(prof, "info", "cache"), encoding="utf-8"))["info"]
        return str(j.get("aimId", "")), j.get("friendly") or j.get("nick") or ""
    except Exception:
        return "", ""

def db_files(folder):
    """All message databases in a conversation folder, newest format first (_db6, _db5, _db4 ...)."""
    try:
        names = [f for f in os.listdir(folder) if re.fullmatch(r"_db\d+", f)]
    except OSError:
        return []
    return sorted(names, key=lambda f: -int(f[3:]))

def merge_into(dst, src):
    """Append src to dst. Messages already in dst (same time, sender and text) are flagged as duplicates,
    not dropped. Counting copies means genuinely repeated messages ('ok', 'ok') are not mistaken for duplicates."""
    from collections import Counter
    cnt = Counter((m[0], m[1], m[2]) for m in dst)
    dup = 0
    for m in src:
        k = (m[0], m[1], m[2])
        if cnt[k] > 0:
            cnt[k] -= 1
            if not m[5]: m[5] = 1
            dup += 1
    dst.extend(src)
    return dup

def read_reactions(folder):
    """_reactions_db1: {(a, ts): [[emoji, count], ...]}. Layout inferred from samples; attaches by tag-1 key."""
    out = {}
    try:
        d = open(os.path.join(folder, "_reactions_db1"), "rb").read()
        for raw, tl in read_records(d):
            key, lst = None, []
            for t, v in tl:
                if t == 1 and len(v) >= 8:
                    key = struct.unpack_from("<II", v, 0)
                elif t == 3:
                    f = dict(parse_tlv(v, 0, len(v)))
                    if 4 in f and 5 in f and len(f[5]) >= 4 and struct.unpack_from("<I", f[5], 0)[0] > 0:
                        lst.append([f[4].decode("utf-8", "replace"), struct.unpack_from("<I", f[5], 0)[0]])
            if key and lst:
                out[key] = lst
    except Exception:
        pass
    return out

def diagnose(data):
    """Structure-only summary of a _db6 (no message text): coverage, tag usage, sender flag values."""
    from collections import Counter
    covered = recs = 0
    tags, flags = Counter(), Counter()
    for raw, tl in read_records(data):
        recs += 1; covered += len(raw) + 16
        for t, v in tl:
            tags[t] += 1
            if t == 2 and len(v) >= 4:
                flags[struct.unpack_from("<I", v, 0)[0]] += 1
    return recs, covered, tags, flags

# ---------------------------------------------------------------- HTML
HTML = r'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ICQ Explorer</title>
<style>
:root{--bg:#f3f5f2;--panel:#fff;--ink:#1b2420;--mute:#6b776f;--line:#dfe5df;--green:#3e9b3a;--me:#d9f0d2;--them:#fff;--hl:#fff3a8;--side:#fbfcfa}
@media(prefers-color-scheme:dark){:root{--bg:#14181a;--panel:#1b2023;--ink:#e6ece8;--mute:#8a968f;--line:#2a3236;--green:#6cc462;--me:#27472a;--them:#242b2f;--hl:#5a5014;--side:#171c1e}}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{display:flex;font:15px/1.45 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink)}
button,input{font:inherit;color:inherit}
#side{width:320px;flex:none;background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
#side h1{font-size:17px;margin:0;padding:14px 16px 4px}
#side .sub{padding:0 16px 10px;color:var(--mute);font-size:13px}
#q{margin:0 12px 6px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
#opt{padding:0 14px 8px;color:var(--mute);font-size:13px;display:flex;gap:6px;align-items:center}
#list{overflow:auto;flex:1;min-height:0}
.c,.s{display:flex;gap:10px;padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--line);align-items:center}
.c:hover,.s:hover{background:var(--bg)} .c.on{background:var(--me)}
.c b{display:block}.c small,.s small{color:var(--mute)}
.s{display:block}.s mark{background:var(--hl);color:inherit}
.av{width:40px;height:40px;border-radius:50%;object-fit:cover;flex:none}
.ph{background:var(--green);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700}
#main{flex:1;display:flex;flex-direction:column;min-width:0}
#head{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
#head h2{margin:0;font-size:17px}#head .meta{color:var(--mute);font-size:13px}
#tools{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
#tools button,#tools input{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);cursor:pointer}
#tools button:hover{border-color:var(--green)}
#years{padding:6px 16px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;gap:6px;flex-wrap:wrap}
#years button{border:0;background:var(--bg);padding:3px 10px;border-radius:12px;cursor:pointer;color:var(--ink)}
#years button:hover{background:var(--green);color:#fff}
#wrap{position:relative;flex:1;min-height:0}
#chat{position:absolute;inset:0;overflow:auto;padding:12px 18px 24px}
#pill{position:absolute;top:8px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:2px 12px;font-size:12px;color:var(--mute);z-index:3;pointer-events:none}
.d{text-align:center;color:var(--mute);font-size:12px;margin:16px 0 6px}
.r{display:flex;gap:8px;align-items:flex-end;margin:3px 0}.r.me{flex-direction:row-reverse}
.r .av{width:30px;height:30px}
.m{max-width:min(70%,640px);padding:6px 11px;border-radius:12px;background:var(--them);border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere}
.me .m{background:var(--me);border-color:transparent}
.t{display:block;font-size:11px;color:var(--mute)}.p{display:block;font-size:12px;color:var(--green);font-style:italic}
.hl .m{outline:3px solid var(--hl)}
.m a{color:var(--green)}
.at{display:block;margin-top:6px;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);font-size:13px}
.at b{display:block}.at small{color:var(--mute);display:block}
.pv{display:block;max-width:100%;max-height:320px;border-radius:6px;margin-top:4px}
.stk{width:170px;height:170px;display:flex;align-items:center;justify-content:center;color:var(--mute);font-size:12px;text-align:center}
.stk img{max-width:100%;max-height:100%}
.rx{display:inline-block;margin:4px 4px 0 0;padding:1px 8px;border:1px solid var(--line);border-radius:12px;background:var(--bg);font-size:13px}
.r.sys{justify-content:center}.r.sys .m{background:transparent;border:1px dashed var(--line);color:var(--mute);font-size:13px;text-align:center}
#me{display:flex;gap:10px;align-items:center;padding:10px 14px;border-top:1px solid var(--line);background:var(--bg)}
#me .av{width:36px;height:36px}#me b{display:block;line-height:1.2}#me small{color:var(--mute)}
.more{display:block;margin:8px auto;padding:5px 14px;border:1px solid var(--line);border-radius:14px;background:var(--panel);cursor:pointer}
#empty{margin:auto;color:var(--mute);text-align:center;padding:40px}
@media(max-width:720px){#side{width:100%;position:absolute;inset:0;z-index:9}body.chat #side{display:none}}
</style>
<body>
<aside id="side">
  <h1>ICQ Explorer</h1><div class="sub" id="tot"></div>
  <input id="q" type="search" placeholder="Search all conversations" autocomplete="off">
  <label id="opt"><input type="checkbox" id="only"> only in the open chat</label>
  <div id="list"></div>
  <div id="me"></div>
</aside>
<section id="main">
  <div id="head" hidden>
    <img id="hav" class="av"><div><h2 id="hname"></h2><div class="meta" id="hmeta"></div></div>
    <div id="tools">
      <input type="date" id="jump" title="Jump to date">
      <button id="dup" title="Show or hide repeated messages">Duplicates</button>
      <button id="swap" title="Swap which side is you">Swap sides</button>
      <button id="exp">Export .txt</button>
    </div>
  </div>
  <div id="years" hidden></div>
  <div id="wrap"><div id="pill" hidden></div>
    <div id="chat"><div id="empty">Pick a conversation on the left, or search all of them.</div></div></div>
</section>
<script>
const DATA=__DATA__;
const $=s=>document.querySelector(s), CH=$('#chat');
const esc=s=>s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const norm=s=>s.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
const pad=n=>String(n).padStart(2,'0');
const dt=t=>new Date(t*1000);
const dayOf=t=>{const d=dt(t);return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())};
const tmOf=t=>{const d=dt(t);return pad(d.getHours())+':'+pad(d.getMinutes())};
const linkify=s=>esc(s).replace(/(https?:\/\/[^\s<]+)/g,'<a href="$1" target="_blank" rel="noopener">$1</a>');
const uinTxt=c=>c.uin+(c.alt?' + '+c.alt.join(' + '):'');
const initial=s=>esc((s||'?').trim().charAt(0).toUpperCase());
const swapKey=c=>'icqx-swap-'+c.uin;
let cur=-1,start=0,end=0,swapped=false,search=false;
let hideDup=localStorage.getItem('icqx-hidedup')!=='0';
function applyDup(){DATA.contacts.forEach(c=>{if(!c.all)c.all=c.msgs;c.msgs=hideDup?c.all.filter(m=>!m[5]):c.all;c.n=c.msgs.length})}
DATA.contacts.forEach(c=>{c.swap=localStorage.getItem(swapKey(c))==='1'});applyDup();
$('#me').innerHTML=(DATA.meAvatar?`<img class="av" src="${DATA.meAvatar}" alt="">`:`<div class="av ph">${esc((DATA.meName||DATA.meUin||'?').charAt(0).toUpperCase())}</div>`)+`<div><b>${esc(DATA.meName||'Me')}</b><small>${esc(DATA.meUin||'')}</small></div>`;
function dupLabel(){const c=DATA.contacts[cur],k=c?c.all.filter(m=>m[5]).length:0;$('#dup').textContent='Duplicates: '+(hideDup?'hidden':'shown')+' ('+k+')'}
$('#tot').textContent=DATA.contacts.length+' conversations \u00b7 '+DATA.contacts.reduce((a,c)=>a+c.n,0).toLocaleString()+' messages';

function av(src,name,cls){return src?`<img class="av ${cls||''}" src="${src}" alt="">`:`<div class="av ph ${cls||''}">${initial(name)}</div>`}
function listContacts(){
  $('#list').innerHTML=DATA.contacts.map((c,i)=>`<div class="c ${i===cur?'on':''}" data-i="${i}">${av(c.avatar,c.name||c.uin)}
   <div><b>${esc(c.name||c.uin)}</b><small>${uinTxt(c)} \u00b7 ${c.n.toLocaleString()} msgs \u00b7 ${c.n?dayOf(c.msgs[c.n-1][0]):''}</small></div></div>`).join('')}
function isMe(c,m){return c.swap?!m[1]:!!m[1]}
function msgHTML(c,i){
  const m=c.msgs[i],p=i?c.msgs[i-1]:null,day=dayOf(m[0]),me=isMe(c,m);
  let h=(!p||dayOf(p[0])!==day)?`<div class="d">${day}</div>`:'';
  const call=m[4]&&m[4][0]&&m[4][0].k==='call';
  if(call)return h+`<div class="r sys" data-i="${i}" data-day="${day}"><div class="m"><span class="t">${tmOf(m[0])}</span>${esc(m[4][0].t)}</div></div>`;
  const onlyStk=m[4]&&m[4].some(a=>a.k==='stk')&&/^https?:\/\/\S+$/.test(m[2].trim());
  h+=`<div class="r ${me?'me':'them'}" data-i="${i}" data-day="${day}">${me?av(DATA.meAvatar,'Me'):av(c.avatar,c.name||c.uin)}
   <div class="m"><span class="t">${tmOf(m[0])}${m[5]?' \u00b7 duplicate':''}</span>${onlyStk?'':linkify(m[2])}${m[4]?atHTML(c,m[4]):(m[3]?`<span class="p">${esc(m[3])}</span>`:'')}${m[6]?'<div>'+m[6].map(r=>`<span class="rx">${esc(r[0])} ${r[1]}</span>`).join('')+'</div>':''}</div></div>`;
  return h}
function atHTML(c,al){return al.map(a=>{
  if(a.k==='stk'){const pk=DATA.packs[a.g]||{},st=DATA.stk[a.id],ic=pk.i?`<img src="${pk.i}" alt="" style="width:32px;opacity:.8">`:'';
    return `<span class="stk" data-id="${esc(a.id)}">${st&&st.i?`<img src="${st.i}" alt="">`:`<span>${ic}<br>${st?'Animated sticker':'Sticker'}${pk.t?' \u00b7 '+esc(pk.t):''}${st?'':'<br>(not cached)'}</span>`}</span>`}
  const src=a.p?(a.p.startsWith('file:')?a.p:a.p.split('/').map(encodeURIComponent).join('/')):'',img=src?`<a href="${src}" target="_blank"><img class="pv" loading="lazy" src="${src}" alt=""></a>`:'';
  if(a.k==='img')return img;
  if(a.k==='vid'&&src)return `<span class="at"><b>${esc(a.t||'')}</b><small>${esc(a.d||'')}</small><video class="pv" controls preload="metadata" src="${src}"></video></span>`;
  if(a.k==='file'&&src)return `<span class="at"><b><a href="${src}" target="_blank">${esc(a.t||'file')}</a></b><small>${esc(a.d||'')}</small></span>`;
  const t=a.t?`<b>${a.u?`<a href="${esc(a.u)}" target="_blank" rel="noopener">${esc(a.t)}</a>`:esc(a.t)}</b>`:'';
  return `<span class="at">${t}${a.d?`<small>${esc(a.d.slice(0,220))}</small>`:''}${img}</span>`}).join('')}
let lotP=null;
function lottieLib(){if(window.lottie)return Promise.resolve(window.lottie);
  return lotP||(lotP=new Promise((ok,no)=>{const s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js';s.onload=()=>ok(window.lottie);s.onerror=()=>{lotP=null;no()};document.head.appendChild(s)}))}
const io=new IntersectionObserver(es=>es.forEach(e=>{if(!e.isIntersecting)return;const el=e.target;io.unobserve(el);
  const st=DATA.stk[el.dataset.id];if(!st||!st.l)return;
  lottieLib().then(L=>{el.innerHTML='';L.loadAnimation({container:el,renderer:'svg',loop:true,autoplay:true,animationData:JSON.parse(st.l)})})
   .catch(()=>{el.innerHTML='<span>Animated sticker<br>(needs internet once to load the player)</span>'})}),{rootMargin:'200px'});
function hydrate(){CH.querySelectorAll('.stk[data-id]:not([data-h])').forEach(el=>{el.dataset.h=1;io.observe(el)})}
function chunk(c,a,b){let h='';for(let i=a;i<b;i++)h+=msgHTML(c,i);return h}
function openChat(ci,idx){
  cur=ci;const c=DATA.contacts[ci];document.body.classList.add('chat');
  $('#head').hidden=false;$('#years').hidden=false;$('#pill').hidden=false;
  $('#hav').replaceWith(Object.assign(document.createElement('div'),{id:'hav'}));
  $('#hav').outerHTML=av(c.avatar,c.name||c.uin).replace('class="av','id="hav" class="av');
  $('#hname').textContent=c.name||c.uin;
  $('#hmeta').textContent=uinTxt(c)+' \u00b7 '+c.n.toLocaleString()+' messages \u00b7 '+(c.n?dayOf(c.msgs[0][0])+' to '+dayOf(c.msgs[c.n-1][0]):'');
  const yrs=[...new Set(c.msgs.map(m=>dt(m[0]).getFullYear()))];
  $('#years').innerHTML=yrs.map(y=>`<button data-y="${y}">${y}</button>`).join('');
  const at=idx==null?Math.max(0,c.n-250):Math.max(0,idx-120);
  start=at;end=Math.min(c.n,at+300);
  CH.innerHTML=(start>0?'<button class="more" id="up">Load earlier</button>':'')+chunk(c,start,end)+(end<c.n?'<button class="more" id="dn">Load later</button>':'');
  if(idx!=null){const e=CH.querySelector(`[data-i="${idx}"]`);if(e){e.classList.add('hl');e.scrollIntoView({block:'center'})}}else CH.scrollTop=CH.scrollHeight;
  listContacts();dupLabel();pill();hydrate()}
function more(dir){
  const c=DATA.contacts[cur];if(cur<0)return;
  if(dir<0&&start>0){const a=Math.max(0,start-200),old=CH.scrollHeight;
    $('#up')?.remove();CH.insertAdjacentHTML('afterbegin',(a>0?'<button class="more" id="up">Load earlier</button>':'')+chunk(c,a,start));
    CH.scrollTop+=CH.scrollHeight-old;start=a;hydrate();
    const f=CH.querySelector(`.r[data-i="${start+ (0)}"]`)}
  if(dir>0&&end<c.n){const b=Math.min(c.n,end+200);$('#dn')?.remove();
    CH.insertAdjacentHTML('beforeend',chunk(c,end,b)+(b<c.n?'<button class="more" id="dn">Load later</button>':''));end=b;hydrate()}}
function pill(){const r=document.elementFromPoint(CH.getBoundingClientRect().left+60,CH.getBoundingClientRect().top+40)?.closest('.r');
  if(r)$('#pill').textContent=r.dataset.day}
CH.addEventListener('scroll',()=>{pill();if(CH.scrollTop<250)more(-1);if(CH.scrollHeight-CH.scrollTop-CH.clientHeight<250)more(1)});
CH.addEventListener('click',e=>{if(e.target.id==='up')more(-1);if(e.target.id==='dn')more(1)});
$('#list').addEventListener('click',e=>{
  const c=e.target.closest('.c'),s=e.target.closest('.s');
  if(c)openChat(+c.dataset.i);if(s)openChat(+s.dataset.c,+s.dataset.i)});
$('#years').addEventListener('click',e=>{const y=e.target.dataset.y;if(!y)return;
  const c=DATA.contacts[cur],t=new Date(+y,0,1)/1000;jumpTo(c,t)});
function jumpTo(c,t){let lo=0,hi=c.n;while(lo<hi){const m=(lo+hi)>>1;c.msgs[m][0]<t?lo=m+1:hi=m}openChat(cur,Math.min(lo,c.n-1))}
$('#jump').addEventListener('change',e=>{if(e.target.value&&cur>=0)jumpTo(DATA.contacts[cur],new Date(e.target.value+'T00:00:00')/1000)});
$('#dup').onclick=()=>{if(cur<0)return;const c=DATA.contacts[cur],r=CH.querySelector('.r'),t=r?c.msgs[+r.dataset.i][0]:null;
  hideDup=!hideDup;localStorage.setItem('icqx-hidedup',hideDup?'1':'0');applyDup();
  let lo=0,hi=c.n;if(t!=null){while(lo<hi){const m=(lo+hi)>>1;c.msgs[m][0]<t?lo=m+1:hi=m}}
  openChat(cur,c.n?Math.min(lo,c.n-1):null);if($('#q').value.trim())runSearch($('#q').value)};
$('#swap').onclick=()=>{if(cur<0)return;const c=DATA.contacts[cur];c.swap=!c.swap;localStorage.setItem(swapKey(c),c.swap?'1':'0');
  const r=CH.querySelector('.r'),i=r?+r.dataset.i:null;openChat(cur,i)};
$('#exp').onclick=()=>{if(cur<0)return;const c=DATA.contacts[cur],nm=c.name||c.uin;
  const txt=c.msgs.map(m=>`[${dayOf(m[0])} ${tmOf(m[0])}] ${isMe(c,m)?(DATA.meName||'Me'):nm}: ${m[2]||(m[4]&&m[4][0]&&m[4][0].t)||''}`).join('\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:'text/plain'}));a.download='ICQ '+nm+'.txt';a.click()};
let tmr;$('#q').addEventListener('input',e=>{clearTimeout(tmr);tmr=setTimeout(()=>runSearch(e.target.value),200)});
function runSearch(q){
  q=norm(q.trim());if(!q){listContacts();return}
  const only=$('#only').checked&&cur>=0,out=[];
  DATA.contacts.forEach((c,ci)=>{if(only&&ci!==cur)return;
    for(let i=c.n-1;i>=0&&out.length<400;i--){const m=c.msgs[i];
      const hay=m._n||(m._n=norm(m[2]+' '+m[3]+' '+(m[4]||[]).map(a=>(a.t||'')+' '+(a.d||'')).join(' ')));const k=hay.indexOf(q);
      if(k>=0)out.push([ci,i,k])}});
  $('#list').innerHTML=out.length?out.map(([ci,i,k])=>{const c=DATA.contacts[ci],m=c.msgs[i],t=m[2];
    const s=Math.max(0,k-30),sn=esc(t.slice(s,s+120));
    return `<div class="s" data-c="${ci}" data-i="${i}"><small>${esc(c.name||c.uin)} \u00b7 ${dayOf(m[0])} ${tmOf(m[0])}</small><div>${s?'\u2026':''}${sn}</div></div>`}).join('')
    +(out.length>=400?'<div class="s"><small>Showing the 400 newest matches. Refine your search to narrow it down.</small></div>':'')
    :'<div class="s"><small>No messages match.</small></div>'}
$('#only').addEventListener('change',()=>runSearch($('#q').value));
listContacts();
if(DATA.contacts.length===1)openChat(0);
</script></html>'''

# ---------------------------------------------------------------- main
def discover(path):
    """Return (list of conversation folders, avatars dir)."""
    if os.path.isfile(path):
        fo = os.path.dirname(os.path.abspath(path))
        return [fo], os.path.normpath(os.path.join(fo, "..", "..", "avatars"))
    path = os.path.abspath(path)
    arch = os.path.join(path, "archive")
    base = path if os.path.isdir(arch) else os.path.dirname(path)
    arch = arch if os.path.isdir(arch) else path
    folders = [os.path.join(arch, d) for d in sorted(os.listdir(arch))
               if db_files(os.path.join(arch, d))]
    return folders, os.path.join(base, "avatars")

def main():
    for st in (sys.stdout, sys.stderr):      # names with unusual characters must never crash a Windows console
        try: st.reconfigure(errors="replace")
        except Exception: pass
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--my-uin")
    ap.add_argument("--out")
    ap.add_argument("--cache", help="content.cache folder (default: <profile>\\content.cache)")
    ap.add_argument("--extra-cache", action="append", default=[], metavar="DIR",
                    help="additional content.cache folder, e.g. from another PC (repeatable)")
    ap.add_argument("--extra-stickers", action="append", default=[], metavar="DIR",
                    help="additional stickers folder, e.g. from another PC (repeatable)")
    ap.add_argument("--extra-profile", action="append", default=[], metavar="DIR",
                    help="another ICQ profile folder (...\\ICQ\\0001, e.g. from another PC). Conversations are merged, "
                         "and its content.cache / stickers / avatars / calls are used too (repeatable)")
    ap.add_argument("--link", action="append", default=[], metavar="OLD=NEW",
                    help="treat two UINs as the same person and show them as one conversation, e.g. --link 111111111=222222222 (repeatable)")
    ap.add_argument("--lottie-js", help="path to a local lottie.min.js (embeds the sticker player so it works offline)")
    ap.add_argument("--diagnose", action="store_true", help="print a structure-only report (no message text) for every conversation")
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    path = a.path
    if not path:
        import tkinter as tk
        from tkinter import filedialog
        tk.Tk().withdraw()
        path = filedialog.askdirectory(title="Select your ICQ profile folder (...\\ICQ\\0001)")
        if not path:
            return
    roots = [path] + a.extra_profile
    profiles = []
    for r in roots:
        fl, av = discover(r)
        profiles.append(dict(prof=os.path.dirname(av), folders=fl, avdir=av))
    if not any(pr["folders"] for pr in profiles):
        sys.exit("No conversations found (looked for archive\\<UIN>\\_db6).")
    prof, avdir = profiles[0]["prof"], profiles[0]["avdir"]
    from collections import Counter
    for pr in profiles:
        if not pr["folders"]:
            continue
        arch = os.path.dirname(pr["folders"][0])
        nodb = [d for d in sorted(os.listdir(arch)) if os.path.isdir(os.path.join(arch, d)) and not db_files(os.path.join(arch, d))]
        if nodb:
            kinds = Counter(tuple(sorted(os.listdir(os.path.join(arch, d)))) for d in nodb)
            print(f"{arch}: {len(nodb)} folders have no message database (_db2 ... _db6), so there is nothing to show: " +
                  "; ".join(f"{n}x {', '.join(k) or 'empty'}" for k, n in kinds.items()))
    my, my_name = "", ""
    for pr in profiles:
        u, n = read_me(pr["prof"])
        my, my_name = my or u, my_name or n
    my = a.my_uin or my or guess_my_uin(profiles[0]["folders"], avdir)
    out = a.out or os.path.join(prof, "ICQ_Explorer.html")
    stickers = Stickers([os.path.join(pr["prof"], "stickers") for pr in profiles] + a.extra_stickers)
    cache = Cache([a.cache or os.path.join(prof, "content.cache")] + [os.path.join(pr["prof"], "content.cache") for pr in profiles[1:]] + a.extra_cache,
                  os.path.dirname(os.path.abspath(out)), stickers)
    print(f"content.cache: {cache.count} files found in {len(cache.dirs)} folder(s)" if cache.files else "content.cache: not found (links will show without previews)")
    cl_names = {}
    for pr in profiles:
        for k, v in contact_list_names(pr["prof"]).items():
            cl_names.setdefault(k, v)
    contacts, by_uin = [], {}
    for pi, pr in enumerate(profiles):
        for fo in pr["folders"]:
            uin = os.path.basename(fo)
            msgs, label = [], ""
            for dbf in db_files(fo):
                raw_db = open(os.path.join(fo, dbf), "rb").read()
                recs, covered, tags, flags = diagnose(raw_db)
                if a.diagnose or covered < len(raw_db) * 0.99:
                    warn = "" if covered >= len(raw_db) * 0.99 else "   <-- part of this file was NOT understood"
                    print(f"  [{uin}/{dbf}{' (profile %d)' % (pi + 1) if len(profiles) > 1 else ''}] {len(raw_db):,} bytes, {recs} records, "
                          f"{covered/max(1,len(raw_db)):.1%} parsed, sender flags {dict(flags)}, tags {dict(sorted(tags.items()))}{warn}")
                part = [cache.attach(m) for m in decode(raw_db)]
                if not msgs:
                    msgs = part
                else:                  # older database version of the same conversation
                    merge_into(msgs, part)
                    extra = sum(1 for m in part if not m[5])      # not a copy of anything already loaded
                    print(f"  {uin}: {dbf} added {extra} messages not in the newer database(s)")
            rx = read_reactions(fo)
            for m in msgs:
                k = m.pop(6)
                if rx.get(k):
                    m.append(rx[k])
            c = by_uin.get(uin)
            if not c:
                c = dict(uin=uin, name="", avatar="", msgs=[])
                contacts.append(c); by_uin[uin] = c
            c["name"] = c["name"] or contact_name(fo) or cl_names.get(uin, "")
            c["avatar"] = c["avatar"] or avatar(pr["avdir"], uin)
            if c["msgs"]:      # same conversation found in more than one profile: keep everything, flag exact copies
                n = len(msgs)
                dup = merge_into(c["msgs"], msgs)
                print(f"  merged {uin}: {n} messages from profile {pi + 1}, {dup} of them identical to ones already there (flagged as duplicates)")
                continue
            c["msgs"].extend(msgs)
    # calls from calls\\call_log.cache become rows in the matching conversation (or a conversation of their own)
    ncalls, seen_calls = 0, set()
    for pr in profiles:
        for cl in read_calls(pr["prof"]):
            if (cl["uin"], cl["ts"]) in seen_calls:
                continue
            seen_calls.add((cl["uin"], cl["ts"]))
            c = by_uin.get(cl["uin"])
            if not c:
                c = dict(uin=cl["uin"], name=cl_names.get(cl["uin"]) or cl["name"], avatar=avatar(pr["avdir"], cl["uin"]), msgs=[])
                contacts.append(c); by_uin[cl["uin"]] = c
            label = CALL_TYPES.get(cl["typ"]) or "Call"   # the type codes (2, 5, ...) are unknown, so only "Call" is shown
            c["msgs"].append([cl["ts"], 0, "", "", [dict(k="call", t=label)], 0]); ncalls += 1
    # same person who moved to a new UIN: hint when the contact list names one UIN after another
    linked = {x for sp in a.link for x in sp.split("=")}
    for uin, nm in cl_names.items():
        if nm in by_uin and nm != uin and uin in by_uin and uin not in linked and nm not in linked:
            print(f"hint: {uin} is called '{nm}' in your contact list, which is another conversation's UIN - "
                  f"if it's the same person, add  --link {nm}={uin}")
    for spec in a.link:
        try:
            old, new = [x.strip() for x in spec.split("=")]
        except ValueError:
            print(f"--link expects OLD=NEW, got '{spec}'"); continue
        co, cn = by_uin.get(old), by_uin.get(new)
        if not co or not cn or co is cn:
            print(f"--link {spec}: need both UINs to have a conversation (found: {old}={'yes' if co else 'no'}, {new}={'yes' if cn else 'no'})"); continue
        merge_into(co["msgs"], cn["msgs"])
        co["alt"] = co.get("alt", []) + [new]
        co["name"] = co["name"] or cn["name"]; co["avatar"] = co["avatar"] or cn["avatar"]
        contacts.remove(cn); del by_uin[new]
        print(f"linked {new} into {old}: {len(cn['msgs'])} messages from the second UIN now appear in the same conversation")
    for c in contacts:
        c["msgs"].sort(key=lambda m: m[0])
        mark_repeats(c["msgs"])
        d1 = sum(1 for m in c["msgs"] if m[5] == 1); d2 = sum(1 for m in c["msgs"] if m[5] == 2)
        print(f"  {c['uin']:>12}  {c['name'] or '-':<24} {len(c['msgs']):>7} messages"
              + (f"  (duplicates flagged: {d1} identical, {d2} repeated runs)" if d1 or d2 else ""))
    contacts.sort(key=lambda c: -(c["msgs"][-1][0] if c["msgs"] else 0))
    print(f"stickers: {cache.stats.get('stickers', 0)} sticker messages, calls: {ncalls}")
    print(f"cache matches: {cache.stats['msgs']} messages with attachments, {cache.stats['meta']} metadata files, "
          f"{cache.stats['img']} images shown, {cache.stats['files']} downloaded originals found")
    if cache.stats["unresolved"]:
        rp = os.path.join(os.path.dirname(os.path.abspath(out)), "ICQ_Explorer_unresolved_links.txt")
        open(rp, "w", encoding="utf-8").write("\n".join(cache.unresolved))
        print(f"{cache.stats['unresolved']} files.icq.net links have no matching entry in content.cache -> {rp}")
    used = {at["id"] for c in contacts for m in c["msgs"] if m[4] for at in m[4] if at.get("k") == "stk"}
    stk = {i: stickers.assets[i] for i in used if stickers.assets.get(i)}
    packs = {g: stickers.packs[g] for g in {at["g"] for c in contacts for m in c["msgs"] if m[4] for at in m[4] if at.get("k") == "stk"} if g in stickers.packs}
    data = dict(contacts=contacts, meUin=my, meName=my_name, meAvatar=next((av for av in (avatar(pr["avdir"], my) for pr in profiles) if av), "") if my else "", stk=stk, packs=packs)
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    page = HTML.replace("__DATA__", blob)
    if a.lottie_js:
        page = page.replace("<script>\nconst DATA", "<script>" + open(a.lottie_js, encoding="utf-8").read().replace("</script", "<\\/script") + "</script>\n<script>\nconst DATA", 1)
    open(out, "w", encoding="utf-8").write(page)
    print(f"\nWrote {out}  ({os.path.getsize(out)/1e6:.1f} MB)")
    if not a.no_open:
        webbrowser.open("file://" + out.replace("\\", "/"))

if __name__ == "__main__":
    main()
