#!/usr/bin/env python3
"""Alien Encryption, desktop edition (Qt). Messages are compatible with the web version.
Setup:  pip install cryptography qtpy PySide6      Run:  python alien_encryption_qt.py"""
import base64, hashlib, json, os, random, re, threading
from pathlib import Path
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    raise SystemExit("Missing dependency. Install it with:  pip install cryptography")

# ---------- core (same formats as the web app) ----------
VG = 'ꗃꘘꖙꕷꔠꓴꒀꑊꐻꏫꎻꍡꌷꋗꊡꉣꈦꇵꆟꅢꄯꃒꂵꁰꀫ꒻꒺꒴꒱꒭꒩꒡ꔕꔻꕅꕻꖝꖵꗋꗵ꘍꘦ꙌꙬꚐꚶꛗ꛺꜏ꜰꝃꝰ꞉Ꞿꟷꠃ꠱ꡍ꡺ꢕꢽꣲꤌꤧꥃꥬꦇꦶ꧕ꧾꨑ꨼ꩢꪄꪱꫂꫨꬍꬵꭄꭲꭿ꯱꯿ힼힺힸힶힴힲힰ힮힬힪힨힦힤힢힠힞힜힚힘힖힔힒힐힎힌힊히힆힄힂힀ힾ꿾꿼꿺꿸꿶꿴꿲꿰꿮꿬꿪꿨꿦꿤꿢꿠꿞꿜꿚꿘꿖꿔꿒꿐꿎꿌꿊꿈꿆꿄꿂꿀꾾꾼꾺꾸꾶꾴꾲꾰꾮꾬꾪꾨꾦꾤꾢꾠꾞꾜꾚꾘꾖꾔꾒꾐꾎꾌꾊꾈꾆꾄꾂꾀껾껼껺껸껶껴껲껰껮껬껪껨껦껤껢껠껞껜껚께껖껔껒껐껎껌껊껈껆껄껂껀꺾꺼꺺꺸꺶꺴꺲꺰꺮꺬꺪꺨꺦꺤꺢꺠꺞꺜꺚꺘꺖꺔꺒꺐꺎꺌꺊꺈꺆꺄꺂꺀꽾꽼꽺꽸꽶꽴꽲꽰꽮꽬꽪꽨'
G = list(VG); SEP = list('꧁꧂꧃꧄꧅꧆꧇꧈'); R = {g: i for i, g in enumerate(G)}
sh = lambda i: (i * 7 + 13) % 37
B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
MSG = {'format': "This doesn't look like a message from this app, or part of it is missing.",
       'rsa': 'This is a key pair message. Switch to Key pair to open it.',
       'aes': 'This is a passphrase message. Switch to Passphrase to open it.',
       'legacy': "This passphrase message came from an old browser version and can't be opened here.",
       'wrong': "Couldn't decrypt. The key is wrong, or the message was changed.",
       'wrongR': "Couldn't decrypt. It was encrypted for a different key pair."}

class Fail(Exception):
    def __init__(s, m, clear=False): super().__init__(m); s.clear = clear
def fail(k): raise Fail(MSG[k], True)

def g_enc(b):
    o, s = [], 0
    for i, v in enumerate(b):
        o.append(G[(v + sh(i)) & 255])
        if (i + 1) % 8 == 0: o.append(SEP[s % 8]); s += 1
    return ''.join(o)
def g_dec(t):
    o, i = [], 0
    for c in t:
        if c in R: o.append((R[c] - sh(i)) & 255); i += 1
    return bytes(o)
is_g = lambda t: any(c in R for c in t)
def pack(raw, alien):
    s = base64.b64encode(raw).decode()
    return g_enc(s.encode()) if alien else s
def unpack(t):
    t = t.strip()
    try: return base64.b64decode(g_dec(t).decode() if is_g(t) else re.sub(r'\s+', '', t))
    except Exception: fail('format')

is_hex = lambda k: re.fullmatch(r'[0-9a-fA-F]{64}', k) is not None
def kdf(p, salt): return PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000).derive(p.encode())
def seal(text, key, salt=None):  # [flags][salt 16 if flags&2][iv 12][ciphertext]
    iv = os.urandom(12)
    return bytes([2 if salt else 0]) + (salt or b'') + iv + AESGCM(key).encrypt(iv, text.encode(), None)
def open_(d, key_for):
    f = d[0] if d else 0
    if len(d) < 29 or f > 3: fail('rsa' if f == 123 else 'format')
    p, salt = 1, None
    if f & 2: salt, p = d[1:17], 17
    try: return AESGCM(key_for(salt)).decrypt(d[p:p + 12], d[p + 12:], None).decode()
    except (InvalidTag, UnicodeDecodeError): fail('wrong')
OAEP = lambda: padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
def enc_aes(t, k):
    if is_hex(k): return seal(t, bytes.fromhex(k)), 'AES-256-GCM'
    s = os.urandom(16); return seal(t, kdf(k, s), s), 'AES-256-GCM'
def dec_aes(raw, k):
    def kf(s):
        if s: return kdf(k, s)
        if is_hex(k): return bytes.fromhex(k)
        fail('legacy')
    return open_(raw, kf)
def enc_rsa(t, pub):
    k = os.urandom(32); w = pub.encrypt(k, OAEP())
    j = json.dumps({'k': base64.b64encode(w).decode(), 'd': base64.b64encode(seal(t, k)).decode()}, separators=(',', ':'))
    return j.encode(), 'RSA-2048 + AES-256-GCM'
def dec_rsa(raw, priv):
    try:
        j = json.loads(raw.decode()); k, d = base64.b64decode(j['k']), base64.b64decode(j['d'])
    except Exception: fail('aes' if raw[:1] and raw[0] <= 3 else 'format')
    try: key = priv.decrypt(k, OAEP())
    except Exception: fail('wrongR')
    return open_(d, lambda s: key)
def pem_pub(k): return k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().strip()
def pem_priv(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode().strip()
def load_pub(t):
    t = t.strip()
    if not t: return None
    try:
        k = serialization.load_pem_public_key(t.encode())
        if isinstance(k, rsa.RSAPublicKey): return k
    except Exception: pass
    raise Fail('Not a public key. It should start with BEGIN PUBLIC KEY.')
def load_priv(t):
    t = t.strip()
    if not t: return None
    try:
        k = serialization.load_pem_private_key(t.encode(), None)
        if isinstance(k, rsa.RSAPrivateKey): return k
    except Exception: pass
    raise Fail('Not a private key. It should start with BEGIN PRIVATE KEY.')
def fingerprint(pub):
    h = hashlib.sha256(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:32]
    return ' '.join(h[i:i + 4] for i in range(0, 32, 4))

# ---------- file encryption (any file type, streamed in 1 MiB chunks) ----------
# Layout: MAGIC | 1 | mode (0 hex key, 1 passphrase, 2 key pair) | [salt 16 | wrapped key] | nonce prefix 8 | AES-GCM chunks.
# Every chunk authenticates the header plus a "last chunk" flag, so edits and truncation are detected.
MAGIC, CH = b'ALIENENC', 1 << 20
MSG.update(wrongF="Couldn't decrypt. The key is wrong, or the file was changed or cut short.", notfile="This isn't a file encrypted by this app.",
           needpass='This file needs your passphrase or hex key. Enter it in the Passphrase tab.', needpriv='This file was encrypted for a key pair. Add your private key in the Key pair tab.')
def unique(p):
    q, n = p, 1
    while q.exists(): q = p.with_name(f'{p.stem} ({n}){p.suffix}'); n += 1
    return q
def enc_file(src, dst, ctx, prog):
    prefix = os.urandom(8); k = ctx['key']
    if ctx['mode'] == 'rsa': key = os.urandom(32); w = ctx['pub'].encrypt(key, OAEP()); hdr = MAGIC + b'\x01\x02' + len(w).to_bytes(2, 'big') + w + prefix
    elif is_hex(k): key = bytes.fromhex(k); hdr = MAGIC + b'\x01\x00' + prefix
    else: salt = os.urandom(16); key = kdf(k, salt); hdr = MAGIC + b'\x01\x01' + salt + prefix
    a = AESGCM(key); size = max(os.path.getsize(src), 1); done = n = 0
    with open(src, 'rb') as f, open(dst, 'wb') as o:
        o.write(hdr); buf = f.read(CH)
        while True:
            nxt = f.read(CH) if len(buf) == CH else b''; last = not nxt
            o.write(a.encrypt(prefix + n.to_bytes(4, 'big'), buf, hdr + (b'\x01' if last else b'\x00')))
            done += len(buf); n += 1; prog(min(99, done * 100 // size))
            if last: break
            buf = nxt
    prog(100)
def dec_file(src, dst, ctx, prog):
    size = max(os.path.getsize(src), 1)
    with open(src, 'rb') as f, open(dst, 'wb') as o:
        if f.read(8) != MAGIC: fail('notfile')
        vm = f.read(2)
        if len(vm) < 2 or vm[0] != 1: fail('notfile')
        m, hdr, k = vm[1], MAGIC + vm, ctx.get('key', '')
        if m == 2:
            wl = f.read(2); w = f.read(int.from_bytes(wl, 'big')); hdr += wl + w
            if not ctx.get('priv'): fail('needpriv')
            try: key = ctx['priv'].decrypt(w, OAEP())
            except Exception: fail('wrongR')
        elif m == 1:
            salt = f.read(16); hdr += salt
            if not k: fail('needpass')
            key = kdf(k, salt)
        elif m == 0:
            if not is_hex(k): fail('needpass')
            key = bytes.fromhex(k)
        else: fail('notfile')
        prefix = f.read(8); hdr += prefix; a = AESGCM(key); n = 0; buf = f.read(CH + 16)
        while True:
            nxt = f.read(CH + 16) if len(buf) == CH + 16 else b''; last = not nxt
            try: o.write(a.decrypt(prefix + n.to_bytes(4, 'big'), buf, hdr + (b'\x01' if last else b'\x00')))
            except InvalidTag: fail('wrongF')
            n += 1; prog(min(99, f.tell() * 100 // size))
            if last: break
            buf = nxt
    prog(100)
def batch(files, force, ctx, prog):  # force: True decrypt, False encrypt, None decide by ".encrypted"
    res = []
    for i, f in enumerate(files):
        p = Path(f); dec = force if force is not None else p.name.endswith('.encrypted'); dst = None
        try:
            dst = unique(p.with_name(p.name[:-10]) if dec and p.name.endswith('.encrypted') else p.with_name(p.name + ('.decrypted' if dec else '.encrypted')))
            (dec_file if dec else enc_file)(p, dst, ctx, lambda pc, i=i, n=p.name: prog((i * 100 + pc) // len(files), n))
            res.append((p.name, True, dst.name))
        except Exception as e:
            dst and dst.exists() and dst.unlink(); res.append((p.name, False, str(e)))
    return res

# ---------- desktop UI (Qt via qtpy) ----------
TH = {'dark': dict(bg='#0c1120', sf='#141a31', fd='#0e1326', ln='#28315a', tx='#e8ebf8', mu='#97a1c6', ac='#ffb454', ai='#1b1200', sg='#6fdcff', er='#ff9494', ok='#7fe3a4'),
      'light': dict(bg='#eef1f7', sf='#ffffff', fd='#f6f7fb', ln='#d3d9e8', tx='#161a2c', mu='#566086', ac='#a85600', ai='#ffffff', sg='#0a6a88', er='#b3261e', ok='#1a7a45')}
CFG = Path.home() / '.alien_encryption.json'
QSS = """
QWidget{background:%(sf)s;color:%(tx)s;font-size:14px}
QMainWindow,#root{background:%(bg)s}
#card{background:%(sf)s;border:1px solid %(ln)s;border-radius:18px}
QLabel{background:transparent}
QLabel#title{font:600 28px Georgia,serif}
QLabel#mu{color:%(mu)s;font-size:12px}
QLabel#b{font-weight:600}
QPushButton{background:%(sf)s;border:1px solid %(ln)s;border-radius:9px;padding:8px 16px;font-weight:600}
QPushButton:hover{border-color:%(ac)s}
QPushButton#acc{background:%(ac)s;color:%(ai)s;border-color:%(ac)s}
#segbar{background:%(fd)s;border:1px solid %(ln)s;border-radius:12px}
QPushButton#seg{background:transparent;border:0;color:%(mu)s;padding:9px 20px;border-radius:9px}
QPushButton#seg:checked{background:%(ac)s;color:%(ai)s}
QPlainTextEdit,QLineEdit{background:%(fd)s;border:1px solid %(ln)s;border-radius:10px;padding:8px;selection-background-color:%(ac)s;selection-color:%(ai)s}
QPlainTextEdit:focus,QLineEdit:focus{border-color:%(ac)s}
QCheckBox{spacing:8px;background:transparent}
QCheckBox::indicator{width:34px;height:18px;border-radius:10px;background:%(ln)s;border:1px solid %(ln)s}
QCheckBox::indicator:checked{background:%(ac)s;border-color:%(ac)s}
QScrollBar:vertical{background:transparent;width:10px}QScrollBar::handle:vertical{background:%(ln)s;border-radius:5px;min-height:24px}
QScrollBar::add-line,QScrollBar::sub-line{height:0}
#drop{background:transparent;border:2px dashed %(ln)s;border-radius:12px}
#drop[hot="true"]{border-color:%(ac)s}
QProgressBar{background:%(fd)s;border:1px solid %(ln)s;border-radius:4px;color:transparent}
QProgressBar::chunk{background:%(ac)s;border-radius:3px}
"""

def main():
    try:
        from qtpy.QtCore import QEvent, QObject, Qt, QThread, QTimer, Signal
        from qtpy.QtGui import QKeySequence
        from qtpy.QtWidgets import (QApplication, QBoxLayout, QButtonGroup, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
                                    QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QShortcut, QStackedWidget, QVBoxLayout, QWidget)
    except Exception:
        raise SystemExit("Missing Qt bindings. Install them with:  pip install qtpy PySide6")
    try: cfg = json.loads(CFG.read_text())
    except Exception: cfg = {}
    def save_cfg():
        try: CFG.write_text(json.dumps(cfg)); os.chmod(CFG, 0o600)
        except Exception: pass

    class Worker(QThread):
        ok = Signal(object); bad = Signal(object)
        def __init__(s, fn): super().__init__(); s.fn = fn
        def run(s):
            try: s.ok.emit(s.fn())
            except Exception as e: s.bad.emit(e)
    class Drop(QPlainTextEdit):
        dropped = Signal(str)
        def dragEnterEvent(s, e): e.acceptProposedAction() if e.mimeData().hasUrls() else super().dragEnterEvent(e)
        def dragMoveEvent(s, e): e.acceptProposedAction() if e.mimeData().hasUrls() else super().dragMoveEvent(e)
        def dropEvent(s, e):
            if e.mimeData().hasUrls(): s.dropped.emit(e.mimeData().urls()[0].toLocalFile()); e.acceptProposedAction()
            else: super().dropEvent(e)
    class FWorker(QThread):
        prog = Signal(int, str); done = Signal(object)
        def __init__(s, fn): super().__init__(); s.fn = fn
        def run(s):
            try: s.done.emit(s.fn(lambda v, n: s.prog.emit(v, n)))
            except Exception as e: s.done.emit(e)
    class DropZone(QFrame):
        files = Signal(list)
        def __init__(s): super().__init__(); s.setAcceptDrops(True)
        def hot(s, v): s.setProperty('hot', v); s.style().unpolish(s); s.style().polish(s)
        def dragEnterEvent(s, e):
            if e.mimeData().hasUrls(): e.acceptProposedAction(); s.hot(True)
        def dragLeaveEvent(s, e): s.hot(False)
        def dropEvent(s, e):
            s.hot(False); fs = [u.toLocalFile() for u in e.mimeData().urls() if Path(u.toLocalFile()).is_file()]
            e.acceptProposedAction(); fs and s.files.emit(fs)
    class Idle(QObject):
        def __init__(s, cb): super().__init__(); s.cb = cb
        def eventFilter(s, o, e):
            if e.type() in (QEvent.KeyPress, QEvent.MouseButtonPress): s.cb()
            return False
    class Win(QMainWindow):
        on_resize = None
        def resizeEvent(s, e):
            super().resizeEvent(e)
            if s.on_resize: s.on_resize(s.width())

    app = QApplication([]); app.setApplicationName('Alien Encryption')
    st = {'pub': None, 'priv': None, 'out': '', 'cipher': False, 'busy': False, 'w': None, 'af': None, 'theme': cfg.get('theme', 'dark'), 'hidden': True}
    C = lambda: TH[st['theme']]
    win = Win(); win.setWindowTitle('Alien Encryption'); win.resize(1060, 800); win.setMinimumSize(520, 640)
    root = QWidget(); root.setObjectName('root'); win.setCentralWidget(root)
    ro = QVBoxLayout(root); ro.setContentsMargins(16, 16, 16, 16)
    card = QFrame(); card.setObjectName('card'); ro.addWidget(card)
    cl = QVBoxLayout(card); cl.setContentsMargins(24, 22, 24, 22); cl.setSpacing(14)

    def L(t, name=''):
        l = QLabel(t); name and l.setObjectName(name); return l
    def B(t, cb, acc=False):
        b = QPushButton(t); b.setCursor(Qt.PointingHandCursor); b.clicked.connect(lambda *_: cb())
        acc and b.setObjectName('acc'); return b
    def row(*ws, stretch=False):
        h = QHBoxLayout(); h.setSpacing(6); h.setContentsMargins(0, 0, 0, 0)
        for w in ws: h.addWidget(w)
        stretch and h.addStretch(); return h
    def prim(b, on):
        b.setObjectName('acc' if on else ''); b.style().unpolish(b); b.style().polish(b)
    def T(ph='', ro=False, cls=QPlainTextEdit):
        t = cls(); t.setPlaceholderText(ph); t.setReadOnly(ro); t.setTabChangesFocus(True); return t
    def tint(w, color): w.setStyleSheet(f'color:{color}' if color else '')

    # header
    theme_b = B('', lambda: toggle_theme())
    h = QHBoxLayout(); tv = QVBoxLayout(); tv.setSpacing(0); tv.addWidget(L('🛸 Alien Encryption', 'title')); tv.addWidget(L('Encrypts text and files on your computer. Nothing is sent anywhere.', 'mu'))
    h.addLayout(tv); h.addStretch(); h.addLayout(row(B('Wipe', lambda: wipe()), theme_b)); cl.addLayout(h)

    # mode switch
    seg = QFrame(); seg.setObjectName('segbar'); sg_l = QHBoxLayout(seg); sg_l.setContentsMargins(4, 4, 4, 4); sg_l.setSpacing(4)
    grp = QButtonGroup(win); segs = {}
    for v, t in (('aes', 'Passphrase  ·  AES-256'), ('rsa', 'Key pair  ·  RSA-2048')):
        b = QPushButton(t); b.setObjectName('seg'); b.setCheckable(True); b.setCursor(Qt.PointingHandCursor); grp.addButton(b); sg_l.addWidget(b); segs[v] = b
        b.clicked.connect(lambda *_, v=v: set_mode(v))
    sr = QHBoxLayout(); sr.addWidget(seg); sr.addStretch(); cl.addLayout(sr)
    stack = QStackedWidget(); cl.addWidget(stack)

    # passphrase panel
    pa = QWidget(); pv = QVBoxLayout(pa); pv.setContentsMargins(0, 4, 0, 0); pv.setSpacing(6)
    pv.addWidget(L('Secret key', 'b'))
    key = QLineEdit(); key.setEchoMode(QLineEdit.Password); key.setPlaceholderText('Passphrase, or 64-character hex key')
    show_b = B('Show', lambda: toggle_key())
    pv.addLayout(row(key, show_b, B('Paste', lambda: paste(key)), B('Random key', lambda: gen()), B('Copy', lambda: copy(key.text()))))
    khint = L('', 'mu'); pv.addWidget(khint)
    mlab = L('', 'mu'); mbtn = [B('Save as master', lambda: m_save()), B('Use master', lambda: m_use()), B('Forget', lambda: m_del())]
    pv.addLayout(row(mlab, *mbtn, stretch=True)); stack.addWidget(pa)

    # key pair panel
    pr = QWidget(); rv = QVBoxLayout(pr); rv.setContentsMargins(0, 4, 0, 0)
    rv.addLayout(row(B('Generate key pair', lambda: gen_rsa(), True), B('Import .pem file', lambda: import_pem()), B('Save keys', lambda: save_keys()), stretch=True))
    kh = QHBoxLayout(); kh.setSpacing(16)
    def keybox(title, ph):
        v = QVBoxLayout(); pill = L(''); hh = QHBoxLayout(); hh.addWidget(L(title, 'b')); hh.addStretch(); hh.addWidget(pill); v.addLayout(hh)
        t = T(ph); t.setFixedHeight(110); t.setStyleSheet(''); v.addWidget(t); kh.addLayout(v); return v, t, pill
    vpub, pub_t, pill_pub = keybox('Public key', 'Paste a public key to encrypt for someone')
    vpri, priv_t, pill_priv = keybox('Private key', 'Needed to decrypt. Keep it secret.')
    vpub.addLayout(row(B('Copy', lambda: copy(pub_t.toPlainText())), B('Paste', lambda: paste(pub_t)), stretch=True))
    fp_l = L('', 'mu'); vpub.addWidget(fp_l); vpub.addWidget(L('Share this. Compare the fingerprint with the owner to confirm it.', 'mu'))
    rev_b = B('Reveal', lambda: hide_priv(not st['hidden']))
    vpri.addLayout(row(rev_b, B('Copy', lambda: copy(priv_t.toPlainText())), B('Paste', lambda: paste(priv_t)), stretch=True)); vpri.addStretch()
    rv.addLayout(kh); stack.addWidget(pr)

    # files
    dz = DropZone(); dz.setObjectName('drop'); dzl = QHBoxLayout(dz); dzl.setContentsMargins(16, 12, 16, 12)
    dzv = QVBoxLayout(); dzv.setSpacing(2); dzv.addWidget(L('Files', 'b')); dh = L('Drop any files here: images, video, audio, documents. Each is saved next to the original as name.ext.encrypted, and files ending in .encrypted are decrypted.', 'mu'); dh.setWordWrap(True); dzv.addWidget(dh)
    dzl.addLayout(dzv, 1); dzl.addLayout(row(B('Encrypt files…', lambda: pick_files(False), True), B('Decrypt files…', lambda: pick_files(True))))
    pbar = QProgressBar(); pbar.setTextVisible(False); pbar.setFixedHeight(8); pbar.hide(); cl.addWidget(dz); cl.addWidget(pbar)

    # message panes
    inp = T('Type text to encrypt, or paste an encrypted message to decrypt. You can also drop a text file here.', cls=Drop); inp.setAcceptDrops(True)
    out_t = T('The result appears here.', True)
    def pane(title, btns, t, foot):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(6)
        hh = QHBoxLayout(); hh.addWidget(L(title, 'b')); hh.addStretch()
        for x in btns: hh.addWidget(x)
        v.addLayout(hh); t.setMinimumHeight(150); v.addWidget(t, 1); v.addLayout(foot); return w
    ci = L('0 characters', 'mu'); co = L('', 'mu'); stl = L('', 'mu')
    f1 = QHBoxLayout(); f1.addWidget(ci); f1.addStretch(); f2 = QHBoxLayout(); f2.addWidget(co); f2.addStretch(); f2.addWidget(stl)
    msg_l = QBoxLayout(QBoxLayout.LeftToRight); msg_l.setSpacing(18)
    msg_l.addWidget(pane('Message', [B('Open file', lambda: open_file()), B('Paste', lambda: paste(inp))], inp, f1))
    msg_l.addWidget(pane('Result', [B('Copy', lambda: copy(st['out'])), B('Save .txt', lambda: save_out())], out_t, f2))
    cl.addLayout(msg_l, 1)
    win.on_resize = lambda w: msg_l.setDirection(QBoxLayout.LeftToRight if w >= 900 else QBoxLayout.TopToBottom)

    # actions
    enc_b = B('Encrypt', lambda: do_enc(), True); dec_b = B('Decrypt', lambda: do_dec())
    sw_alien = QCheckBox('Alien script (glyphs instead of Base64)'); sw_alien.setChecked(cfg.get('alien', True))
    sw_copy = QCheckBox('Copy after encrypting'); sw_idle = QCheckBox('Auto-clear after 5 min idle'); sw_idle.setChecked(cfg.get('idle', False))
    for s in (sw_alien, sw_copy, sw_idle): s.setCursor(Qt.PointingHandCursor)
    ab = row(enc_b, dec_b, B('Swap', lambda: swap()), B('Clear', lambda: clear())); ab.addSpacing(14)
    for s in (sw_alien, sw_copy, sw_idle): ab.addWidget(s)
    ab.addStretch(); cl.addLayout(ab)

    # logic
    def status(m, k=''):
        stl.setText(m); stl.setStyleSheet('color:' + {'err': C()['er'], 'ok': C()['ok']}.get(k, C()['mu']))
    def counts(*_):
        v = inp.toPlainText(); ci.setText(f'{len(v):,} characters'); co.setText(f"{len(st['out']):,} characters" if st['out'] else '')
        s = v.strip(); c = len(s) > 20 and (is_g(s) or re.fullmatch(r'[A-Za-z0-9+/=\s]{60,}', s) is not None)
        prim(enc_b, not c); prim(dec_b, c)
    def set_out(t): out_t.setPlainText(t)
    def show(t, cipher=False, anim=False):
        st['out'], st['cipher'] = t, cipher
        if st['af']: st['af'].stop(); st['af'] = None
        g = is_g(t); tint(out_t, C()['sg'] if t else ''); f = out_t.font(); f.setPointSize(16 if g else 11); f.setFamily('Consolas' if cipher and not g else ''); out_t.setFont(f)
        set_out(t); counts()
        if anim and t:
            pool, n, step = (G if g else list(B64)), [0], max(8, len(t) // 22); tm = QTimer(win); st['af'] = tm
            def tick():
                n[0] += step
                if n[0] >= len(t): tm.stop(); st['af'] = None; set_out(t); return
                set_out(t[:n[0]] + ''.join(random.choice(pool) for _ in range(14)))
            tm.timeout.connect(tick); tm.start(30)
    def copy(t):
        if not t: return status('Nothing to copy')
        app.clipboard().setText(t); status('Copied', 'ok')
    def paste(w):
        s = app.clipboard().text()
        if not s: return status('Clipboard is empty')
        w.setText(s) if isinstance(w, QLineEdit) else w.setPlainText(s); status('Pasted', 'ok')
    def err(e):
        if isinstance(e, Fail):
            status(str(e), 'err')
            if e.clear: show('')
        else: status('Something went wrong: ' + str(e), 'err')
    def run(msg, work, done):
        if st['busy']: return
        st['busy'] = True; status(msg); w = Worker(work); st['w'] = w
        def fin(cb):
            def f(r): st['busy'] = False; cb(r)
            return f
        w.ok.connect(fin(done)); w.bad.connect(fin(err)); w.start()
    def secret():
        k = key.text().strip()
        if not k: raise Fail('Enter a passphrase or key first.')
        return k
    def do_enc():
        try:
            t = inp.toPlainText()
            if not t.strip(): raise Fail('Type a message to encrypt first.')
            if segs['aes'].isChecked(): k = secret(); work = lambda: enc_aes(t, k)
            else:
                if not st['pub']: raise Fail('Add a public key first, or generate a key pair.')
                p = st['pub']; work = lambda: enc_rsa(t, p)
        except Fail as e: return err(e)
        al = sw_alien.isChecked()
        def done(r):
            show(pack(r[0], al), True, al); status('Encrypted with ' + r[1] + '.', 'ok')
            if sw_copy.isChecked(): copy(st['out'])
        run('Encrypting…', work, done)
    def do_dec():
        try:
            t = inp.toPlainText()
            if not t.strip(): raise Fail('Paste an encrypted message first.')
            if segs['aes'].isChecked(): k = secret(); work = lambda: dec_aes(unpack(t), k)
            else:
                if not st['priv']: raise Fail('Add your private key first.')
                p = st['priv']; work = lambda: dec_rsa(unpack(t), p)
        except Fail as e: return err(e)
        run('Decrypting…', work, lambda r: (show(r), status('Decrypted.', 'ok')))
    def swap():
        a, b = inp.toPlainText(), st['out']; inp.setPlainText(b)
        show(a, is_g(a) or re.fullmatch(r'[A-Za-z0-9+/=\s]{60,}', a) is not None); status('')
    def clear(): inp.clear(); show(''); status('')
    def wipe():
        for w in (key, pub_t, priv_t, inp): w.clear()
        st['pub'] = st['priv'] = None; show(''); hint(); refresh(); status('Cleared from this window', 'ok')
    def toggle_key():
        s = key.echoMode() == QLineEdit.Password; key.setEchoMode(QLineEdit.Normal if s else QLineEdit.Password); show_b.setText('Hide' if s else 'Show')
    def hint():
        k = key.text().strip(); weak = bool(k) and not is_hex(k) and len(k) < 10
        khint.setText('Use a passphrase, or make a random 256-bit key with Random key.' if not k else '256-bit key, used as is.' if is_hex(k) else
                      'Short passphrase. A longer one is safer.' if weak else 'Passphrase, stretched with PBKDF2 (600,000 rounds). Encrypting takes a moment.')
        khint.setStyleSheet('color:' + (C()['er'] if weak else C()['mu']))
    def gen(): key.setText(os.urandom(32).hex()); key.setEchoMode(QLineEdit.Normal); show_b.setText('Hide'); status('Random key made. Store it safely; messages need it.', 'ok')
    def master():
        has = bool(cfg.get('master')); mlab.setText('Master key saved on this computer, unencrypted.' if has else 'No master key saved.')
        mbtn[1].setVisible(has); mbtn[2].setVisible(has)
    def m_save():
        k = key.text().strip()
        if not k: return status('Enter a key first', 'err')
        cfg['master'] = k; save_cfg(); master(); status('Master key saved', 'ok')
    def m_use(): key.setText(cfg.get('master', '')); status('Master key loaded', 'ok')
    def m_del(): cfg.pop('master', None); save_cfg(); master(); status('Master key removed', 'ok')
    bad = {}
    def pill(l, text, color): l.setText(text); l.setStyleSheet(f'color:{color};border:1px solid {color};border-radius:9px;padding:1px 9px;font-size:11px;font-weight:600')
    def refresh():
        c = C()
        for p, k, t, n in ((pill_pub, st['pub'], 'Ready to encrypt', 'pub'), (pill_priv, st['priv'], 'Ready to decrypt', 'priv')):
            pill(p, 'Invalid' if bad.get(n) else t if k else 'Not set', c['er'] if bad.get(n) else c['ok'] if k else c['mu'])
        fp_l.setText('Fingerprint: ' + fingerprint(st['pub']) if st['pub'] else '')
    def hide_priv(h):
        st['hidden'] = h; tint(priv_t, C()['fd'] if h else ''); rev_b.setText('Reveal' if h else 'Hide')
    def key_text(w):
        try:
            if w == 'pub': st['pub'] = load_pub(pub_t.toPlainText())
            else:
                st['priv'] = load_priv(priv_t.toPlainText())
                if st['priv'] and not pub_t.toPlainText().strip(): st['pub'] = st['priv'].public_key(); pub_t.setPlainText(pem_pub(st['pub']))
            bad[w] = False
        except Fail as e: st[w] = None; bad[w] = True; status(str(e), 'err')
        refresh()
    timers = {}
    for w, t in (('pub', pub_t), ('priv', priv_t)):
        tm = QTimer(win); tm.setSingleShot(True); tm.setInterval(350); tm.timeout.connect(lambda w=w: key_text(w)); t.textChanged.connect(tm.start); timers[w] = tm
    def gen_rsa():
        def done(k):
            st['priv'], st['pub'] = k, k.public_key(); bad.clear(); pub_t.setPlainText(pem_pub(st['pub'])); priv_t.setPlainText(pem_priv(k)); refresh(); status('Key pair ready.', 'ok')
        run('Generating RSA-2048 keys…', lambda: rsa.generate_private_key(65537, 2048), done)
    def import_pem():
        f = QFileDialog.getOpenFileName(win, 'Import key', '', 'PEM keys (*.pem *.key *.txt);;All files (*)')[0]
        if not f: return
        t = Path(f).read_text(errors='ignore'); found = False
        for name, w in (('PUBLIC', pub_t), ('PRIVATE', priv_t)):
            m = re.search(rf'-----BEGIN {name} KEY-----[\s\S]*?-----END {name} KEY-----', t)
            if m: w.setPlainText(m.group(0)); found = True
        status('Key imported' if found else 'No PEM key found in that file', 'ok' if found else 'err')
    def save_keys():
        a, b = priv_t.toPlainText().strip(), pub_t.toPlainText().strip()
        if not a and not b: return status('No keys to save', 'err')
        d = QFileDialog.getExistingDirectory(win, 'Save keys to folder')
        if not d: return
        if a: p = Path(d) / 'private_key.pem'; p.write_text(a); os.chmod(p, 0o600)
        if b: (Path(d) / 'public_key.pem').write_text(b)
        status('Saved. Keep private_key.pem secret.', 'ok')
    def load_file(f):
        if not f: return
        if Path(f).stat().st_size > 2_000_000: return status('File too large (2 MB max)', 'err')
        inp.setPlainText(Path(f).read_text(errors='replace'))
    def open_file(): load_file(QFileDialog.getOpenFileName(win, 'Open text file', '', 'Text files (*.txt *.md *.json *.csv);;All files (*)')[0])
    def save_out():
        if not st['out']: return status('Nothing to save')
        f = QFileDialog.getSaveFileName(win, 'Save result', 'alien-message.txt', 'Text (*.txt)')[0]
        if f: Path(f).write_text(st['out'], encoding='utf-8'); status('Saved', 'ok')
    def pick_files(dec):
        fs = QFileDialog.getOpenFileNames(win, 'Choose files', '', 'Encrypted files (*.encrypted);;All files (*)' if dec else 'All files (*)')[0]
        run_files(fs, dec)
    def run_files(files, force):
        if st['busy'] or not files: return
        aes = segs['aes'].isChecked(); ctx = {'mode': 'aes' if aes else 'rsa', 'key': key.text().strip(), 'pub': st['pub'], 'priv': st['priv']}
        if any(not (force if force is not None else f.endswith('.encrypted')) for f in files):
            if aes and not ctx['key']: return status('Enter a passphrase or key first.', 'err')
            if not aes and not st['pub']: return status('Add a public key first, or generate a key pair.', 'err')
        st['busy'] = True; pbar.setValue(0); pbar.show(); status('Working…'); w = FWorker(lambda cb: batch(files, force, ctx, cb)); st['w'] = w
        def fin(r):
            st['busy'] = False; pbar.hide()
            if isinstance(r, Exception): return err(r)
            bad_ = [x for x in r if not x[1]]; ok_ = len(r) - len(bad_)
            status(f"{ok_} file{'s' if ok_ != 1 else ''} done, saved next to the originals." if not bad_ else f'{len(bad_)} failed. See details.', 'ok' if not bad_ else 'err')
            if bad_: QMessageBox.warning(win, 'Some files failed', '\n\n'.join(f'{n}: {m}' for n, _, m in bad_))
        w.prog.connect(lambda v, n: (pbar.setValue(v), status(n + '…'))); w.done.connect(fin); w.start()
    dz.files.connect(lambda fs: run_files(fs, None))
    def set_mode(m):
        segs[m].setChecked(True); stack.setCurrentIndex(0 if m == 'aes' else 1); cfg['mode'] = m; save_cfg()
    idle_t = QTimer(win); idle_t.setSingleShot(True); idle_t.setInterval(300000)
    idle_t.timeout.connect(lambda: (wipe(), status('Cleared after 5 minutes idle', 'ok')))
    def bump():
        idle_t.stop(); sw_idle.isChecked() and idle_t.start()
    def apply():
        app.setStyleSheet(QSS % C()); theme_b.setText('Light' if st['theme'] == 'dark' else 'Dark')
        hint(); refresh(); hide_priv(st['hidden']); show(st['out'], st['cipher']); counts()
    def toggle_theme():
        st['theme'] = 'light' if st['theme'] == 'dark' else 'dark'; cfg['theme'] = st['theme']; save_cfg(); apply()
    sw_alien.toggled.connect(lambda v: (cfg.update(alien=v), save_cfg())); sw_idle.toggled.connect(lambda v: (cfg.update(idle=v), save_cfg(), bump()))
    inp.textChanged.connect(counts); inp.dropped.connect(load_file); key.textChanged.connect(hint)
    for ks, f in (('Ctrl+Return', do_enc), ('Ctrl+Enter', do_enc), ('Ctrl+Shift+Return', do_dec)): QShortcut(QKeySequence(ks), win).activated.connect(f)
    idle_f = Idle(bump); app.installEventFilter(idle_f)
    apply(); set_mode(cfg.get('mode', 'aes')); master(); status('Ready. Ctrl+Enter encrypts, Ctrl+Shift+Enter decrypts.')
    win.on_resize(win.width()); win.show(); app.exec()

if __name__ == '__main__':
    main()
