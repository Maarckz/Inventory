
import os
import threading
from datetime import datetime
from io import BytesIO
import json
import ast

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, Image, Flowable,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.pdfgen import canvas as pdfcanvas

from utils import report_data as RD

from utils.language import LANGUAGES as _ALL_LANGS

_thread_lang = threading.local()

PDF_LANGS = ('pt', 'en', 'es', 'hi')

def _set_report_lang(lang):

    if lang in PDF_LANGS:
        _thread_lang.lang = lang
    elif lang in _ALL_LANGS:
        _thread_lang.lang = 'en'
    else:
        _thread_lang.lang = 'pt'

def tr(key):

    lang = getattr(_thread_lang, 'lang', 'pt')
    return (_ALL_LANGS.get(lang, {}).get(key)
            or _ALL_LANGS['pt'].get(key, key))

def dec(x):

    lang = getattr(_thread_lang, 'lang', 'pt')
    return str(x).replace('.', ',' if lang in ('pt', 'es') else '.')

INK       = colors.HexColor('#334155')
PRIMARY   = colors.HexColor('#4F46E5')
OK        = colors.HexColor('#10B981')
DANGER    = colors.HexColor('#EF4444')
SLATE     = colors.HexColor('#64748B')
DARK      = colors.HexColor('#1E293B')
BG_SOFT   = colors.HexColor('#F8FAFC')
BORDER    = colors.HexColor('#E2E8F0')

BRAND       = colors.HexColor('#7570E4')
COVER_DEEP  = colors.HexColor('#221D8F')
COVER_LINE  = colors.HexColor('#C3C0F5')
COVER_PANEL = colors.HexColor('#8984EC')
COVER_SUB   = colors.HexColor('#DDD9F9')
OK_LIGHT    = colors.HexColor('#6EE7B7')
WARN_LIGHT  = colors.HexColor('#FCD34D')
DANGER_LIGHT= colors.HexColor('#FCA5A5')
COVER_BG_TOP = colors.HexColor('#F4F3FD')
COVER_BG_BOT = colors.HexColor('#DFE9F9')
WARN_SOLID   = colors.HexColor('#F59E0B')

PAGE_W, PAGE_H = A4
M_LEFT = M_RIGHT = 40
CONTENT_W = PAGE_W - M_LEFT - M_RIGHT

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FONTS_DIR = os.path.join(_BASE, 'static', 'fonts', 'pdf')

FONT_MAIN = 'Helvetica'
FONT_BOLD = 'Helvetica-Bold'
FONT_MONO = 'Courier'

try:
    pdfmetrics.registerFont(TTFont('Inter', os.path.join(_FONTS_DIR, 'Inter-Regular.ttf')))
    pdfmetrics.registerFont(TTFont('Inter-Bold', os.path.join(_FONTS_DIR, 'Inter-Bold.ttf')))
    pdfmetrics.registerFont(TTFont('Inter-Mono', os.path.join(_FONTS_DIR, 'JetBrainsMono-Regular.ttf')))
    registerFontFamily('Inter', normal='Inter', bold='Inter-Bold',
                       italic='Inter', boldItalic='Inter-Bold')
    FONT_MAIN, FONT_BOLD, FONT_MONO = 'Inter', 'Inter-Bold', 'Inter-Mono'
except Exception:
    pass

_ICON_DIR = os.path.join(_BASE, 'static', 'icons', 'devtypes')
_ICON_TYPES = {'router', 'switch', 'ap', 'desktop', 'vm', 'rpi', 'phone',
               'smarttv', 'printer', 'camera', 'nas', 'server',
               'firewall', 'loadbalancer', 'hypervisor', 'storage',
               'laptop', 'tablet', 'voip', 'iot'}

_TYPE_LABELS = {
    'router': 'Router', 'switch': 'Switch', 'ap': 'Access Point',
    'firewall': 'Firewall', 'loadbalancer': 'Load Balancer',
    'server': 'Servidor (Server)', 'hypervisor': 'Hypervisor',
    'vm': 'Máquina Virtual (VM)', 'storage': 'Storage (SAN / NAS)',
    'desktop': 'Desktop', 'laptop': 'Laptop / Notebook', 'tablet': 'Tablet',
    'phone': 'Smartphone (Phone)', 'voip': 'Telefone IP (VoIP)',
    'printer': 'Impressora / Multifuncional (Printer)',
    'iot': 'Dispositivos IoT',
    'rpi': 'Raspberry Pi', 'smarttv': 'Smart TV', 'camera': 'Camera',
    'nas': 'NAS',
}

_LOGO_WHITE = os.path.join(_BASE, 'static', 'logos',
                           'inventory-wordmark-white.png')
_LOGO_INDIGO = os.path.join(_BASE, 'static', 'logos',
                            'inventory-wordmark-indigo.png')

import re as _re
import shutil as _shutil
import tempfile as _tempfile

_DEVA_RE = _re.compile(r'[\u0900-\u097F\u200c\u200d]')
_TAG_RE = _re.compile(r'(<[^>]+>)')
_FONT_ATTRS_RE = _re.compile(r'(size|color)\s*=\s*["\']([^"\']*)["\']')

_HI_SCALE = 4
_HI_NOTO_REG = os.path.join(_FONTS_DIR, 'NotoSansDevanagari-Regular.ttf')
_HI_NOTO_BOLD = os.path.join(_FONTS_DIR, 'NotoSansDevanagari-Bold.ttf')
_HI_OK = False
_HI_CACHE = {}
_HI_DIR = None
_HI_N = [0]

try:
    from PIL import Image as _PILImage, ImageDraw as _PILDraw, ImageFont as _PILFont
    from PIL import features as _PILFeatures
    if (os.path.exists(_HI_NOTO_REG) and os.path.exists(_HI_NOTO_BOLD)
            and _PILFeatures.check('raqm')):
        _HI_OK = True
except Exception:
    _HI_OK = False

def _hi_font(size_pt, bold):

    path = _HI_NOTO_BOLD if bold else _HI_NOTO_REG
    try:
        return _PILFont.truetype(path, max(4, int(size_pt * _HI_SCALE)),
                                 layout_engine=_PILFont.Layout.RAQM)
    except Exception:
        return _PILFont.truetype(path, max(4, int(size_pt * _HI_SCALE)))

def _hi_dir():

    global _HI_DIR
    if _HI_DIR is None:
        _HI_DIR = _tempfile.mkdtemp(prefix='inv_hi_')
    return _HI_DIR

def _hi_cleanup():

    global _HI_DIR
    _HI_CACHE.clear()
    _HI_N[0] = 0
    if _HI_DIR and os.path.isdir(_HI_DIR):
        try:
            _shutil.rmtree(_HI_DIR, ignore_errors=True)
        except Exception:
            pass
    _HI_DIR = None

def _rgb_tuple(rl_color):

    try:
        return tuple(int(round(c * 255)) for c in rl_color.rgb()[:3])
    except Exception:
        return (30, 41, 59)

def _hi_frag(text, size_pt, bold, rgb):

    key = (text, round(float(size_pt), 2), bool(bold), rgb)
    if key in _HI_CACHE:
        return _HI_CACHE[key]

    font = _hi_font(size_pt, bold)
    asc, desc = font.getmetrics()
    scratch = _PILDraw.Draw(_PILImage.new('L', (4, 4)))
    l, t, r, b = scratch.textbbox((0, 0), text, font=font)
    w_px = max(2, r - l + 2)
    h_px = asc + desc
    im = _PILImage.new('RGBA', (w_px, h_px), (0, 0, 0, 0))
    _PILDraw.Draw(im).text((-l, 0), text, font=font, fill=(*rgb, 255))
    path = os.path.join(_hi_dir(), f'hi_{_HI_N[0]}.png')
    _HI_N[0] += 1
    im.save(path)
    frag = (path, w_px / _HI_SCALE, h_px / _HI_SCALE, -desc / _HI_SCALE)
    _HI_CACHE[key] = frag
    return frag

def _hi_img_tag(text, size_pt, bold, rgb):

    path, w, h, va = _hi_frag(text, size_pt, bold, rgb)
    return (f'<img src="{path}" width="{w:.2f}" height="{h:.2f}" '
            f'valign="{va:.2f}"/>')

def _split_deva(text):

    runs, cur, cur_dev = [], '', None
    for ch in text:
        dev = bool(_DEVA_RE.match(ch))
        if cur_dev is None or dev == cur_dev:
            cur += ch
        else:
            runs.append((cur_dev, cur))
            cur = ch
        cur_dev = dev
    if cur:
        runs.append((cur_dev, cur))
    return runs

def _deva_inline(text, size_pt, bold, rgb):

    out = []
    for dev, chunk in _split_deva(text):
        if not dev or not chunk.strip():
            out.append(chunk)
            continue
        lead = ' ' if chunk[:1] == ' ' else ''
        trail = ' ' if chunk[-1:] == ' ' else ''
        core = chunk.strip()
        out.append(f'{lead}{_hi_img_tag(core, size_pt, bold, rgb)}{trail}')
    return ''.join(out)

def _hindi_markup(markup, style):

    size = getattr(style, 'fontSize', 8.5) or 8.5
    bold = str(getattr(style, 'fontName', FONT_MAIN)) == FONT_BOLD
    rgb = _rgb_tuple(getattr(style, 'textColor', None) or DARK)

    out = []
    for tok in _TAG_RE.split(markup):
        if not tok:
            continue
        if tok.startswith('<'):
            out.append(tok)
            tl = tok.lower()
            if tl == '<b>':
                bold = True
            elif tl == '</b>':
                bold = False
            elif tl.startswith('<font'):
                for attr, val in _FONT_ATTRS_RE.findall(tok):
                    if attr == 'size':
                        try:
                            size = float(val)
                        except ValueError:
                            pass
                    elif attr == 'color':
                        try:
                            rgb = _rgb_tuple(colors.HexColor(val))
                        except Exception:
                            pass
            elif tl == '</font>':
                size = getattr(style, 'fontSize', 8.5) or 8.5
                bold = str(getattr(style, 'fontName', FONT_MAIN)) == FONT_BOLD
                rgb = _rgb_tuple(getattr(style, 'textColor', None) or DARK)
        else:
            out.append(_deva_inline(tok, size, bold, rgb))
    return ''.join(out)

def _P(markup, style, *args, **kwargs):

    if (getattr(_thread_lang, 'lang', 'pt') == 'hi' and _HI_OK
            and isinstance(markup, str) and _DEVA_RE.search(markup)):
        try:
            markup = _hindi_markup(markup, style)
        except Exception:
            pass
    return Paragraph(markup, style, *args, **kwargs)

def _cv_text(cv, x, y, text, size=8.5, bold=False, color=SLATE,
             align='left', font=None):

    fname = font or (FONT_BOLD if bold else FONT_MAIN)
    if not (_HI_OK and getattr(_thread_lang, 'lang', 'pt') == 'hi'
            and isinstance(text, str) and _DEVA_RE.search(text)):
        cv.setFont(fname, size)
        cv.setFillColor(color)
        if align == 'right':
            cv.drawRightString(x, y, text)
        else:
            cv.drawString(x, y, text)
        return

    rgb = _rgb_tuple(color)
    segs = []
    for dev, chunk in _split_deva(text):
        if not chunk:
            continue
        if dev and chunk.strip():
            core = chunk.strip()
            path, w, h, va = _hi_frag(core, size, bold, rgb)
            segs.append(('img', path, w, h, va))
        else:
            w = pdfmetrics.stringWidth(chunk, fname, size)
            segs.append(('txt', chunk, w))
    total = sum(s[2] for s in segs)
    cx = (x - total) if align == 'right' else x
    for s in segs:
        if s[0] == 'txt':
            cv.setFont(fname, size)
            cv.setFillColor(color)
            cv.drawString(cx, y, s[1])
            cx += s[2]
        else:
            _, path, w, h, va = s
            cv.drawImage(path, cx, y + va, width=w, height=h,
                         mask='auto', preserveAspectRatio=False)
            cx += w

def dev_icon_img(dev_type, size=9.5, valign=-2):

    t = str(dev_type or 'server').strip().lower()
    if t not in _ICON_TYPES:
        t = 'server'
    src = os.path.join(_ICON_DIR, f'{t}.png')
    if not os.path.exists(src):
        return ''
    return (f'<img src="{src}" width="{size}" height="{size}" '
            f'valign="{valign}"/>')

def _switch_display_name(sw):

    return (str(sw.get('hostname') or '').strip()
            or str(sw.get('name') or '').strip()
            or str(sw.get('ip') or '').strip()
            or str(sw.get('mac') or '').strip())

def _switch_names_map(switches):

    out = {}
    for sw in (switches or []):
        key = str(sw.get('mac') or '').strip().lower()
        if key:
            out[key] = _switch_display_name(sw)
    return out

def _port_is_configured(p, i):

    default_label = f'Fa0/{i}'
    return bool(
        (p.get('label') or '').strip() and p['label'].strip() != default_label
        or (p.get('vlan') or '').strip()
        or (p.get('device_mac') or '').strip()
        or (p.get('speed') or '').strip()
        or (p.get('duplex') or '').strip()
        or (p.get('notes') or '').strip())

def _configured_switches(switches):

    out = []
    for sw in (switches or []):
        ports = [p for p in (sw.get('ports') or [])
                 if _port_is_configured(p, p.get('port', 0))]
        if ports:
            out.append((sw, ports))
    return out

def _switch_link_line(ns, sw_names):

    sp = (ns or {}).get('switch_port')
    if not isinstance(sp, dict) or not sp:
        return ''
    parts = []
    key = str(sp.get('switch_mac') or '').strip().lower()
    sw_name = sw_names.get(key) or str(sp.get('switch_mac') or '').strip()
    if sw_name:
        parts.append(f"<b>{tr('Switch')}:</b> {_trunc(sw_name, 30)}")
    if sp.get('port') not in (None, '', 0, '0'):
        parts.append(f"<b>{tr('Porta')}:</b> {sp.get('port')}")
    label = str(sp.get('label') or '').strip()
    if label:
        parts.append(f"<b>Label:</b> {_trunc(label, 24)}")
    vlan = str(sp.get('vlan') or '').strip()
    if vlan:
        parts.append(f"<b>VLAN:</b> {_trunc(vlan, 10)}")
    return ' &nbsp;·&nbsp; '.join(parts)

def get_value(obj, key, default='N/A'):

    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _parse_jsonish(raw):

    if isinstance(raw, str):
        for conv in (json.loads, ast.literal_eval):
            try:
                return conv(raw)
            except Exception:
                continue
        return []
    return raw or []

def normalize_details(machine):

    ifaces = _parse_jsonish(get_value(machine, 'netiface', []))
    ports = _parse_jsonish(get_value(machine, 'ports', []))
    addrs = _parse_jsonish(get_value(machine, 'netaddr', []))
    return ifaces, addrs, ports

def fmt_dt(iso, with_time=True):

    s = str(iso or '').strip()
    if not s or s == 'N/A':
        return '—'
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M' if with_time else '%d/%m/%Y')
    except ValueError:
        return s[:16].replace('T', ' ')

def _trunc(s, n):

    s = str(s)
    return s if len(s) <= n else s[: n - 1].rstrip() + '…'

def _fmt_gb(v):

    if not isinstance(v, (int, float)):
        return '—'
    txt = dec(f'{v:.1f}'.replace('.0', ''))
    return f'{txt} GB'

def _machine_type(ns):

    t = str((ns or {}).get('type') or '').strip().lower()
    return t if t in _ICON_TYPES else 'server'

class NumberedCanvas(pdfcanvas.Canvas):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_states = []

    def showPage(self):
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_states)
        for state in self._saved_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total):

        if self._pageNumber == 1:
            return
        self.saveState()
        self.setStrokeColor(BORDER)
        self.setLineWidth(0.8)
        self.line(M_LEFT, 42, PAGE_W - M_RIGHT, 42)
        _cv_text(self, M_LEFT, 30,
                 tr('Inventory — Relatório de Inventário'),
                 size=7.5, color=SLATE)
        _cv_text(self, PAGE_W - M_RIGHT, 30,
                 tr('Página {} de {}').format(self._pageNumber, total),
                 size=7.5, color=SLATE, align='right')
        self.restoreState()

def _header_band(cv, doc):

    if cv.getPageNumber() == 1:
        return
    cv.saveState()
    try:
        cv.drawImage(_LOGO_INDIGO,
                     M_LEFT, PAGE_H - 44, width=57, height=20,
                     preserveAspectRatio=True, mask='auto')
    except Exception:
        cv.setFont(FONT_BOLD, 12)
        cv.setFillColor(BRAND)
        cv.drawString(M_LEFT, PAGE_H - 40, 'INVENTORY')
    _cv_text(cv, PAGE_W - M_RIGHT, PAGE_H - 36, tr('RELATÓRIO DE INVENTÁRIO'),
             size=8.5, bold=True, color=SLATE, align='right')
    cv.setStrokeColor(BRAND)
    cv.setLineWidth(0.8)
    cv.line(M_LEFT, PAGE_H - 52, PAGE_W - M_RIGHT, PAGE_H - 52)
    cv.restoreState()

def _cover_background(cv, doc):

    cv.saveState()
    cv.linearGradient(0, PAGE_H, 0, 0, [COVER_BG_TOP, COVER_BG_BOT],
                      positions=[0.0, 1.0], extend=True)
    cv.restoreState()

def _styles():
    ss = {}
    ss['h1'] = ParagraphStyle('H1', fontName=FONT_BOLD, fontSize=24,
                              leading=29, textColor=DARK, spaceAfter=2)
    ss['h1sub'] = ParagraphStyle('H1sub', fontName=FONT_MAIN, fontSize=10.5,
                                 leading=14, textColor=SLATE)
    ss['h2'] = ParagraphStyle('H2', fontName=FONT_BOLD, fontSize=13,
                              leading=17, textColor=INK, spaceBefore=12,
                              spaceAfter=5)
    ss['h3'] = ParagraphStyle('H3', fontName=FONT_BOLD, fontSize=10,
                              leading=13, textColor=DARK, spaceBefore=9,
                              spaceAfter=4)
    ss['body'] = ParagraphStyle('Body', fontName=FONT_MAIN, fontSize=8.5,
                                leading=12, textColor=DARK)
    ss['small'] = ParagraphStyle('Small', fontName=FONT_MAIN, fontSize=7.5,
                                 leading=10, textColor=SLATE)
    ss['cell'] = ParagraphStyle('Cell', fontName=FONT_MAIN, fontSize=8,
                                leading=10.5, textColor=DARK)
    ss['mono'] = ParagraphStyle('Mono', fontName=FONT_MONO, fontSize=7.5,
                                leading=10, textColor=DARK)
    ss['kpi_num'] = ParagraphStyle('KpiNum', fontName=FONT_BOLD, fontSize=19,
                                   leading=22, alignment=TA_CENTER)
    ss['kpi_lbl'] = ParagraphStyle('KpiLbl', fontName=FONT_MAIN, fontSize=7,
                                   leading=9, alignment=TA_CENTER,
                                   textColor=SLATE)

    ss['cov_h1'] = ParagraphStyle('CovH1', fontName=FONT_BOLD, fontSize=21,
                                  leading=26, alignment=TA_CENTER,
                                  textColor=DARK)
    ss['cov_sub'] = ParagraphStyle('CovSub', fontName=FONT_MAIN, fontSize=10.5,
                                   leading=14, alignment=TA_CENTER,
                                   textColor=SLATE)
    ss['p2meta'] = ParagraphStyle('P2Meta', fontName=FONT_MAIN, fontSize=7.5,
                                  leading=10, alignment=TA_LEFT,
                                  textColor=SLATE)
    ss['cov_kpi'] = ParagraphStyle('CovKpi', fontName=FONT_BOLD, fontSize=19,
                                   leading=22, alignment=TA_CENTER,
                                   textColor=DARK)
    ss['cov_kpi_lbl'] = ParagraphStyle('CovKpiLbl', fontName=FONT_MAIN,
                                       fontSize=7.2, leading=9,
                                       alignment=TA_CENTER,
                                       textColor=SLATE)
    ss['cov_kpi_sub'] = ParagraphStyle('CovKpiSub', fontName=FONT_MAIN,
                                       fontSize=6.8, leading=8.5,
                                       alignment=TA_CENTER, textColor=SLATE)
    ss['cov_chart'] = ParagraphStyle('CovChart', fontName=FONT_BOLD, fontSize=9,
                                     leading=12, alignment=TA_LEFT,
                                     textColor=DARK)
    ss['thead'] = ParagraphStyle('Thead', fontName=FONT_BOLD, fontSize=7.5,
                                 leading=9.5, textColor=colors.white)
    ss['num'] = ParagraphStyle('Num', fontName=FONT_BOLD, fontSize=8,
                               leading=10.5, textColor=DARK, alignment=TA_RIGHT)
    return ss

S = _styles()

def rank_table(entries, total, label_header, width=246,
               suffix='', max_label=40, show_pct=True):

    if show_pct:
        w_lbl, w_cnt, w_pct = width - 56 - 46, 56, 46
        header = [_P(label_header, S['thead']),
                  _P(tr('Máquinas'), S['thead']),
                  _P(tr('% total'), S['thead'])]
    else:
        w_lbl, w_cnt = width - 66, 66
        header = [_P(label_header, S['thead']),
                  _P(tr('Valor'), S['thead'])]
    rows = [header]
    if not entries:
        if show_pct:
            rows.append([_P(tr('Sem dados coletados'), S['cell']),
                         _P('—', S['num']), _P('—', S['num'])])
        else:
            rows.append([_P(tr('Sem dados coletados'), S['cell']),
                         _P('—', S['num'])])
    for label, count in entries:
        if isinstance(count, float):
            count_str = dec(f'{count:.1f}')
        else:
            count_str = str(int(count))
        if show_pct:
            pct = dec(f'{100.0 * count / total:.1f}') if total else '—'
            rows.append([
                _P(_trunc(str(label), max_label), S['cell']),
                _P(f'{count_str}{suffix}', S['num']),
                _P(f'{pct}%', S['num']),
            ])
        else:
            rows.append([
                _P(_trunc(str(label), max_label), S['cell']),
                _P(f'{count_str}{suffix}', S['num']),
            ])
    t = Table(rows, colWidths=([w_lbl, w_cnt, w_pct] if show_pct
                               else [w_lbl, w_cnt]), repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, -1), (-1, -1), 0.8, BORDER),
        ('LINEBELOW', (0, 0), (-1, 0), 1, INK),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    return t

def cpu_full_table(entries, total, max_rows=14):

    header = [_P(tr('Modelo de CPU'), S['thead']),
              _P(tr('Máquinas'), S['thead']),
              _P(tr('% total'), S['thead'])]
    w_lbl, w_cnt, w_pct = CONTENT_W - 60 - 50, 60, 50
    rows = [header]
    if not entries:
        rows.append([_P(tr('Sem dados coletados'), S['cell']),
                     _P('—', S['num']), _P('—', S['num'])])
    shown = entries[:max_rows]
    for name, count in shown:
        pct = dec(f'{100.0 * count / total:.1f}') if total else '—'
        rows.append([_P(str(name), S['cell']),
                     _P(str(int(count)), S['num']),
                     _P(f'{pct}%', S['num'])])
    extra = len(entries) - len(shown)
    if extra > 0:
        rows.append([_P(tr('… e mais {} modelos').format(extra), S['small']),
                     _P('—', S['num']), _P('—', S['num'])])
    t = Table(rows, colWidths=[w_lbl, w_cnt, w_pct], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, -1), (-1, -1), 0.8, BORDER),
        ('LINEBELOW', (0, 0), (-1, 0), 1, INK),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    return t

def os_kernel_table(entries, total, max_rows=16):

    header = [_P(tr('Sistema Operacional'), S['thead']),
              _P(tr('Versão do sistema'), S['thead']),
              _P(tr('Kernel'), S['thead']),
              _P(tr('Máquinas'), S['thead']),
              _P(tr('% total'), S['thead'])]
    w_sys, w_ver, w_krn = 150, 150, 105
    w_cnt, w_pct = 60, 50
    rows = [header]
    if not entries:
        rows.append([_P(tr('Sem dados coletados'), S['cell']),
                     _P('—', S['cell']), _P('—', S['cell']),
                     _P('—', S['num']), _P('—', S['num'])])
    shown = entries[:max_rows]
    for name, ver, kern, count in shown:
        pct = dec(f'{100.0 * count / total:.1f}') if total else '—'
        rows.append([
            _P(_trunc(str(name), 30), S['cell']),
            _P(_trunc(str(ver), 32) or '—', S['cell']),
            _P(_trunc(str(kern), 24) or '—', S['mono']),
            _P(str(int(count)), S['num']),
            _P(f'{pct}%', S['num']),
        ])
    extra = len(entries) - len(shown)
    if extra > 0:
        note = tr('… e mais {} combinações').format(extra)
        rows.append([_P(note, S['small']), _P('', S['cell']),
                     _P('', S['cell']), _P('—', S['num']),
                     _P('—', S['num'])])
    t = Table(rows, colWidths=[w_sys, w_ver, w_krn, w_cnt, w_pct],
              repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, -1), (-1, -1), 0.8, BORDER),
        ('LINEBELOW', (0, 0), (-1, 0), 1, INK),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    return t

def kv_table(pairs, width=CONTENT_W, two_cols=True):

    if not pairs:
        return None
    rows = []
    if two_cols:
        for i in range(0, len(pairs), 2):
            left = pairs[i]
            right = pairs[i + 1] if i + 1 < len(pairs) else ('', '')
            rows.append([
                _P(f'<b>{_trunc(left[0], 28)}</b>', S['small']),
                _P(str(left[1]), S['cell']),
                _P(f'<b>{_trunc(right[0], 28)}</b>', S['small']),
                _P(str(right[1]), S['cell']),
            ])
        w = (width * 0.24, width * 0.26, width * 0.24, width * 0.26)
    else:
        for k, v in pairs:
            rows.append([
                _P(f'<b>{_trunc(k, 30)}</b>', S['small']),
                _P(str(v), S['cell']),
            ])
        w = (width * 0.28, width * 0.72)
    t = Table(rows, colWidths=w)
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, BG_SOFT]),
        ('BOX', (0, 0), (-1, -1), 0.6, BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.3, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
    ]))
    return t

def _side_by_side(title_left, flow_left, title_right, flow_right,
                  pad=14):

    def cell(title, flow):
        inner = [
            _P(f'<b>{title}</b>', S['h3']),
            flow,
        ]
        t = Table([[x] for x in inner], colWidths=[CONTENT_W / 2 - pad / 2])
        t.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ]))
        return t

    row = Table([[cell(title_left, flow_left), cell(title_right, flow_right)]],
                colWidths=[CONTENT_W / 2, CONTENT_W / 2])
    row.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (0, -1), 0),
        ('RIGHTPADDING', (1, 0), (1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return row

class _CoverDonutDrawing(Flowable):

    def __init__(self, entries, width, height, label_max=24):
        super().__init__()
        self.entries = entries
        self.width, self.height = width, height
        self.label_max = label_max

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        cv = self.canv
        w, h = self.width, self.height
        total = sum(c for _, c, _ in self.entries) or 1
        donut_h = min(h * 0.52, w * 0.62)
        r_out = donut_h / 2.0
        r_in = r_out * 0.62
        cx, cy = w / 2.0, h - r_out - 2
        start = 90.0
        if not self.entries:
            cv.setStrokeColor(BORDER)
            cv.setLineWidth(r_out - r_in)
            cv.circle(cx, cy, (r_out + r_in) / 2.0, stroke=1, fill=0)
            txt = tr('Sem dados')
            half = pdfmetrics.stringWidth(txt, FONT_MAIN, 6.5) / 2.0
            _cv_text(cv, cx - half, cy - 2.5, txt, size=6.5, color=SLATE)
            return
        for label, count, col in self.entries:
            ext = 360.0 * count / total
            if ext <= 0:
                continue
            cv.saveState()
            cv.setFillColor(col)
            cv.setStrokeColor(colors.white)
            cv.setLineWidth(0.8)
            x1, y1 = cx - r_out, cy - r_out
            x2, y2 = cx + r_out, cy + r_out
            cv.wedge(x1, y1, x2, y2, start, -ext, stroke=1, fill=1)
            cv.restoreState()
            start -= ext
        cv.setFillColor(colors.white)
        cv.circle(cx, cy, r_in, stroke=0, fill=1)
        cv.setFillColor(DARK)
        cv.setFont(FONT_BOLD, 9)
        cv.drawCentredString(cx, cy - 3, str(total))
        row_h = 10.5
        legend_top = h - r_out * 2 - 8
        y = legend_top
        for label, count, col in self.entries:
            y -= row_h
            if y < 0:
                break
            cv.setFillColor(col)
            cv.circle(6, y + 2.2, 2.4, stroke=0, fill=1)
            _cv_text(cv, 13, y, _trunc(str(label), self.label_max),
                     size=6.5, color=DARK)
            _cv_text(cv, w - 4, y, str(count), size=6.5, bold=True,
                     color=DARK, align='right')

def _cover_page(elements, ctx, os_dist, agent_status):

    if os.path.exists(_LOGO_INDIGO):
        logo = Image(_LOGO_INDIGO, width=240, height=84.3)
        logo.hAlign = 'CENTER'
        elements.append(Spacer(1, 40))
        elements.append(logo)
        elements.append(Spacer(1, 14))
    else:
        elements.append(Spacer(1, 70))
        elements.append(_P('INVENTORY', S['cov_h1']))
        elements.append(Spacer(1, 18))

    elements.append(_P(tr('RELATÓRIO DE INVENTÁRIO'), S['cov_h1']))
    elements.append(Spacer(1, 7))
    rule = Table([['']], colWidths=[180], rowHeights=[1])
    rule.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BRAND),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    rule.hAlign = 'CENTER'
    elements.append(rule)
    elements.append(Spacer(1, 8))
    elements.append(_P(tr('Inventory · Inventário de TI'), S['cov_sub']))
    elements.append(Spacer(1, 30))

    def kpi_card(num, label, accent, value_color, sub=None):

        num_p = ParagraphStyle('n', parent=S['cov_kpi'], textColor=value_color)
        sub_par = _P(sub if sub else '<br/>', S['cov_kpi_sub'])
        t = Table(
            [[_P(f'<b>{label}</b>', S['cov_kpi_lbl'])],
             [_P(f'<b>{num}</b>', num_p)],
             [sub_par]],
            colWidths=[CONTENT_W / 4 - 9], rowHeights=[12, 24, 19])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 0.7, BORDER),
            ('LINEABOVE', (0, 0), (-1, 0), 2.2, accent),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'TOP'),
            ('VALIGN', (0, 1), (-1, 1), 'MIDDLE'),
            ('VALIGN', (0, 2), (-1, 2), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, 0), 4),
            ('TOPPADDING', (0, 1), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (0, 0), 0),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 0),
            ('BOTTOMPADDING', (0, 2), (-1, 2), 3),
        ]))
        return t

    total_sub = (f'<b>{ctx["wazuh_count"]}</b> {tr("com agente")}'
                 f'<br/><b>{ctx["no_agent"]}</b> {tr("sem agente")}')
    kpis = [
        (ctx['total'], tr('Total de Máquinas'), PRIMARY, PRIMARY, total_sub),
        (ctx['online'], tr('Agentes Wazuh Online'), OK, OK, None),
        (ctx['offline'], tr('Agentes Wazuh Offline'), WARN_SOLID, WARN_SOLID,
         None),
        (ctx['no_agent'], tr('Sem Agente Wazuh'), DANGER, DANGER, None),
    ]
    kpi_row = Table(
        [[kpi_card(n, l, a, vc, s) for n, l, a, vc, s in kpis]],
        colWidths=[CONTENT_W / 4] * 4)
    kpi_row.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
    ]))
    kpi_row.hAlign = 'CENTER'
    elements.append(kpi_row)
    elements.append(Spacer(1, 20))

    def chart_card(title, drawing):

        t = Table(
            [[_P(f'<b>{title}</b>', S['cov_chart'])], [drawing]],
            colWidths=[CONTENT_W / 3 - 8], rowHeights=[18, 168])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 0.7, BORDER),
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, BORDER),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('VALIGN', (0, 1), (-1, 1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, 0), 8),
            ('LEFTPADDING', (0, 1), (-1, 1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        return t

    coverage_segments = [
        (tr('Com agente'), ctx['wazuh_count'], PRIMARY),
        (tr('Sem agente'), ctx['no_agent'], SLATE),
    ]
    status_segments = [
        (tr('Agentes Ativos'), agent_status.get('active', 0), OK),
        (tr('Agentes Desconectados'), agent_status.get('disconnected', 0),
         DANGER),
        (tr('Nunca Conectaram'), agent_status.get('never_connected', 0),
         SLATE),
    ]
    status_segments = [s for s in status_segments if s[1] > 0] \
        or [(tr('Sem dados'), 0, SLATE)]
    _COVER_PALETTE = [colors.HexColor(c) for c in (
        '#6366F1', '#8B5CF6', '#0EA5E9', '#10B981', '#F59E0B')]
    top_os = list(os_dist[:5])
    rest = sum(c for _, c in os_dist[5:])
    os_segments = [(name, count, _COVER_PALETTE[i])
                   for i, (name, count) in enumerate(top_os)]
    if rest:
        os_segments.append((tr('Outros'), rest, SLATE))
    if not os_segments:
        os_segments = [(tr('Sem dados'), 0, SLATE)]

    charts_row = Table(
        [[
            chart_card(tr('Cobertura de Agentes Wazuh'),
                       _CoverDonutDrawing(coverage_segments,
                                          CONTENT_W / 3 - 24, 160)),
            chart_card(tr('Status dos Agentes Wazuh'),
                       _CoverDonutDrawing(status_segments,
                                          CONTENT_W / 3 - 24, 160)),
            chart_card(tr('Sistemas Operacionais'),
                       _CoverDonutDrawing(os_segments,
                                          CONTENT_W / 3 - 24, 160)),
        ]],
        colWidths=[CONTENT_W / 3] * 3)
    charts_row.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
    ]))
    charts_row.hAlign = 'CENTER'
    elements.append(charts_row)

def _wazuh_os_label(m):

    os_name = str((m or {}).get('os_name') or '').strip()
    os_ver = str((m or {}).get('os_version') or '').strip()
    if os_ver in ('N/A', 'unknown', 'Unknown', 'None'):
        os_ver = ''
    if not os_name or os_name in ('N/A', 'unknown', 'Unknown', 'None'):
        os_name = 'Unknown'
    return f'{os_name} {os_ver}'.strip()

def _row_mac(row):

    m, ns = row.get('machine'), row.get('ns')
    for iface in ((m or {}).get('netiface') or []):
        mac = str(iface.get('mac') or '').strip()
        if mac and mac.lower() not in ('n/a', 'none', 'unknown'):
            return mac
    return str((ns or {}).get('mac') or '').strip()

def _consolidated_table(rows, sw_names):

    headers = [tr('Hostname'), 'IP', tr('Tipo / Sistema'),
               tr('Agente Wazuh'), tr('Fabricante'),
               tr('Documentação'), tr('Switch')]
    col_w = [112, 62, 92, 46, 74, 74, 55]

    rows_out = [[_P(h, S['thead']) for h in headers]]
    for r in rows:
        m, ns = r['machine'], r['ns']

        icon = dev_icon_img(_machine_type(ns))
        host_cell = ''
        if ns:
            online_scan = (str(ns.get('status') or '').strip().lower()
                           == 'online')
            host_cell += (f"<font color='{'#10B981' if online_scan else '#94A3B8'}' size='8'>•</font> ")
        host_cell += f'{icon} <b>{_trunc(r["hostname"], 20)}</b>'
        mac = _row_mac(r)
        if mac:
            host_cell += (f"<br/><font size='6.3' color='#64748B' "
                          f"face='{FONT_MONO}'>{_trunc(mac, 17)}</font>")
        host_p = _P(host_cell, S['cell'])

        ip_p = _P(_trunc(r['ip'], 15), S['mono'])

        dtype = str((ns or {}).get('type') or '').strip().lower()
        so = _wazuh_os_label(m) if m else str((ns or {}).get('os') or '').strip()
        if so in ('N/A', 'None', 'unknown', 'Unknown'):
            so = ''
        if dtype:
            tipo_lbl = tr(_TYPE_LABELS.get(dtype, dtype))
            tipo_cell = _trunc(tipo_lbl, 18)
            if so:
                tipo_cell += (f"<br/><font size='6.3' color='#64748B'>"
                              f'{_trunc(so, 32)}</font>')
            tipo_p = _P(tipo_cell, S['cell'])
        else:
            tipo_p = _P(_trunc(so or '—', 32), S['cell'])

        if m:
            online = str(m.get('agent_status_raw') or '').strip().lower() == 'active'
        elif ns and ns.get('has_agent') and ns.get('agent_status'):
            online = str(ns.get('agent_status')) == 'active'
        else:
            online = None
        if online is None:
            ag_p = _P("<font color='#94A3B8'>—</font>", S['cell'])
        else:
            ag_p = _P(
                f"<font color='{'#10B981' if online else '#EF4444'}'>"
                f'<b>{tr("Online") if online else tr("Offline")}</b></font>',
                S['cell'])

        vendor = str((ns or {}).get('vendor') or '').strip()
        model = str((ns or {}).get('model') or '').strip()
        if vendor and model:
            fab_p = _P(f'{_trunc(vendor, 18)}<br/>'
                       f"<font size='6.3' color='#64748B'>"
                       f'{_trunc(model, 24)}</font>', S['cell'])
        elif vendor or model:
            fab_p = _P(_trunc(vendor or model, 24), S['cell'])
        else:
            fab_p = _P("<font color='#94A3B8'>—</font>", S['cell'])

        doc_lines = []
        for label, key in ((tr('Usuário'), 'user'), (tr('Depto'), 'department'),
                           (tr('Local'), 'location'), ('Asset Tag', 'asset_tag'),
                           (tr('Lacre'), 'seal_number')):
            v = str((ns or {}).get(key) or '').strip()
            if v and v not in ('N/A', 'None'):
                doc_lines.append(f'{label}: {_trunc(v, 20)}')
        if doc_lines:
            doc_p = _P("<font size='6.3'>" + '<br/>'.join(doc_lines) + '</font>',
                       S['cell'])
        else:
            doc_p = _P("<font color='#94A3B8'>—</font>", S['cell'])

        sw_lines = []
        sp = (ns or {}).get('switch_port')
        if isinstance(sp, dict):
            swk = str(sp.get('switch_mac') or '').strip().lower()
            sw_name = sw_names.get(swk) or (swk[:12] if swk else '')
            if sw_name:
                sw_lines.append(_trunc(sw_name, 12))
            if sp.get('port') not in (None, '', 0, '0'):
                sw_lines.append(f"{tr('Porta')} {sp.get('port')}")
            vlan = str(sp.get('vlan') or '').strip()
            if vlan:
                sw_lines.append(f'VLAN {_trunc(vlan, 8)}')
        if sw_lines:
            sw_p = _P("<font size='6.3'>" + '<br/>'.join(sw_lines) + '</font>',
                      S['cell'])
        else:
            sw_p = _P("<font color='#94A3B8'>—</font>", S['cell'])

        rows_out.append([host_p, ip_p, tipo_p, ag_p, fab_p, doc_p, sw_p])

    t = Table(rows_out, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
        ('LINEBELOW', (0, 0), (-1, 0), 1, INK),
        ('LINEBELOW', (0, -1), (-1, -1), 0.8, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    return t

def _switches_blocks(switches):

    sw_names = _switch_names_map(switches)
    configured = _configured_switches(switches)
    blocks = []
    for sw, ports in configured:
        name = _switch_display_name(sw)
        ip = str(sw.get('ip') or '').strip()
        head = (f"{dev_icon_img('switch', size=10, valign=-2)} "
                f"<b>{_trunc(name, 36)}</b>"
                + (f' <font size="8" color="#64748B">({ip})</font>' if ip else ''))
        trows = [[_P(tr('Porta'), S['thead']),
                  _P(tr('Label'), S['thead']),
                  _P(tr('VLAN'), S['thead']),
                  _P(tr('Dispositivo conectado'), S['thead'])]]
        for p in ports:
            dev = str(p.get('device_name') or '').strip()
            if not dev:
                dev = str(p.get('device_ip') or '').strip()
            trows.append([
                _P(str(p.get('port', '—')), S['mono']),
                _P(_trunc(str(p.get('label') or '—'), 22), S['cell']),
                _P(_trunc(str(p.get('vlan') or '—'), 10), S['cell']),
                _P(_trunc(dev or '—', 30), S['cell']),
            ])
        t = Table(trows, colWidths=[50, 110, 55, 300], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), INK),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
            ('LINEBELOW', (0, 0), (-1, 0), 1, INK),
            ('LINEBELOW', (0, -1), (-1, -1), 0.8, BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        blocks.append(_P(head, S['h3']))
        blocks.append(t)
        blocks.append(Spacer(1, 8))
    return blocks, sw_names

import math as _math

_TOPO_COLORS = {
    'router': '#6366f1', 'switch': '#f59e0b', 'ap': '#f97316',
    'desktop': '#3b82f6', 'vm': '#8b5cf6', 'rpi': '#10b981',
    'phone': '#ec4899', 'smarttv': '#f97316', 'printer': '#64748b',
    'camera': '#ef4444', 'nas': '#14b8a6',
}
_TOPO_DEFAULT = '#64748b'
_TOPO_ROOT_R = 62
_TOPO_R_MAX = 205
_TOPO_LEAF_DOT = 3.4
_TOPO_ROOT_DOT = 6.5
_TOPO_LABEL_PT = 5.5
_TOPO_ROOTLBL_PT = 6.8
_TOPO_LABEL_CHARS = 13

def _dev_field(d, name, default=''):

    try:
        v = d.get(name, default)
        return default if v in (None, 'N/A') else v
    except Exception:
        return default

def _topo_key(d):

    return str(_dev_field(d, 'uid') or _dev_field(d, 'mac') or '').strip().lower()

def _topo_label(d):

    host = str(_dev_field(d, 'hostname') or _dev_field(d, 'agent_name')).strip()
    if host:
        return host
    ip = str(_dev_field(d, 'ip')).strip()
    if ip:
        return ip
    return _topo_key(d)[:12] or '?'

def _topo_subnet(d):

    sub = str(_dev_field(d, 'subnet')).strip()
    if sub:
        return sub
    ip = str(_dev_field(d, 'ip')).strip()
    if ip.count('.') == 3:
        return ip.rsplit('.', 1)[0]
    return ''

def _build_topology_forest(devices):

    nodes = {}
    for d in (devices or []):
        k = _topo_key(d)
        if k and k not in nodes:
            nodes[k] = {'dev': d, 'depth': 0, 'children': []}

    links = []

    def add_child(parent_key, child_key, documented):
        if parent_key == child_key:
            return
        nodes[child_key]['depth'] = 1
        nodes[parent_key]['children'].append(child_key)
        links.append((parent_key, child_key, documented))

    for k, nd in nodes.items():
        pid = str(_dev_field(nd['dev'], 'parent_id') or '').strip().lower()
        if pid and pid in nodes and pid != k:
            documented = not bool(_dev_field(nd['dev'], 'parent_inferred', False))
            add_child(pid, k, documented)

    for k, nd in nodes.items():
        if nd['children'] or nd['depth']:
            continue
        sp = nd['dev'].get('switch_port')
        if isinstance(sp, dict):
            swk = str(sp.get('switch_mac') or '').strip().lower()
            if swk and swk in nodes and swk != k:
                add_child(swk, k, True)

    unparented = [k for k, nd in nodes.items() if not nd['children'] and not nd['depth']]
    by_subnet = {}
    for k in unparented:
        by_subnet.setdefault(_topo_subnet(nodes[k]['dev']), []).append(k)
    for subnet, keys in sorted(by_subnet.items()):
        if not subnet:
            continue
        devs = [nodes[k]['dev'] for k in keys]
        gw = next((d for d in devs if str(_dev_field(d, 'ip')).endswith('.1')), None)
        if gw is None:
            gw = next((d for d in devs if _dev_field(d, 'type') == 'router'), None)
        if gw is None:
            def _ip_sort(d):
                try:
                    return [int(o) for o in str(_dev_field(d, 'ip')).split('.')]
                except ValueError:
                    return [999]
            gw = sorted(devs, key=_ip_sort)[0]
        gk = _topo_key(gw)
        for k in keys:
            if k != gk:
                add_child(gk, k, False)

    roots = [k for k, nd in nodes.items() if not nd['children'] and nd['depth'] == 0]
    is_child = {c for p, c, _ in links}
    roots = [k for k in nodes if k not in is_child]
    for k in nodes:
        nodes[k]['depth'] = 0
    queue = list(roots)
    while queue:
        cur = queue.pop(0)
        for ch in nodes[cur]['children']:
            nodes[ch]['depth'] = nodes[cur]['depth'] + 1
            queue.append(ch)
    roots_sorted = sorted(roots, key=lambda k: (_topo_subnet(nodes[k]['dev']),
                                                _topo_label(nodes[k]['dev'])))
    return nodes, links, roots_sorted

def _leaf_count(nodes, key, memo=None):

    memo = memo if memo is not None else {}
    if key in memo:
        return memo[key]
    ch = nodes[key]['children']
    if not ch:
        memo[key] = 1
        return 1
    memo[key] = sum(_leaf_count(nodes, c, memo) for c in ch)
    return memo[key]

class _TopologyDrawing(Flowable):

    def __init__(self, devices, width, height):
        super().__init__()
        self.width, self.height = width, height
        self.nodes, self.links, self.roots = _build_topology_forest(devices)
        self.max_depth = max((nd['depth'] for nd in self.nodes.values()),
                             default=1) or 1
        self.ring_r = {}
        for dep in range(0, self.max_depth + 1):
            if dep == 0:
                self.ring_r[dep] = _TOPO_ROOT_R
            elif self.max_depth == 1:
                self.ring_r[dep] = _TOPO_R_MAX
            else:
                self.ring_r[dep] = (_TOPO_ROOT_R
                                    + (_TOPO_R_MAX - _TOPO_ROOT_R) * dep
                                    / self.max_depth)
        self.angles = {}
        self._layout_sectors()

    def _layout_sectors(self):
        nodes, roots = self.nodes, self.roots
        if not roots:
            return
        leaves = {k: _leaf_count(nodes, k) for k in nodes}
        total = sum(leaves[r] for r in roots)
        if total == 0:
            total = 1
        start = -_math.pi / 2
        for r in roots:
            span = 2 * _math.pi * leaves[r] / total
            mid = start + span / 2
            self.angles[r] = mid
            self._fan_children(r, start, start + span, leaves)
            start += span

    def _fan_children(self, key, a_start, a_end, leaves):

        ch = self.nodes[key]['children']
        if not ch:
            return
        ch = sorted(ch, key=lambda c: _topo_label(self.nodes[c]['dev']))
        total = sum(leaves[c] for c in ch) or 1
        cur = a_start
        for c in ch:
            span = (a_end - a_start) * leaves[c] / total
            self.angles[c] = cur + span / 2
            self._fan_children(c, cur, cur + span, leaves)
            cur += span

    def _pos(self, key):
        dep = self.nodes[key]['depth']
        r = self.ring_r.get(dep, _TOPO_R_MAX)
        a = self.angles[key]
        cx, cy = self.cx, self.cy
        return cx + r * _math.cos(a), cy + r * _math.sin(a)

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        cv = self.canv
        self.cx = self.width / 2.0
        self.cy = self.height - self.width / 2.0 - 18
        nodes, links = self.nodes, self.links

        cx, cy = self.cx, self.cy
        for pk, ck, documented in links:
            px, py = self._pos(pk)
            qx, qy = self._pos(ck)
            r0 = self.ring_r.get(self.nodes[pk]['depth'], _TOPO_R_MAX)
            r1 = self.ring_r.get(self.nodes[ck]['depth'], _TOPO_R_MAX)
            a0 = self.angles.get(pk, 0.0)
            a1 = self.angles.get(ck, 0.0)
            am = (a0 + a1) / 2.0
            c1x = cx + r0 * _math.cos(am)
            c1y = cy + r0 * _math.sin(am)
            c2x = cx + r1 * _math.cos(am)
            c2y = cy + r1 * _math.sin(am)
            cv.saveState()
            cv.setStrokeColor(colors.HexColor('#CBD5E1'))
            cv.setLineWidth(0.45)
            if not documented:
                cv.setDash(2, 2)
            cv.bezier(px, py, c1x, c1y, c2x, c2y, qx, qy)
            cv.restoreState()

        placed_root_lbls = []
        for k in sorted(nodes, key=lambda x: (nodes[x]['depth'],
                                              self.angles.get(x, 0))):
            nd = nodes[k]
            d = nd['dev']
            px, py = self._pos(k)
            color = colors.HexColor(_TOPO_COLORS.get(
                str(_dev_field(d, 'type') or '').strip().lower(), _TOPO_DEFAULT))
            has_agent = bool(_dev_field(d, 'has_agent', False)
                             or _dev_field(d, 'agent_id'))
            dep = nd['depth']
            is_root = dep == 0
            dot = _TOPO_ROOT_DOT if is_root else _TOPO_LEAF_DOT

            cv.saveState()
            if has_agent:
                cv.setFillColor(color)
                cv.circle(px, py, dot / 2, stroke=0, fill=1)
            else:
                cv.setFillColor(colors.white)
                cv.setStrokeColor(color)
                cv.setLineWidth(1.1)
                cv.circle(px, py, dot / 2, stroke=1, fill=1)
            cv.restoreState()

            if is_root:
                self._root_label(cv, k, px, py, placed_root_lbls)
            elif dep >= 1:
                self._leaf_label(cv, k, px, py)

        cv.saveState()
        cv.setStrokeColor(colors.HexColor('#7570E4'))
        cv.setLineWidth(0.9)
        cv.setFillColor(colors.HexColor('#EEEDFB'))
        cv.circle(self.cx, self.cy, 11, stroke=1, fill=1)
        cv.setFont(FONT_BOLD, 7.2)
        cv.setFillColor(colors.HexColor('#4F46E5'))
        cv.drawCentredString(self.cx, self.cy - 2.4, tr('Rede'))
        cv.restoreState()

        self._draw_legend(cv)

    def _type_label(self, t):
        return tr(_TYPE_LABELS.get(t, t))

    def _draw_legend(self, cv):
        present = sorted({str(_dev_field(nd['dev'], 'type') or 'desktop')
                          .strip().lower() for nd in self.nodes.values()})
        items = [(t, _TOPO_COLORS.get(t, _TOPO_DEFAULT),
                  self._type_label(t)) for t in present[:8]]

        y = 14
        x = 6
        for t, hexc, name in items:
            cv.setFillColor(colors.HexColor(hexc))
            cv.circle(x + 3.5, y + 2.8, 3.2, stroke=0, fill=1)
            cv.setFont(FONT_MAIN, 6.5)
            cv.setFillColor(colors.HexColor('#475569'))
            cv.drawString(x + 9.5, y, name)
            x += 9.5 + pdfmetrics.stringWidth(name, FONT_MAIN, 6.5) + 10

        y2 = 4
        seg = [
            ('dot', tr('Com agente Wazuh')),
            ('open', tr('Sem agente Wazuh')),
            ('solid', tr('Link documentado')),
            ('dash', tr('Vínculo inferido por sub-rede')),
        ]
        x = 6
        for kind, name in seg:
            cv.saveState()
            if kind == 'dot':
                cv.setFillColor(colors.HexColor('#3B82F6'))
                cv.circle(x + 3.5, y2 + 2.8, 3.2, stroke=0, fill=1)
            elif kind == 'open':
                cv.setFillColor(colors.white)
                cv.setStrokeColor(colors.HexColor('#3B82F6'))
                cv.setLineWidth(1.1)
                cv.circle(x + 3.5, y2 + 2.8, 3.2, stroke=1, fill=1)
            elif kind == 'solid':
                cv.setStrokeColor(colors.HexColor('#CBD5E1'))
                cv.setLineWidth(0.8)
                cv.line(x, y2 + 2.8, x + 7, y2 + 2.8)
            else:
                cv.setStrokeColor(colors.HexColor('#CBD5E1'))
                cv.setLineWidth(0.8)
                cv.setDash(2, 2)
                cv.line(x, y2 + 2.8, x + 7, y2 + 2.8)
            cv.restoreState()
            cv.setFont(FONT_MAIN, 6.5)
            cv.setFillColor(colors.HexColor('#475569'))
            cv.drawString(x + 9.5, y2, name)
            x += 9.5 + pdfmetrics.stringWidth(name, FONT_MAIN, 6.5) + 10

    def _root_label(self, cv, key, px, py, placed):

        lbl = _trunc(_topo_label(self.nodes[key]['dev']), 16)
        for attempt in range(4):
            ox = _math.cos(self.angles[key]) * (attempt * 13)
            oy = _math.sin(self.angles[key]) * (attempt * 13)
            lx, ly = px + ox, py + oy
            w = pdfmetrics.stringWidth(lbl, FONT_BOLD, _TOPO_ROOTLBL_PT)
            right = _math.cos(self.angles[key]) >= 0
            x0 = lx + 5 if right else lx - w - 5
            bbox = (x0, ly - 3, x0 + w, ly + 5)
            if not any(self._boxes_hit(bbox, b) for b in placed):
                placed.append(bbox)
                cv.setFont(FONT_BOLD, _TOPO_ROOTLBL_PT)
                cv.setFillColor(colors.HexColor('#334155'))
                cv.drawString(x0, ly - 1.6, lbl)
                return
        placed.append(bbox)

    def _leaf_label(self, cv, key, px, py):

        lbl = _trunc(_topo_label(self.nodes[key]['dev']), _TOPO_LABEL_CHARS)
        a = self.angles[key]
        deg = _math.degrees(a)
        cv.saveState()
        cv.translate(px, py)
        if 90 < deg < 270:
            cv.rotate(deg + 180)
            cv.setFont(FONT_MAIN, _TOPO_LABEL_PT)
            cv.setFillColor(colors.HexColor('#475569'))
            cv.drawRightString(-_TOPO_LEAF_DOT / 2 - 1.5, -1.7, lbl)
        else:
            cv.rotate(deg)
            cv.setFont(FONT_MAIN, _TOPO_LABEL_PT)
            cv.setFillColor(colors.HexColor('#475569'))
            cv.drawString(_TOPO_LEAF_DOT / 2 + 1.5, -1.7, lbl)
        cv.restoreState()

    @staticmethod
    def _boxes_hit(a, b):
        return not (a[2] < b[0] or b[2] < a[0] or a[3] < b[1] or b[3] < a[1])

def _topology_section(elements, devices):

    if not devices:
        return

    elements.append(PageBreak())
    elements.append(_P(f'{tr("Topologia da Rede")}', S['h2']))
    elements.append(_P(
        tr('Árvore radial do parque mapeado pelo NetScope — gateways e switches no centro, máquinas nas bordas. Linha sólida: vínculo documentado; tracejada: vínculo inferido pela sub-rede.'),
        S['body']))
    elements.append(Spacer(1, 6))

    drawing = _TopologyDrawing(devices, CONTENT_W, 560)
    drawing.hAlign = 'CENTER'
    elements.append(drawing)

    elements.append(Spacer(1, 6))

def _machine_detail_block(row, sw_names):

    m, ns = row['machine'], row['ns']
    blocks = []

    host = row['hostname']
    ip = row['ip']

    icon = dev_icon_img(_machine_type(ns), size=10.5, valign=-2)
    head = f'{icon} <b>{_trunc(host, 42)}</b>'
    if ip and ip != '—':
        head += f' <font size="8" color="#64748B">({ip})</font>'
    blocks.append(_P(head, S['h3']))

    if m:
        cpu = str(get_value(m, 'cpu_name', 'N/A'))
        cores = get_value(m, 'cpu_cores', 'N/A')
        ram_total = get_value(m, 'ram_total', 0)
        ram_use = get_value(m, 'ram_usage', 'N/A')
        os_full = str(get_value(m, 'os_full', get_value(m, 'os_name', 'N/A')))
        kernel = str(get_value(m, 'os_kernel', 'N/A'))
        arch = str(get_value(m, 'os_architecture', 'N/A'))
        platform = str(get_value(m, 'os_platform', 'N/A'))
        ka = fmt_dt(get_value(m, 'last_seen', ''))
        aid = str(get_value(m, 'id', '—'))
        groups = get_value(m, 'groups', []) or []
        macs = [str(i.get('mac')) for i in (m.get('netiface') or [])
                if i.get('mac') and str(i.get('mac')).lower() != 'n/a']
        raw = str(m.get('agent_status_raw') or '').strip().lower()
        online = raw == 'active'

        kv = [
            (tr('CPU'), f'{cpu} ({cores} {tr("núcleos")})'),
            (tr('RAM total'), _fmt_gb(ram_total)),
            (tr('RAM em uso'), f'{ram_use}%' if isinstance(ram_use, (int, float)) else '—'),
            (tr('Sistema Operacional'), os_full),
            (tr('Kernel'), kernel),
            (tr('Arquitetura / Plataforma'), f'{arch} / {platform}'),
            (tr('Agente Wazuh'),
             f'{tr("ID")} {aid} · {tr("Online") if online else tr("Offline")} · keepalive {ka}'),
            (tr('Grupos de políticas'), ', '.join(groups) if groups else '—'),
            (tr('Endereço MAC'), ', '.join(macs[:3]) if macs else '—'),
        ]
        wazuh_t = kv_table(kv)
        if wazuh_t is not None:
            blocks.append(_P(f'<b>{tr("Inventário Wazuh (syscollector)")}</b>', S['small']))
            blocks.append(wazuh_t)
            blocks.append(Spacer(1, 5))

        ifaces, addrs, ports = normalize_details(m)

        if ifaces:
            trows = [[_P(tr('Interface'), S['thead']), _P(tr('MAC'), S['thead']),
                      _P(tr('Estado'), S['thead']), _P('MTU', S['thead']),
                      _P(tr('Tipo'), S['thead'])]]
            for it in ifaces:
                trows.append([
                    _P(str(it.get('name', '—')), S['mono']),
                    _P(str(it.get('mac', '—')), S['mono']),
                    _P(str(it.get('state', '—')), S['cell']),
                    _P(str(it.get('mtu', '—')), S['cell']),
                    _P(str(it.get('type', '—')), S['cell']),
                ])
            it_t = Table(trows, colWidths=[110, 130, 90, 60, 105])
            it_t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), INK),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                ('LINEBELOW', (0, -1), (-1, -1), 0.5, BORDER),
            ]))
            blocks.append(_P(tr('Interfaces de Rede'), S['small']))
            blocks.append(it_t)
            blocks.append(Spacer(1, 5))

        if addrs:
            trows = [[_P(tr('Interface'), S['thead']), _P(tr('Endereço IP'), S['thead']),
                      _P(tr('Máscara'), S['thead']), _P(tr('Broadcast'), S['thead']),
                      _P(tr('Proto'), S['thead'])]]
            for a in addrs:
                trows.append([
                    _P(str(a.get('iface', '—')), S['mono']),
                    _P(str(a.get('address', '—')), S['mono']),
                    _P(str(a.get('netmask', '—')), S['mono']),
                    _P(str(a.get('broadcast', '—')), S['mono']),
                    _P(str(a.get('proto', '—')), S['cell']),
                ])
            ad_t = Table(trows, colWidths=[90, 120, 110, 130, 45])
            ad_t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), INK),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                ('LINEBELOW', (0, -1), (-1, -1), 0.5, BORDER),
            ]))
            blocks.append(_P(tr('Endereços IP'), S['small']))
            blocks.append(ad_t)
            blocks.append(Spacer(1, 5))

        if ports:
            shown = ports[:50]
            trows = [[_P(tr('Porta'), S['thead']), _P(tr('Proto'), S['thead']),
                      _P(tr('Processo'), S['thead']), _P(tr('Estado'), S['thead']),
                      _P(tr('IP local'), S['thead'])]]
            for p in shown:
                local = p.get('local', {}) if isinstance(p, dict) else {}
                trows.append([
                    _P(str(local.get('port', '—')), S['mono']),
                    _P(str(p.get('protocol', '—')), S['cell']),
                    _P(str(p.get('process', '—')), S['cell']),
                    _P(str(p.get('state', '—')), S['cell']),
                    _P(str(local.get('ip', '—')), S['mono']),
                ])
            extra = len(ports) - len(shown)
            foot = (tr('… e mais {} portas (omissas por limite de exibição)').format(extra)
                    if extra > 0 else '')
            trows.append([_P(foot, S['small']), _P('', S['small']),
                          _P('', S['small']), _P('', S['small']),
                          _P('', S['small'])])
            pt_t = Table(trows, colWidths=[45, 45, 170, 80, 150])
            pt_t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), INK),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_SOFT]),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                ('LINEBELOW', (0, -1), (-1, -1), 0.5, BORDER),
                ('SPAN', (0, -1), (-1, -1)),
            ]))
            blocks.append(_P(tr('Portas Abertas'), S['small']))
            blocks.append(pt_t)
            blocks.append(Spacer(1, 5))

    if ns:
        doc_bits = []
        for label, key in ((tr('Usuário'), 'user'), (tr('Depto'), 'department'),
                           (tr('Local'), 'location'), ('Asset Tag', 'asset_tag'),
                           (tr('Lacre'), 'seal_number')):
            v = str(ns.get(key) or '').strip()
            if v and v not in ('N/A', 'None'):
                doc_bits.append(f'<b>{label}:</b> {_trunc(v, 28)}')
        ns_os = str(ns.get('os') or '').strip()
        if ns_os and ns_os not in ('N/A', 'None'):
            doc_bits.append(f"<b>{tr('Sistema')}:</b> {_trunc(ns_os, 28)}")
        if doc_bits:
            blocks.append(_P(
                f"<b>{tr('Documentação (NetScope)')}:</b> "
                + ' &nbsp;·&nbsp; '.join(doc_bits), S['small']))
        link = _switch_link_line(ns, sw_names)
        if link:
            blocks.append(_P(link, S['small']))
        ns_ports = ns.get('open_ports') or []
        if ns_ports:
            blocks.append(_P(
                f'{tr("Portas descobertas pelo scan:")} {", ".join(str(p) for p in ns_ports[:20])}',
                S['small']))

    blocks.append(Spacer(1, 10))
    blocks.append(HRFlowable(width='100%', thickness=0.6, color=BORDER))
    blocks.append(Spacer(1, 6))
    return blocks

def generate_pdf_report(stats, machines, rows, ns_stats, groups_data,
                        switches=None, include_details=False,
                        generated_by='', lang='pt', devices=None):

    _set_report_lang(lang)
    active = stats.get('status', {}).get('Ativo', 0)
    inactive = stats.get('status', {}).get('Inativo', 0)
    wazuh_count = sum(1 for r in rows if r['machine'])
    netscope_only = sum(1 for r in rows
                        if not r['machine'] and not r.get('agent_exempt'))
    ctx = {
        'total': len(rows),
        'wazuh_count': wazuh_count,
        'netscope_only': netscope_only,
        'ns_total': (ns_stats or {}).get('total', len(rows)),
        'online': active,
        'offline': inactive,
        'no_agent': (ns_stats or {}).get('without_agent', len(rows) - wazuh_count),
    }

    sw_blocks, sw_names = _switches_blocks(switches)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=64, bottomMargin=56, leftMargin=M_LEFT, rightMargin=M_RIGHT,
        title=tr('Relatório de Inventário — Inventory'),
        author=str(generated_by or 'Inventory'),
    )
    elements = []

    _cover_page(elements, ctx,
                RD.os_distribution(machines), RD.agent_status_detail(machines))
    elements.append(PageBreak())

    d_part = datetime.now().strftime('%d/%m/%Y')
    h_part = datetime.now().strftime('%H:%M')
    when = f'{d_part} {tr("às")} {h_part}'
    meta_line = (
        f'{tr("Gerado em")} <b>{when}</b>'
        f'{" &nbsp;·&nbsp; " + tr("por") + " <b>" + str(generated_by or "—") + "</b>" if generated_by else ""}'
        f' &nbsp;·&nbsp; <b>{ctx["total"]}</b> {tr("máquinas no relatório")}'
        f' &nbsp;·&nbsp; <b>{ctx["wazuh_count"]}</b> {tr("com agente Wazuh")}'
    )
    elements.append(_P(meta_line, S['p2meta']))
    elements.append(Spacer(1, 6))

    sec = 1

    elements.append(_P(f'{sec}. {tr("Inventário Consolidado")}', S['h2']))
    elements.append(_P(
        tr('Todas as máquinas conhecidas pelo sistema em UMA tabela — inventário do Wazuh (IP, sistema, status do agente) e documentação do NetScope (MAC, tipo, fabricante, modelo, usuário, departamento, local, asset tag, lacre e vínculo de switch) concatenados por ativo.'),
        S['body']))
    elements.append(Spacer(1, 8))
    elements.append(_consolidated_table(rows, sw_names))
    elements.append(Spacer(1, 6))
    elements.append(_P(
        f'{tr("Legenda:")} <b>{ctx["wazuh_count"]}</b> {tr("máquinas com agente Wazuh")} · '
        f'<b>{ctx["netscope_only"]}</b> {tr("máquinas somente no NetScope (sem agente)")} · '
        f'{tr("total")} <b>{ctx["total"]}</b> {tr("máquinas.")}', S['small']))
    elements.append(Spacer(1, 10))
    sec += 1

    elements.append(_P(f'{sec}. {tr("Rankings do Inventário")}', S['h2']))
    elements.append(_P(
        tr('Agregados do último ciclo de sincronização com o Wazuh — mesmas séries do Dashboard, em tabelas nomeadas.')
        + f' ({wazuh_count} {tr("máquinas")})', S['body']))
    elements.append(Spacer(1, 8))

    n_machines = len(machines) or wazuh_count

    elements.append(_side_by_side(
        tr('Processos mais comuns'),
        rank_table(RD.top_processes(machines), n_machines, tr('Processo')),
        tr('Pacotes mais instalados'),
        rank_table(RD.top_packages(machines), n_machines, tr('Pacote'))))

    ram_top = [(r['name'], r['usage']) for r in RD.ram_usage_top(machines)]
    elements.append(_side_by_side(
        tr('Portas de rede mais comuns'),
        rank_table(RD.top_ports(machines), n_machines, tr('Porta / Serviço')),
        tr('Uso de RAM por máquina'),
        rank_table(ram_top, n_machines, tr('Máquina'), suffix='%',
                   show_pct=False)))

    elements.append(_P(tr('Sistemas operacionais'), S['h3']))
    elements.append(os_kernel_table(RD.os_version_kernel(machines),
                                     n_machines))
    elements.append(Spacer(1, 8))

    elements.append(_P(tr('Modelos de processador'), S['h3']))
    elements.append(cpu_full_table(RD.cpu_top(machines, n=14), n_machines))
    elements.append(Spacer(1, 8))

    groups_rows = [(g.get('grupo', '—'), g.get('quantidade_agentes', 0))
                   for g in (groups_data or []) if g.get('quantidade_agentes')]
    elements.append(_side_by_side(
        tr('Memória RAM por faixa (GB)'),
        rank_table(RD.ram_distribution(machines), n_machines, tr('Faixa')),
        tr('Grupos do Wazuh'),
        rank_table(groups_rows, n_machines, tr('Grupo de políticas'),
                   max_label=34, show_pct=False)))

    buckets = RD.keepalive_buckets(machines)
    bucket_rows = [(k, v) for k, v in buckets.items()]
    sd = RD.agent_status_detail(machines)
    agent_rows = [
        (tr('Ativos (active)'), sd.get('active', 0)),
        (tr('Desconectados (disconnected)'), sd.get('disconnected', 0)),
        (tr('Nunca conectaram (never_connected)'), sd.get('never_connected', 0)),
    ] + [(tr(k), v) for k, v in bucket_rows]
    elements.append(_P(tr('Agentes Wazuh — Status e Atualização'), S['h3']))
    elements.append(rank_table(agent_rows, n_machines, tr('Situação'),
                               width=CONTENT_W, max_label=44))

    elements.append(Spacer(1, 10))
    sec += 1

    if devices:
        _topology_section(elements, devices)
        sec += 1

    if sw_blocks:
        elements.append(_P(f'{sec}. {tr("Configuração de Switches")}', S['h2']))
        elements.append(_P(
            tr('Portas configuradas nos switches mapeados pelo NetScope.'),
            S['body']))
        elements.append(Spacer(1, 8))
        elements.extend(sw_blocks)
        elements.append(Spacer(1, 2))
        sec += 1

    if include_details and rows:
        detail_rows = [r for r in rows if r['machine']]
        if detail_rows:
            elements.append(_P(f'{sec}. {tr("Detalhamento Técnico por Máquina")}', S['h2']))
            elements.append(_P(
                tr('Fichas dos hosts com agente Wazuh: inventário do syscollector (hardware, sistema, agente, interfaces, endereços IP e portas) + documentação e vínculo de switch do NetScope quando houver. Os dispositivos sem agente aparecem na tabela do Inventário Consolidado.'),
                S['body']))
            elements.append(Spacer(1, 8))
            for row in detail_rows:
                elements.append(KeepTogether(_machine_detail_block(row, sw_names)))

    try:
        doc.build(elements, onFirstPage=_cover_background,
                  onLaterPages=_header_band, canvasmaker=NumberedCanvas)
    finally:
        _hi_cleanup()
    buffer.seek(0)
    return buffer
