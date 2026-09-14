
const $ = id => document.getElementById(id);

async function api(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    return await r.json();
  } catch (e) {
    return { error: e.message };
  }
}

const _TOAST_CAT = { ok: 'success', err: 'danger', warn: 'warning', info: 'info' };

const _NS_TOAST_ICONS = { success: 'fa-circle-check', danger: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };

function toast(msg, type = 'ok') {
  const cat = _TOAST_CAT[type] || 'info';
  const el = document.createElement('div');
  el.className = 'alert alert-' + cat;

  const ic = document.createElement('i');
  ic.className = 'fas ' + (_NS_TOAST_ICONS[cat] || 'fa-circle-info') + ' alert-icon';
  const span = document.createElement('span');
  span.textContent = msg;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'alert-close';
  btn.innerHTML = '<i class="fas fa-times"></i>';

  el.appendChild(ic);
  el.appendChild(span);
  el.appendChild(btn);
  $('toasts').appendChild(el);

  const hide = () => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(100px)';
    el.style.transition = 'opacity .3s, transform .3s';
    setTimeout(() => el.remove(), 300);
  };
  btn.addEventListener('click', hide);
  setTimeout(() => { if (el.parentElement) hide(); }, 5000);
}

function setBtnLoading(btn, on) {
  if (on) {
    btn.dataset.origHtml = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    btn.style.pointerEvents = 'none'; btn.style.opacity = '.6';
  } else {
    btn.innerHTML = btn.dataset.origHtml || btn.innerHTML;
    btn.style.pointerEvents = ''; btn.style.opacity = '';
  }
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function t(key, vars) {
  let s = (window.NS_T && window.NS_T[key]) || key;
  if (vars) { for (const k in vars) s = s.split('{' + k + '}').join(String(vars[k])); }
  return s;
}

function fmtDate(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('pt-BR') + ' ' + d.toLocaleTimeString('pt-BR', {hour:'2-digit',minute:'2-digit'});
  } catch (e) { return iso; }
}

const S = {
  devices: [],
  selected: null,
  popover: null,
  ctrlLink: null,
  search: '',
  filter: 'all',
  scanning: false,
  _ctxKey: null,
  _prevMacSet: '',
  _prevLinkSet: '',
  config: null,
  stats: { total: 0, online: 0, offline: 0, new_today: 0 },

  layoutMode: 'tree',
  switches: [],
  snapshots: [],
  snapshotView: null,
  snapshotDevices: null,
  assetFilter: '',

  assetSort: { key: null, dir: 1 },

  assetSel: new Set(),

  conflictGroups: [],
  conflictUids: {},

  wazuh: { total: 0, active: 0, with_agent: 0, without_agent: 0 },
};

const SVG_ICONS = {
  router: '<path d="M2 14h20v6H2z" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="6" y1="14" x2="6" y2="10" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="14" x2="12" y2="8" stroke="currentColor" stroke-width="1.5"/><line x1="18" y1="14" x2="18" y2="10" stroke="currentColor" stroke-width="1.5"/>',
  switch: '<rect x="2" y="8" width="20" height="8" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="6" cy="12" r="1" fill="currentColor"/><circle cx="10" cy="12" r="1" fill="currentColor"/><circle cx="14" cy="12" r="1" fill="currentColor"/><circle cx="18" cy="12" r="1" fill="currentColor"/>',
  ap: '<path d="M5 12.55a11 11 0 0 1 14.08 0" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="19" r="1" fill="currentColor"/>',

  firewall: '<path d="M3 5h18v14H3z" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="3" y1="10" x2="21" y2="10" stroke="currentColor" stroke-width="1.5"/><line x1="3" y1="15" x2="21" y2="15" stroke="currentColor" stroke-width="1.5"/><line x1="8" y1="5" x2="8" y2="10" stroke="currentColor" stroke-width="1.5"/><line x1="15" y1="10" x2="15" y2="15" stroke="currentColor" stroke-width="1.5"/><line x1="8" y1="15" x2="8" y2="19" stroke="currentColor" stroke-width="1.5"/>',
  loadbalancer: '<circle cx="12" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="5" cy="19" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="19" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="19" cy="19" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="7" x2="12" y2="11" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="11" x2="5.8" y2="17.2" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="11" x2="12" y2="17" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="11" x2="18.2" y2="17.2" stroke="currentColor" stroke-width="1.5"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="3" y="13" width="18" height="7" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="6.5" cy="7.5" r=".9" fill="currentColor"/><circle cx="6.5" cy="16.5" r=".9" fill="currentColor"/><line x1="10" y1="7.5" x2="18" y2="7.5" stroke="currentColor" stroke-width="1.5"/><line x1="10" y1="16.5" x2="18" y2="16.5" stroke="currentColor" stroke-width="1.5"/>',
  hypervisor: '<path d="M12 3 3 8l9 5 9-5-9-5Z" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="m3 13 9 5 9-5" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  storage: '<rect x="4" y="6" width="16" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="16" cy="12" r="1" fill="currentColor"/><line x1="4" y1="9.5" x2="20" y2="9.5" stroke="currentColor" stroke-width="1.5"/>',
  desktop: '<rect x="3" y="4" width="18" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="8" y1="20" x2="16" y2="20" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="16" x2="12" y2="20" stroke="currentColor" stroke-width="1.5"/>',
  laptop: '<rect x="5" y="5" width="14" height="9" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M2.5 18h19l-1.8-3H4.3l-1.8 3Z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  tablet: '<rect x="5" y="3" width="14" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="10" y1="17.5" x2="14" y2="17.5" stroke="currentColor" stroke-width="1.5"/>',
  vm: '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  rpi: '<rect x="5" y="5" width="14" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="9" cy="10" r="1.2" fill="currentColor"/><circle cx="15" cy="10" r="1.2" fill="currentColor"/>',
  phone: '<rect x="6" y="3" width="12" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="12" y1="18" x2="12" y2="18.01" stroke="currentColor" stroke-width="1.5"/>',
  voip: '<rect x="4" y="5" width="16" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="7" y="8" width="5" height="6" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/><circle cx="15.5" cy="9" r=".9" fill="currentColor"/><circle cx="15.5" cy="12" r=".9" fill="currentColor"/><circle cx="15.5" cy="15" r=".9" fill="currentColor"/><line x1="8" y1="16.5" x2="16" y2="16.5" stroke="currentColor" stroke-width="1.2"/>',
  iot: '<rect x="7" y="7" width="10" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="10" y1="7" x2="10" y2="4" stroke="currentColor" stroke-width="1.5"/><line x1="14" y1="7" x2="14" y2="4" stroke="currentColor" stroke-width="1.5"/><line x1="10" y1="17" x2="10" y2="20" stroke="currentColor" stroke-width="1.5"/><line x1="14" y1="17" x2="14" y2="20" stroke="currentColor" stroke-width="1.5"/><line x1="7" y1="10" x2="4" y2="10" stroke="currentColor" stroke-width="1.5"/><line x1="7" y1="14" x2="4" y2="14" stroke="currentColor" stroke-width="1.5"/><line x1="17" y1="10" x2="20" y2="10" stroke="currentColor" stroke-width="1.5"/><line x1="17" y1="14" x2="20" y2="14" stroke="currentColor" stroke-width="1.5"/>',
  smarttv: '<rect x="3" y="7" width="18" height="13" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><polyline points="17 3 12 7 7 3" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  printer: '<rect x="6" y="10" width="12" height="8" rx="1" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M6 14H3a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h18a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3" fill="none" stroke="currentColor" stroke-width="1.5"/><rect x="8" y="3" width="8" height="5" rx=".5" fill="none" stroke="currentColor" stroke-width="1.2"/>',
  camera: '<path d="M2 7h4l2-3h8l2 3h4a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="13" r="3.5" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  nas: '<rect x="4" y="6" width="16" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="16" cy="12" r="1" fill="currentColor"/>',
};

const FILL_COLORS = {
  router:'#6366f1', switch:'#f59e0b', ap:'#f97316', desktop:'#3b82f6', vm:'#8b5cf6',

  firewall:'#ef4444', loadbalancer:'#0ea5e9', server:'#0891b2', hypervisor:'#9333ea',
  storage:'#14b8a6', laptop:'#1d4ed8', tablet:'#0d9488', voip:'#65a30d', iot:'#d946ef',
  rpi:'#10b981', phone:'#ec4899', smarttv:'#f97316',
  printer:'#64748b', camera:'#ef4444', nas:'#14b8a6',
};
const ICON_COLORS = {
  router:'#c7d2fe', switch:'#fef3c7', ap:'#ffedd5', desktop:'#dbeafe', vm:'#ede9fe',

  firewall:'#fee2e2', loadbalancer:'#e0f2fe', server:'#cffafe', hypervisor:'#f3e8ff',
  storage:'#ccfbf1', laptop:'#dbeafe', tablet:'#99f6e4', voip:'#ecfccb', iot:'#fae8ff',
  rpi:'#d1fae5', phone:'#fce7f3', smarttv:'#ffedd5',
  printer:'#e2e8f0', camera:'#fee2e2', nas:'#ccfbf1',
};

const TYPE_LABELS = {
  router: 'Router', switch: 'Switch', ap: 'Access Point',
  firewall: 'Firewall', loadbalancer: 'Load Balancer', server: 'Servidor (Server)',
  hypervisor: 'Hypervisor', vm: 'Máquina Virtual (VM)', storage: 'Storage (SAN / NAS)',
  desktop: 'Desktop', laptop: 'Laptop / Notebook', tablet: 'Tablet',
  phone: 'Smartphone (Phone)', voip: 'Telefone IP (VoIP)',
  printer: 'Impressora / Multifuncional (Printer)', iot: 'Dispositivos IoT',

  rpi: 'Raspberry Pi', smarttv: 'Smart TV', camera: 'Camera', nas: 'NAS',
};

let _treeData = null;
const RING_BASE = 180, RING_STEP = 160;

function computeTreeData(devices) {
  devices = devices || S.devices;
  const devMap = {};
  devices.forEach(d => { devMap[d.id] = d; });
  const childrenOf = {}, depthOf = {}, roots = [];
  devices.forEach(d => { childrenOf[d.id] = []; });
  devices.forEach(d => {
    if (d.parent_id && devMap[d.parent_id]) {
      childrenOf[d.parent_id].push(d.id);
    } else {
      depthOf[d.id] = 0;
      roots.push(d.id);
    }
  });
  const queue = [...roots], visited = new Set(roots);
  while (queue.length) {
    const mac = queue.shift();
    (childrenOf[mac] || []).forEach(cm => {
      if (!visited.has(cm)) { visited.add(cm); depthOf[cm] = (depthOf[mac]||0)+1; queue.push(cm); }
    });
  }
  devices.forEach(d => {
    if (!visited.has(d.id)) { depthOf[d.id] = 0; roots.push(d.id); }
  });

  const subSize = {};
  function calcSize(mac) {
    const ch = childrenOf[mac] || [];
    if (!ch.length) { subSize[mac] = 1; return 1; }
    subSize[mac] = ch.reduce((s, cm) => s + calcSize(cm), 0);
    return subSize[mac];
  }
  roots.forEach(r => { if (subSize[r] === undefined) calcSize(r); });

  const nodeLayout = {};
  function layoutSector(nodes, aStart, aEnd, depth) {
    const total = nodes.reduce((s, m) => s + (subSize[m] || 1), 0);
    let cur = aStart;
    nodes.forEach(mac => {
      const frac = (subSize[mac] || 1) / total;
      const span = (aEnd - aStart) * frac;
      const mid = cur + span / 2;
      nodeLayout[mac] = { ringR: RING_BASE + depth * RING_STEP, angle: mid };
      const ch = childrenOf[mac] || [];
      if (ch.length) {
        const pad = span * 0.06;
        layoutSector(ch, cur + pad, cur + span - pad, depth + 1);
      }
      cur += span;
    });
  }

  roots.forEach((mac, i) => {
    const a = roots.length === 1 ? -Math.PI/2 : (i/roots.length)*Math.PI*2 - Math.PI/2;
    nodeLayout[mac] = { ringR: 0, angle: a };
  });

  if (roots.length === 1) {
    const ch = childrenOf[roots[0]] || [];
    if (ch.length) layoutSector(ch, -Math.PI, Math.PI, 1);
  } else {
    const sector = (Math.PI * 2) / roots.length;
    roots.forEach((mac, i) => {
      const base = (i / roots.length) * Math.PI * 2 - Math.PI / 2;
      const ch = childrenOf[mac] || [];
      if (ch.length) layoutSector(ch, base - sector/2 + 0.05, base + sector/2 - 0.05, 1);
    });
  }

  _treeData = { childrenOf, depthOf, roots, devMap, nodeLayout };
  return _treeData;
}

function forceTreeLayout() {
  let strength = 0.5;
  function force(alpha) {
    if (!_treeData || !_treeData.nodeLayout) return;
    const { nodeLayout } = _treeData;
    const cx = W / 2, cy = H / 2;
    S.devices.forEach(d => {
      if (d.fx != null) return;
      const l = nodeLayout[d.id];
      if (!l) return;
      const tx = cx + Math.cos(l.angle) * l.ringR;
      const ty = cy + Math.sin(l.angle) * l.ringR;
      d.vx += (tx - (d.x || tx)) * strength * alpha;
      d.vy += (ty - (d.y || ty)) * strength * alpha;
    });
  }
  force.strength = s => { strength = s; return force; };
  return force;
}

function computeHierarchyLayout() {
  computeTreeData();
  if (!_treeData) return;
  const { roots, childrenOf } = _treeData;
  const LAYER_H = 140;
  const NODE_W = 100;
  const cx = W / 2;
  const layout = {};

  const leafCount = {};
  function countLeaves(mac) {
    const ch = childrenOf[mac] || [];
    if (!ch.length) { leafCount[mac] = 1; return 1; }
    leafCount[mac] = ch.reduce((s, c) => s + countLeaves(c), 0);
    return leafCount[mac];
  }
  roots.forEach(r => { if (leafCount[r] === undefined) countLeaves(r); });

  let xCursor = 0;
  function assign(mac, depth) {
    const ch = childrenOf[mac] || [];
    if (!ch.length) {
      layout[mac] = { x: cx + (xCursor - (leafCount[roots[0]] || 1) / 2 + 0.5) * NODE_W, y: 80 + depth * LAYER_H };
      xCursor++;
      return;
    }
    ch.forEach(c => assign(c, depth + 1));
    const first = layout[ch[0]], last = layout[ch[ch.length - 1]];
    layout[mac] = { x: (first.x + last.x) / 2, y: 80 + depth * LAYER_H };
  }
  let rootX = 0;
  roots.forEach((r, i) => {
    const before = xCursor;
    assign(r, 0);
    rootX += leafCount[r] || 1;
  });

  const allX = Object.values(layout).map(p => p.x);
  if (allX.length) {
    const minX = Math.min(...allX), maxX = Math.max(...allX);
    const offset = cx - (minX + maxX) / 2;
    Object.keys(layout).forEach(k => { layout[k].x += offset; });
  }
  _treeData.nodeLayout = layout;

  Object.keys(layout).forEach(mac => {
    const p = layout[mac];
    _treeData.nodeLayout[mac] = { angle: Math.atan2(p.y - H/2, p.x - W/2), ringR: Math.hypot(p.x - W/2, p.y - H/2), _x: p.x, _y: p.y };
  });
}

function forceHierarchyLayout() {
  let strength = 0.6;
  function force(alpha) {
    if (!_treeData || !_treeData.nodeLayout) return;
    S.devices.forEach(d => {
      if (d.fx != null) return;
      const l = _treeData.nodeLayout[d.id];
      if (!l || l._x == null) return;
      d.vx += (l._x - (d.x || l._x)) * strength * alpha;
      d.vy += (l._y - (d.y || l._y)) * strength * alpha;
    });
  }
  force.strength = s => { strength = s; return force; };
  return force;
}

function computeGridLayout() {
  const cols = Math.ceil(Math.sqrt(S.devices.length));
  const CELL_W = 140, CELL_H = 110;
  const startX = W/2 - (cols * CELL_W) / 2 + CELL_W/2;
  const startY = 80;
  const layout = {};

  const sorted = [...S.devices].sort((a, b) => {
    const order = ['router','switch','ap','firewall','loadbalancer','server','hypervisor','vm','storage','desktop','laptop','tablet','phone','voip','printer','iot','rpi','smarttv','camera','nas'];
    const ta = order.indexOf(a.type) >= 0 ? order.indexOf(a.type) : 99;
    const tb = order.indexOf(b.type) >= 0 ? order.indexOf(b.type) : 99;
    if (ta !== tb) return ta - tb;
    return (a.name || '').localeCompare(b.name || '');
  });
  sorted.forEach((d, i) => {
    const col = i % cols, row = Math.floor(i / cols);
    layout[d.id] = { _x: startX + col * CELL_W, _y: startY + row * CELL_H, angle: 0, ringR: 0 };
  });
  if (!_treeData) _treeData = {};
  _treeData.nodeLayout = layout;
}

function forceGridLayout() {
  let strength = 0.8;
  function force(alpha) {
    if (!_treeData || !_treeData.nodeLayout) return;
    S.devices.forEach(d => {
      if (d.fx != null) return;
      const l = _treeData.nodeLayout[d.id];
      if (!l || l._x == null) return;
      d.vx += (l._x - (d.x || l._x)) * strength * alpha;
      d.vy += (l._y - (d.y || l._y)) * strength * alpha;
    });
  }
  force.strength = s => { strength = s; return force; };
  return force;
}

function applyLayoutMode() {

  simulation.force('layout', null);
  if (S.layoutMode === 'tree') {
    computeTreeData();
    simulation.force('layout', forceTreeLayout());
  } else if (S.layoutMode === 'hierarchy') {
    computeHierarchyLayout();
    simulation.force('layout', forceHierarchyLayout());
  } else if (S.layoutMode === 'grid') {
    computeGridLayout();
    simulation.force('layout', forceGridLayout());
  }

  const cx = W / 2, cy = H / 2;
  S.devices.forEach(d => {
    if (_treeData && _treeData.nodeLayout) {
      const l = _treeData.nodeLayout[d.id];
      if (l) {
        if (S.layoutMode === 'grid' || S.layoutMode === 'hierarchy') {

          if (l._x != null) {
            d.x = l._x; d.y = l._y;
          } else {
            d.x = cx + Math.cos(l.angle) * l.ringR;
            d.y = cy + Math.sin(l.angle) * l.ringR;
          }
          d.vx = 0; d.vy = 0;
          d.fx = null; d.fy = null;
        } else if (d.x == null) {

          d.x = cx + Math.cos(l.angle) * l.ringR + (Math.random()-.5)*25;
          d.y = cy + Math.sin(l.angle) * l.ringR + (Math.random()-.5)*25;
        }
      }
    }
  });
  simulation.alpha(0.3).restart();

  if (S.layoutMode === 'grid') {
    setTimeout(() => { simulation.alphaTarget(0).alpha(0).stop(); }, 300);
  }
}

async function loadDevices() {
  const r = await api('/netscope/api/devices');
  if (r.error) return;
  const newDevs = (r.devices || []).map(d => {

    d.id = d.uid || d.mac;
    d.mac = d.mac || '';
    d.name = d.hostname || d.dns_name || d.ip;
    return d;
  });
  const posMap = {};
  S.devices.forEach(d => { posMap[d.id] = { x: d.x, y: d.y, fx: d.fx, fy: d.fy, vx: d.vx, vy: d.vy }; });
  newDevs.forEach(d => {
    const prev = posMap[d.id];
    if (prev) { d.x = prev.x; d.y = prev.y; d.fx = prev.fx; d.fy = prev.fy; d.vx = prev.vx; d.vy = prev.vy; }
  });
  S.devices = newDevs;

  if (S.snapshotView) {
    const snap = await api('/netscope/api/snapshots/' + S.snapshotView);
    if (snap && snap.devices) {
      S.snapshotDevices = snap.devices.map(d => ({...d, id: d.uid || d.mac, mac: d.mac || '', name: d.hostname || d.dns_name || d.ip, _snapshot: true}));
      S.devices = S.snapshotDevices;
    }
  }
  computeTreeData();

  const cx = W / 2, cy = H / 2;
  S.devices.forEach(d => {
    if (d.x == null) {
      const l = _treeData.nodeLayout ? _treeData.nodeLayout[d.id] : null;
      if (l) {
        if (l._x != null) {
          d.x = l._x;
          d.y = l._y;
        } else {
          d.x = cx + Math.cos(l.angle) * l.ringR + (Math.random()-.5)*25;
          d.y = cy + Math.sin(l.angle) * l.ringR + (Math.random()-.5)*25;
        }
      } else {
        d.x = cx + (Math.random()-.5)*200;
        d.y = cy + (Math.random()-.5)*200;
      }
    }
  });
  renderList();
  updateGraph();
  loadStats();

  loadConflicts();
}

async function loadStats() {
  const r = await api('/netscope/api/stats');
  if (r.error) return;
  S.stats = r;
  $('stat-online').textContent = r.online;
  $('stat-offline').textContent = r.offline;
  $('stat-new').textContent = r.new_today;

  const dupEl = $('stat-duplicates');
  if (dupEl) dupEl.textContent = r.duplicates || 0;
  const dupItem = $('stat-dup-item');
  if (dupItem) dupItem.classList.toggle('active', (r.duplicates || 0) > 0);

  if (r.wazuh_total != null) {
    $('wz-yes').textContent = r.with_agent != null ? r.with_agent : 0;
    $('wz-no').textContent = r.without_agent != null ? r.without_agent : 0;
    $('wz-total').textContent = r.wazuh_total + (r.wazuh_active != null ? t(' ({n} ativos)', {n: r.wazuh_active}) : '');
  }
}

async function loadConflicts() {
  const r = await api('/netscope/api/conflicts');
  if (r.error) return;
  S.conflictGroups = r.conflicts || [];
  const map = {};
  S.conflictGroups.forEach(g => (g.devices || []).forEach(d => { map[d.uid] = (g.devices || []).length; }));
  S.conflictUids = map;
  const numEl = $('stat-conflicts');
  if (numEl) numEl.textContent = S.conflictGroups.length;
  const itemEl = $('stat-conflict-item');
  if (itemEl) itemEl.classList.toggle('has-conflicts', S.conflictGroups.length > 0);
  renderConflictsModal();
  renderList();
  updateGraph();
}

function renderConflictsModal() {
  const el = $('conflict-list');
  if (!el) return;
  if (!S.conflictGroups.length) {
    el.innerHTML = '<div class="conflict-empty"><i class="fas fa-circle-check"></i> ' + t('Nenhum conflito de IP') + '</div>';
    return;
  }
  el.innerHTML = S.conflictGroups.map(g =>
    '<div class="conflict-group">' +
      '<div class="conflict-ip"><i class="fas fa-triangle-exclamation"></i> ' + esc(g.ip) +
        '<span class="conflict-n">' + t('{n} dispositivos', {n: (g.devices || []).length}) + '</span></div>' +
      (g.devices || []).map(d =>
        '<div class="conflict-dev" data-uid="' + esc(d.uid) + '" title="' + t('Clique para localizar no mapa') + '">' +
          '<span class="cd-name">' + esc(d.name) + (d.status === 'online' ? ' <span class="cd-on">●</span>' : '') + '</span>' +
          '<span class="cd-mac">' + esc(d.mac || '—') + '</span>' +
        '</div>').join('') +
    '</div>'
  ).join('');
  el.querySelectorAll('.conflict-dev').forEach(row => {
    row.onclick = () => {
      const n = S.devices.find(d => d.id === row.dataset.uid);
      if (!n) return;
      closeModal('modal-conflicts');
      S.selected = n.id;
      showPopover(n);
      renderList(); updateClasses();
    };
  });
}

$('stat-conflict-item').onclick = () => {
  renderConflictsModal();
  openModal('modal-conflicts');
};

$('stat-dup-item').onclick = () => {
  const sel = $('filter-select');
  if (S.filter === 'dup') {
    S.filter = 'all';
    if (sel) sel.value = 'all';
  } else {
    S.filter = 'dup';
    if (sel) sel.value = 'dup';
  }
  renderList();
};

async function loadConfig() {
  S.config = await api('/netscope/api/config');
}

async function loadSubnets() {
  const r = await api('/netscope/api/subnets');
  const list = r.subnets || [];

  S._nets = list;
  const el = $('subnet-list');

  el.innerHTML = list.map(n =>
    '<div class="subnet-item subnet-editable" data-edit="' + esc(n.subnet) + '" title="' + esc(t('Clique para editar a rede')) + '"><span>' + esc(n.subnet) + '.0/24 <span style="color:var(--gray);font-size:.65rem">GW ' + esc(n.gateway) + '</span></span>' +
    '<button data-subnet="' + esc(n.subnet) + '" title="Remover"><i class="fas fa-times"></i></button></div>'
  ).join('');
  el.querySelectorAll('.subnet-editable').forEach(item => {
    item.onclick = (e) => {
      if (e.target.closest('button[data-subnet]')) return;
      const net = list.find(n => n.subnet === item.dataset.edit);
      if (net) openCidrModal(net);
    };
  });
  el.querySelectorAll('button[data-subnet]').forEach(b => {
    b.onclick = async () => {
      const sub = b.dataset.subnet;
      const r = await api('/netscope/api/subnets', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ subnet: sub }) });
      if (r.error) { toast(r.error, 'err'); return; }
      toast(t('Rede removida'), 'ok'); loadSubnets();
    };
  });
  $('subnet-info').textContent = list.length ? list.map(n => n.subnet + '.0/24').join(' | ') : t('Nenhuma rede configurada');
  return list;
}

function getFiltered() {
  const q = S.search.toLowerCase();
  const today = new Date().toISOString().slice(0, 10);
  return S.devices.filter(d => {
    if (S.filter === 'online' && d.status !== 'online') return false;
    if (S.filter === 'offline' && d.status !== 'offline') return false;
    if (S.filter === 'new' && !(d.first_seen && d.first_seen.slice(0,10) === today)) return false;
    if (S.filter === 'undoc' && d.user) return false;
    if (S.filter === 'agent' && !d.has_agent) return false;
    if (S.filter === 'noagent' && d.has_agent) return false;

    if (S.filter === 'dup' && !d.dup) return false;
    if (q) {
      const blob = [d.ip, d.mac, d.name, d.vendor, d.user, d.department, d.location, d.asset_tag, d.hostname, d.dns_name, d.model, d.seal_number, d.serial_number, d.has_agent ? t('com agente wazuh agent') : t('sem agente wazuh no agent')]
        .filter(Boolean).join(' ').toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  });
}

const _HOST_RE = /^(?!-)[A-Za-z0-9.-]+(?<!-)$/;
function _machineUrl(node) {

  let h = String(node.agent_name || '').trim();
  if (!_HOST_RE.test(h)) h = String(node.hostname || '').trim();
  return (node.has_agent && _HOST_RE.test(h)) ? ('/machine/' + encodeURIComponent(h)) : null;
}

function renderList() {
  const devs = getFiltered();
  const el = $('device-list');
  const empty = $('empty-msg');
  if (!devs.length) { el.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  el.innerHTML = devs.map(n => {
    const sel = S.selected === n.id ? ' selected' : '';
    const off = n.status === 'offline' ? ' offline' : '';
    const dnsTag = n.dns_name && n.dns_name !== n.name ? ' <span style="color:var(--info);font-size:.55rem">DNS</span>' : '';

    const arpTag = n.discovery === 'arp' ? ' <span class="arp-tag" title="' + t('Descoberto via ARP (não responde ping)') + '">ARP</span>' : '';
    const userTag = n.user ? ' <span style="color:var(--success);font-size:.55rem" title="' + esc(n.user) + '">●</span>' : '';
    const portTag = n.switch_port ? ' <span style="color:var(--warning);font-size:.55rem" title="' + t('Porta {p}', {p: n.switch_port.port}) + '">P' + esc(n.switch_port.port) + '</span>' : '';

    const confCnt = S.conflictUids ? (S.conflictUids[n.id] || 0) : 0;
    const confTag = confCnt
      ? ' <span class="ip-conflict-tag" title="' + esc(t('{n} dispositivos usam este IP', {n: confCnt})) + '"><i class="fas fa-triangle-exclamation"></i></span>'
      : '';

    const DUP_R = { ip: 'mesmo IP', hostname: 'mesmo hostname', 'mac-prefix': 'mesmo fabricante (prefixo de MAC)' };
    const dupReasons = n.dup ? String(n.dup).split(',').filter(Boolean) : [];
    const dupTag = dupReasons.length
      ? ' <span class="dup-tag" title="' + esc(t('Duplicado') + ' — ' + dupReasons.map(r => t(DUP_R[r] || r)).join(', ')) + '"><i class="fas fa-clone"></i></span>'
      : '';

    const agTag = n.has_agent
      ? ' <span class="ag-tag yes" title="' + t('Com agente Wazuh') + (n.agent_id ? ' (ID ' + esc(n.agent_id) + ')' : '') + '"><i class="fas fa-shield-halved"></i></span>'
      : (n.agent_exempt
        ? ' <span class="ag-tag na" title="' + t('Sem possibilidade de agente — não conta como sem agente') + '"><i class="fas fa-shield-halved"></i></span>'
        : ' <span class="ag-tag no" title="' + t('SEM agente Wazuh — instalar') + '"><i class="fas fa-shield-halved"></i></span>');

    const mUrl = _machineUrl(n);
    const fichaBtn = mUrl
      ? ' <button class="dev-ficha-btn" data-machine-url="' + esc(mUrl) + '" title="' + t('Abrir a ficha completa da máquina no Inventory') + '"><i class="fas fa-id-card"></i></button>'
      : '';
    return '<div class="dev-card ' + sel + off + '" data-id="' + esc(n.id) + '">' +
      '<div class="dot ' + (n.status === 'online' ? 'on' : 'off') + '"></div>' +
      '<div class="info">' +
        '<div class="name">' + esc(n.name) + agTag + dupTag + dnsTag + arpTag + userTag + portTag + fichaBtn + '</div>' +
        '<div class="ip">' + esc(n.ip) + confTag + '</div>' +
        '<div class="meta"><span class="mac">' + esc(n.mac || '—') + '</span><span class="vendor">' + esc(n.vendor||'?') + '</span></div>' +
      '</div></div>';
  }).join('');
  el.querySelectorAll('.dev-card').forEach(card => {
    card.onclick = (e) => {
      if (e.ctrlKey || e.metaKey) { handleCtrlLink(card.dataset.id); return; }

      const ficha = e.target.closest('.dev-ficha-btn');
      if (ficha) { window.location.href = ficha.dataset.machineUrl; return; }
      const n = S.devices.find(d => d.id === card.dataset.id);
      if (n) showPopover(n);
    };
  });
}

const canvas = $('canvas');
const svg = d3.select('#graph');
svg.on('contextmenu', e => e.preventDefault());

const gMain = svg.append('g');
const gLinks = gMain.append('g');
const gPortLabels = gMain.append('g');
const gNodes = gMain.append('g');

let W = canvas.clientWidth, H = canvas.clientHeight;

const zoom = d3.zoom()
  .filter(e => e.button === 2 || e.type === 'wheel')
  .scaleExtent([0.05, 5])
  .on('zoom', e => gMain.attr('transform', e.transform));
svg.call(zoom);

const simulation = d3.forceSimulation()
  .force('link', d3.forceLink().id(d => d.id).distance(130).strength(0.4))
  .force('charge', d3.forceManyBody().strength(-60))
  .force('collision', d3.forceCollide().radius(45))
  .force('layout', forceTreeLayout())
  .alphaDecay(0.03)
  .velocityDecay(0.55);

function resize() {
  W = canvas.clientWidth; H = canvas.clientHeight;
}
window.addEventListener('resize', resize);

function buildLinks() {
  const targetCounts = {}, targetIndices = {}, links = [];
  S.devices.forEach(d => {
    if (!d.parent_id) return;
    targetCounts[d.parent_id] = (targetCounts[d.parent_id] || 0) + 1;
  });
  S.devices.forEach(d => {
    if (!d.parent_id) return;
    const child = d.id, parent = d.parent_id;
    const idx = targetIndices[parent] || 0;
    targetIndices[parent] = idx + 1;
    const cnt = targetCounts[parent];
    const sortKey = child < parent ? child + '|' + parent : parent + '|' + child;

    const sp = d.switch_port || null;
    links.push({
      source: child, target: parent, key: sortKey,
      pidx: idx, pcnt: cnt,
      inferred: d.parent_inferred, confidence: d.parent_confidence,
      port_label: sp ? (sp.label || ('P' + sp.port)) : '',
      port_num: sp ? sp.port : null,
      vlan: sp ? sp.vlan : '',
    });
  });
  return links;
}

function linkPath(d) {
  const sx = d.source.x, sy = d.source.y, tx = d.target.x, ty = d.target.y;
  if (sx == null || tx == null) return '';
  const dx = tx - sx, dy = ty - sy, len = Math.hypot(dx, dy) || 1;
  const offset = d.pcnt <= 1 ? 0 : (d.pidx - (d.pcnt - 1) / 2) * 18;
  const nx = -dy / len, ny = dx / len;
  return 'M' + sx + ',' + sy + ' Q' + ((sx+tx)/2 + nx*offset) + ',' + ((sy+ty)/2 + ny*offset) + ' ' + tx + ',' + ty;
}

let _dragMoved = false;
const dragBehavior = d3.drag()
  .on('start', (event, d) => {
    if (!event.active) simulation.alphaTarget(0.08).restart();
    _dragMoved = false;
    d.fx = d.x; d.fy = d.y;
  })
  .on('drag', (event, d) => {
    _dragMoved = true;
    d.fx = event.x; d.fy = event.y;
  })
  .on('end', (event, d) => {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null; d.fy = null;

    if (_dragMoved && !S.snapshotView) {
      api('/netscope/api/devices/' + d.id, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ pos: { x: d.x, y: d.y } }) });
    }
  });

function updateGraph() {
  if (S.layoutMode === 'tree') computeTreeData();
  else if (S.layoutMode === 'hierarchy') computeHierarchyLayout();
  else if (S.layoutMode === 'grid') computeGridLayout();
  const links = buildLinks();

  const curMacSet = S.devices.map(d => d.id).sort().join(',');
  const structuralChange = curMacSet !== S._prevMacSet;
  S._prevMacSet = curMacSet;

  const linkKey = d => d.key + '-' + d.pidx;
  const linkEls = gLinks.selectAll('path.link-el')
    .data(links, linkKey)
    .join(
      enter => enter.append('path').attr('class', d => 'link link-el' + (d.inferred ? ' inferred' : '')),
      update => update.attr('class', d => 'link link-el' + (d.inferred ? ' inferred' : '')),
      exit => exit.remove()
    );

  const portEls = gPortLabels.selectAll('g.port-label')
    .data(links.filter(l => l.port_label), linkKey)
    .join(
      enter => enter.append('g').attr('class', 'port-label')
        .each(function() {
          const g = d3.select(this);
          g.append('rect').attr('class', 'port-label-bg').attr('rx', 3).attr('ry', 3);
          g.append('text').attr('class', 'port-label-text').attr('text-anchor', 'middle').attr('dy', '0.32em');
        }),
      update => update,
      exit => exit.remove()
    );

  const nodeSel = gNodes.selectAll('g.node').data(S.devices, d => d.id);
  nodeSel.exit().remove();
  const nodeEnter = nodeSel.enter().append('g').attr('class', 'node').attr('data-id', d => d.id).call(dragBehavior);
  nodeEnter.append('circle').attr('class', 'ring').attr('r', 20);
  nodeEnter.append('circle').attr('class', 'fill').attr('r', 16);
  nodeEnter.append('g').attr('class', 'ico').attr('transform', 'translate(-8,-8)');
  nodeEnter.append('text').attr('class', 'nlabel').attr('dy', 32).attr('text-anchor', 'middle');
  nodeEnter.append('text').attr('class', 'nsub').attr('dy', 43).attr('text-anchor', 'middle');

  nodeEnter.append('circle').attr('class', 'user-badge').attr('r', 4).attr('cx', 14).attr('cy', -14).attr('fill', 'var(--success)').style('display', 'none');

  const AGENT_YES = '#10b981', AGENT_NO = '#ef4444', AGENT_NA = '#94a3b8';
  nodeEnter.append('circle').attr('class', 'agent-badge').attr('r', 6).attr('cx', -14).attr('cy', -14)
    .attr('fill', d => d.has_agent ? AGENT_YES : (d.agent_exempt ? AGENT_NA : AGENT_NO))
    .attr('stroke', '#ffffff').attr('stroke-width', 1.5);
  nodeEnter.append('g').attr('class', 'agent-badge-ico').attr('transform', 'translate(-19,-21.5)')
    .html('<path d="M2 5l3-2 3 2v3c0 2-1.4 3.4-3 4-1.6-.6-3-2-3-4z" fill="#fff"/>')
    .style('pointer-events', 'none');

  nodeEnter.append('line').attr('class', 'agent-badge-slash')
    .attr('x1', -18.2).attr('y1', -9.8).attr('x2', -9.8).attr('y2', -18.2)
    .attr('stroke', '#ffffff').attr('stroke-width', 1.4).attr('stroke-linecap', 'round')
    .style('pointer-events', 'none').style('display', 'none');

  nodeEnter.append('circle').attr('class', 'conflict-badge').attr('r', 6)
    .attr('cx', -14).attr('cy', 14)
    .attr('fill', '#F59E0B').attr('stroke', '#ffffff').attr('stroke-width', 1.5)
    .style('display', 'none').style('pointer-events', 'none');
  nodeEnter.append('text').attr('class', 'conflict-badge-txt').attr('x', -14).attr('y', 14)
    .attr('text-anchor', 'middle').attr('dy', '0.35em')
    .attr('fill', '#ffffff').attr('font-size', '9px').attr('font-weight', '700')
    .text('!').style('display', 'none').style('pointer-events', 'none');
  const nodes = nodeEnter.merge(nodeSel);

  nodes.each(function(d) {
    const g = d3.select(this);
    const dtype = d.type || 'desktop';
    const off = d.status === 'offline';
    let rc = 'ring ' + (d.parent_id ? 'known' : 'unknown');
    if (S.selected === d.id) rc += ' selected';
    if (S.ctrlLink === d.id) rc += ' ctrl-link-parent';
    if (S.snapshotView) rc += ' snapshot';
    g.select('.ring').attr('class', rc);
    g.select('.fill').attr('fill', off ? (document.documentElement.classList.contains('dark-mode') ? '#1e293b' : '#f1f5f9') : (FILL_COLORS[dtype] || '#f1f5f9')).attr('class', 'fill' + (off ? ' offline' : ''));
    g.select('.ico').html(SVG_ICONS[dtype] || SVG_ICONS.desktop).attr('color', off ? (document.documentElement.classList.contains('dark-mode') ? '#475569' : '#94a3b8') : (ICON_COLORS[dtype] || '#64748b'));
    g.select('.nlabel').text(d.name);
    g.select('.nsub').text(d.ip);
    g.select('.user-badge').style('display', d.user ? '' : 'none').attr('title', d.user || '');

    const naAg = !d.has_agent && d.agent_exempt;
    g.select('.agent-badge').attr('fill', d.has_agent ? '#10b981' : (naAg ? '#94a3b8' : '#ef4444'))
      .attr('title', d.has_agent ? (t('Agente Wazuh: SIM') + (d.agent_id ? t(' (ID {id}, {st})', {id: d.agent_id, st: d.agent_status || '?'}) : '')) : (naAg ? t('Agente Wazuh: Não aplicável') : t('Agente Wazuh: NÃO instalado')));
    g.select('.agent-badge-slash').style('display', naAg ? '' : 'none');

    const nConf = S.conflictUids ? (S.conflictUids[d.id] || 0) : 0;
    g.select('.conflict-badge').style('display', nConf ? '' : 'none')
      .attr('title', nConf ? t('{n} dispositivos usam este IP', {n: nConf}) : '');
    g.select('.conflict-badge-txt').style('display', nConf ? '' : 'none');
  });

  nodes.on('click', (event, d) => {
    if (event.defaultPrevented || _dragMoved) return;
    if (event.ctrlKey || event.metaKey) {
      handleCtrlLink(d.id);
      return;
    }
    showPopover(d);
  })
    .on('mouseenter', function(event, d) {
      if (S.ctrlLink === d.id) { d3.select(this).select('.ring').classed('ctrl-link-parent', true); return; }
      if (S.ctrlLink) { d3.select(this).classed('ctrl-link-target', true); return; }
      d3.select(this).select('.ring').classed('hover', true);
    })
    .on('mouseleave', function() {
      d3.select(this).classed('ctrl-link-target', false);
      d3.select(this).select('.ring').classed('ctrl-link-parent', false);
      d3.select(this).select('.ring').classed('hover', false);
    })
    .on('contextmenu', (event, d) => { event.stopPropagation(); if (!S.snapshotView) showCtxMenu(event, d); });

  const curLinkSet = links.map(l => l.key + '-' + l.pidx).sort().join(';');
  const linkChange = curLinkSet !== (S._prevLinkSet || '');
  S._prevLinkSet = curLinkSet;
  const needsRestart = structuralChange || linkChange;

  function tick() {
    linkEls.attr('d', linkPath);
    nodes.attr('transform', d => d.x != null ? 'translate(' + d.x + ',' + d.y + ')' : '');
    linkEls.classed('hl', d => { if (!S.selected) return false; const sid=d.source.id||d.source, tid=d.target.id||d.target; return sid===S.selected||tid===S.selected; });

    portEls.each(function(d) {
      const g = d3.select(this);

      const sx = d.source.x || 0, sy = d.source.y || 0, tx = d.target.x || 0, ty = d.target.y || 0;
      const px = sx + (tx - sx) * 0.3;
      const py = sy + (ty - sy) * 0.3;
      const labelText = d.port_label + (d.vlan ? '/V' + d.vlan : '');
      g.attr('transform', 'translate(' + px + ',' + py + ')');
      g.select('.port-label-text').text(labelText);

      const textNode = g.select('.port-label-text').node();
      if (textNode) {
        const bbox = textNode.getBBox();
        g.select('.port-label-bg')
          .attr('x', bbox.x - 4)
          .attr('y', bbox.y - 2)
          .attr('width', bbox.width + 8)
          .attr('height', bbox.height + 4);
      }
    });

    if (S.popover) { const pn=S.devices.find(n=>n.id===S.popover); if(pn) positionPopover(pn); }
  }

  simulation.nodes(S.devices);
  simulation.force('link').links(links);
  simulation.on('tick', tick);

  if (needsRestart) {
    simulation.alpha(0.15).restart();
  } else {
    tick();
  }
}

function updateClasses() {
  gNodes.selectAll('g.node').each(function(d) {
    let rc = 'ring ' + (d.parent_id ? 'known' : 'unknown');
    if (S.selected === d.id) rc += ' selected';
    if (S.ctrlLink === d.id) rc += ' ctrl-link-parent';
    if (S.snapshotView) rc += ' snapshot';
    d3.select(this).select('.ring').attr('class', rc);
  });
}

const ctxMenu = $('ctx-menu');
const ctxItems = $('ctx-items');

function showCtxMenu(event, node) {
  event.preventDefault();
  hidePopover();
  S._ctxKey = node.id;
  $('ctx-name').textContent = node.name;
  $('ctx-ip').textContent = node.ip + ' \u00b7 ' + (node.mac || t('sem MAC'));
  $('ctx-dot').className = 'status-dot ' + (node.status === 'online' ? 'on' : 'off');
  $('ctx-dot').style.marginTop = '2px';

  const hasParent = !!node.parent_id;
  const parentName = hasParent ? (S.devices.find(n => n.id === node.parent_id)?.name || node.parent_id) : '';

  let html = '';
  html += '<div class="ctx-item" data-act="edit"><i class="fas fa-pen"></i> ' + t('Editar / Documentar') + '</div>';
  html += '<div class="ctx-item" data-act="ping"><i class="fas fa-signal"></i> ' + t('Ping') + '</div>';
  html += '<div class="ctx-item" data-act="ports"><i class="fas fa-ethernet"></i> ' + t('Portas TCP') + '</div>';

  html += '<div class="ctx-item" data-act="agent-exempt"><i class="fas fa-' + (node.agent_exempt ? 'check-square' : 'user-slash') + '"></i> '
    + (node.agent_exempt ? '\u2713 ' : '') + t('Agente não aplicável') + '</div>';

  if (_machineUrl(node)) {
    html += '<div class="ctx-item" data-act="machine"><i class="fas fa-id-card"></i> ' + t('Ficha da Máquina') + '</div>';
  }
  if (node.type === 'switch') {
    html += '<div class="ctx-item" data-act="switch-ports"><i class="fas fa-network-wired"></i> ' + t('Gerenciar Portas') + '</div>';
  }
  html += '<div class="ctx-sep"></div>';
  if (hasParent) {
    html += '<div class="ctx-item" data-act="unlink"><i class="fas fa-unlink"></i> ' + t('Desassociar ({p})', {p: parentName}) + '</div>';
  } else {
    html += '<div class="ctx-item ctx-hint" data-act="none"><i class="fas fa-link"></i> ' + t('Ctrl+Clique para associar') + '</div>';
  }
  html += '<div class="ctx-sep"></div>';
  html += '<div class="ctx-item" data-act="copy-ip"><i class="fas fa-copy"></i> ' + t('Copiar IP') + '</div>';
  html += '<div class="ctx-item" data-act="copy-mac"><i class="fas fa-copy"></i> ' + t('Copiar MAC') + '</div>';
  if (node.user) {
    html += '<div class="ctx-item" data-act="copy-user"><i class="fas fa-user"></i> ' + t('Copiar Usuário') + '</div>';
  }
  if (node.dns_name) {
    html += '<div class="ctx-item" data-act="copy-dns"><i class="fas fa-copy"></i> ' + t('Copiar DNS: {d}', {d: node.dns_name}) + '</div>';
  }
  html += '<div class="ctx-sep"></div>';
  html += '<div class="ctx-item ctx-danger" data-act="trash"><i class="fas fa-trash"></i> ' + t('Mover para lixeira') + '</div>';

  ctxItems.innerHTML = html;
  ctxItems.querySelectorAll('.ctx-item').forEach(item => {
    item.onclick = async () => {
      const act = item.dataset.act;
      const mac = S._ctxKey;
      if (!mac) return;
      const n = S.devices.find(d => d.id === mac);
      hideCtxMenu();
      if (!n) return;
      await handleCtxAction(act, n);
    };
  });

  ctxMenu.classList.remove('hidden');
  const x = event.clientX, y = event.clientY;
  ctxMenu.style.left = '0px'; ctxMenu.style.top = '0px';
  const mw = ctxMenu.offsetWidth, mh = ctxMenu.offsetHeight;
  ctxMenu.style.left = ((x + mw > window.innerWidth) ? x - mw - 4 : x) + 'px';
  ctxMenu.style.top = ((y + mh > window.innerHeight) ? y - mh - 4 : y) + 'px';
}

async function handleCtxAction(act, node) {
  if (act === 'edit') {
    openEditModal(node);
  } else if (act === 'agent-exempt') {

    const r = await api('/netscope/api/devices/' + node.id, {
      method: 'PUT', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({agent_exempt: !node.agent_exempt})
    });
    if (r.error) { toast(t('Erro: {e}', {e: r.error}), 'err'); return; }
    toast(node.agent_exempt
      ? t('{n} volta a contar como sem agente', {n: node.name})
      : t('{n} fora do computo sem agente', {n: node.name}), 'ok');
    loadDevices();
  } else if (act === 'machine') {

    const url = _machineUrl(node);
    if (url) window.location.href = url;
  } else if (act === 'switch-ports') {
    openSwitchPortModal(node.id);
  } else if (act === 'ping') {
    toast(t('Pingando {ip}...', {ip: node.ip}), 'ok');
    const r = await api('/netscope/api/devices/' + node.id + '/ping', { method: 'POST' });
    if (r.error) { toast(t('Ping falhou: {e}', {e: r.error}), 'err'); return; }
    toast(node.ip + ': ' + (r.reachable ? (r.avg_rtt + 'ms' + (r.ttl ? ' TTL=' + r.ttl : '')) : t('sem resposta')), r.reachable ? 'ok' : 'err');
    loadDevices();
  } else if (act === 'ports') {

    openPortScanModal(node);
  } else if (act === 'unlink') {
    if (!node.parent_id) { toast(t('Sem associação'), 'warn'); return; }
    const r = await api('/netscope/api/links', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ mac: node.id }) });
    if (r.error) { toast(r.error, 'err'); return; }
    toast(t('Desassociado'), 'ok'); loadDevices();
  } else if (act === 'trash') {
    if (confirm(t('Mover {n} para lixeira?', {n: node.name}))) {
      const r = await api('/netscope/api/devices/' + node.id, { method: 'DELETE' });
      if (r.error) { toast(r.error, 'err'); return; }
      loadDevices(); toast(t('Movido para lixeira'), 'warn');
    }
  } else if (act === 'copy-ip') {
    navigator.clipboard?.writeText(node.ip).then(() => toast('IP: ' + node.ip, 'ok'));
  } else if (act === 'copy-mac') {
    if (node.mac) { navigator.clipboard?.writeText(node.mac).then(() => toast('MAC: ' + node.mac, 'ok')); }
    else { toast(t('Sem MAC cadastrado'), 'warn'); }
  } else if (act === 'copy-user') {
    navigator.clipboard?.writeText(node.user).then(() => toast(t('Usuário: {u}', {u: node.user}), 'ok'));
  } else if (act === 'copy-dns') {
    navigator.clipboard?.writeText(node.dns_name).then(() => toast('DNS: ' + node.dns_name, 'ok'));
  }
}

function hideCtxMenu() { ctxMenu.classList.add('hidden'); S._ctxKey = null; }

document.addEventListener('click', e => { if (!ctxMenu.contains(e.target)) hideCtxMenu(); });
document.addEventListener('contextmenu', e => { if (!e.target.closest('.node')) hideCtxMenu(); });

const popoverEl = $('popover');

function showPopover(node) {
  S.popover = node.id; S.selected = node.id; renderList(); updateClasses();
  $('pop-name').textContent = node.name;
  $('pop-dot').className = 'status-dot ' + (node.status === 'online' ? 'on' : 'off');
  const body = $('pop-body');
  const rttStr = node.avg_rtt != null ? node.avg_rtt + ' ms' : '-';
  const ttlStr = node.ttl != null ? node.ttl : '-';
  const dnsStr = node.dns_name || '-';
  const ports = node.open_ports || [];
  const parent = node.parent_id ? (S.devices.find(p => p.id === node.parent_id)?.name || node.parent_id) : t('Nenhum');
  const pCls = node.parent_inferred ? 'val inferred' : 'val';
  const sp = node.switch_port || null;
  const swName = sp ? (S.devices.find(d => d.id === sp.switch_mac)?.name || sp.switch_mac) : '';
  const agYes = !!node.has_agent;

  const agentStr = agYes
    ? (t('Sim') + (node.agent_id ? ' — ID ' + esc(node.agent_id) : '') + (node.agent_status ? ' (' + esc(node.agent_status) + ')' : ''))
    : (node.agent_exempt ? t('Não aplicável') : t('Não instalado'));
  const agValCls = agYes ? 'agent-yes' : (node.agent_exempt ? 'agent-na' : 'agent-no');

  const exemptRow = (!agYes && node.agent_exempt)
    ? '<div class="pop-row"><span class="lbl"><i class="fas fa-user-slash"></i> ' + t('Agente não aplicável') + '</span><span class="val"><span class="ex-tag">' + t('Isento') + '</span> ' + t('não conta como sem agente') + '</span></div>'
    : '';
  let html =
    '<div class="pop-row"><span class="lbl"><i class="fas fa-shield-halved"></i> ' + t('Agente Wazuh') + '</span><span class="val ' + agValCls + '">' + agentStr + '</span></div>' +
    exemptRow +
    '<div class="pop-row"><span class="lbl">MAC</span><span class="val">' + esc(node.mac || '—') + '</span></div>' +
    '<div class="pop-row"><span class="lbl">DNS</span><span class="val">' + esc(dnsStr) + '</span></div>' +

    ((S.conflictUids && (S.conflictUids[node.id] || 0) > 0)
      ? '<div class="pop-row"><span class="lbl"><i class="fas fa-triangle-exclamation"></i> ' + t('Conflito de IP') + '</span><span class="val conflict-val">' + esc(t('{n} dispositivos usam este IP', {n: S.conflictUids[node.id]})) + '</span></div>'
      : '') +
    '<div class="pop-row"><span class="lbl">' + t('Fabricante') + '</span><span class="val">' + esc(node.vendor||'-') + '</span></div>' +
    (node.model ? '<div class="pop-row"><span class="lbl">' + t('Modelo') + '</span><span class="val">' + esc(node.model) + '</span></div>' : '') +
    '<div class="pop-row"><span class="lbl">RTT</span><span class="val">' + rttStr + '</span></div>' +
    '<div class="pop-row"><span class="lbl">TTL</span><span class="val">' + ttlStr + '</span></div>' +
    (node.discovery === 'arp'
      ? '<div class="pop-row"><span class="lbl"><i class="fas fa-tower-broadcast"></i> ' + t('Descoberta') + '</span><span class="val"><span class="arp-tag">ARP</span> ' + t('via ARP (não responde ping)') + '</span></div>'
      : '') +
    '<div class="pop-row"><span class="lbl">' + t('Pai') + '</span><span class="' + pCls + '">' + esc(parent) + (node.parent_inferred ? ' (' + node.parent_confidence + '%)' : '') + '</span></div>';
  if (agYes && node.agent_last_keepalive) {
    html += '<div class="pop-row"><span class="lbl">KeepAlive</span><span class="val">' + esc(fmtDate(node.agent_last_keepalive)) + '</span></div>';
  }

  if (node.user || node.department || node.location || node.asset_tag || node.seal_number) {
    html += '<div class="pop-divider"></div>';
    if (node.user) html += '<div class="pop-row"><span class="lbl"><i class="fas fa-user"></i> ' + t('Usuário') + '</span><span class="val">' + esc(node.user) + '</span></div>';
    if (node.department) html += '<div class="pop-row"><span class="lbl">' + t('Depto') + '</span><span class="val">' + esc(node.department) + '</span></div>';
    if (node.location) html += '<div class="pop-row"><span class="lbl">' + t('Local') + '</span><span class="val">' + esc(node.location) + '</span></div>';
    if (node.asset_tag) html += '<div class="pop-row"><span class="lbl">Asset Tag</span><span class="val">' + esc(node.asset_tag) + '</span></div>';
    if (node.seal_number) html += '<div class="pop-row"><span class="lbl"><i class="fas fa-tag"></i> ' + t('Lacre') + '</span><span class="val">' + esc(node.seal_number) + '</span></div>';
  }

  if (sp) {
    html += '<div class="pop-divider"></div>';
    html += '<div class="pop-row"><span class="lbl"><i class="fas fa-ethernet"></i> ' + t('Switch') + '</span><span class="val">' + esc(swName) + '</span></div>';
    html += '<div class="pop-row"><span class="lbl">' + t('Porta') + '</span><span class="val">' + esc(sp.label || ('P' + sp.port)) + (sp.vlan ? ' / VLAN ' + esc(sp.vlan) : '') + '</span></div>';
  }
  if (ports.length) html += '<div class="pop-ports">' + ports.map(p => '<span class="pop-port">' + p + '</span>').join('') + '</div>';
  body.innerHTML = html;

  const actBar = popoverEl.querySelector('.popover-actions');
  const hasParent = !!node.parent_id;
  const isSwitch = node.type === 'switch';

  actBar.innerHTML =
    '<button class="btn btn-sm btn-outline" data-act="edit"><i class="fas fa-pen"></i> ' + t('Editar') + '</button>' +
    '<button class="btn btn-sm btn-outline" data-act="ping"><i class="fas fa-signal"></i> ' + t('Ping') + '</button>' +
    '<button class="btn btn-sm btn-outline" data-act="ports"><i class="fas fa-ethernet"></i> ' + t('Portas') + '</button>' +

    '<button class="btn btn-sm ' + (node.agent_exempt ? 'btn-warning' : 'btn-outline') + '" data-act="agent-exempt" title="' + t('Sem possibilidade de agente — não conta como sem agente') + '"><i class="fas fa-user-slash"></i> ' + (node.agent_exempt ? '\u2713 ' : '') + t('Não apl.') + '</button>' +
    (isSwitch ? '<button class="btn btn-sm btn-outline" data-act="switch-ports"><i class="fas fa-network-wired"></i> Sw</button>' : '') +
    (hasParent
      ? '<button class="btn btn-sm btn-warning" data-act="unlink"><i class="fas fa-unlink"></i> ' + t('Desassoc.') + '</button>'
      : '<button class="btn btn-sm btn-outline" data-act="link"><i class="fas fa-link"></i> ' + t('Assoc.') + '</button>') +

    '<button class="btn btn-sm btn-warning" data-act="trash"><i class="fas fa-trash"></i> ' + t('Excluir') + '</button>';

  positionPopover(node); popoverEl.classList.remove('hidden');
}

function positionPopover(node) {
  if (node.x == null) return;
  const zt = d3.zoomTransform(svg.node());
  const sx = node.x * zt.k + zt.x, sy = node.y * zt.k + zt.y;
  const TOPBAR = 46; const pw = 280, ph = popoverEl.offsetHeight || 220;
  let left = sx + 28, top = sy + TOPBAR - 16;
  if (left + pw > canvas.clientWidth - 8) left = sx - pw - 28;
  if (left < 8) left = 8;
  if (top + ph > canvas.clientHeight - 8) top = canvas.clientHeight - ph - 8;
  if (top < TOPBAR + 4) top = TOPBAR + 4;
  popoverEl.style.left = left + 'px'; popoverEl.style.top = top + 'px';
}

function hidePopover() { popoverEl.classList.add('hidden'); S.popover = null; }
$('pop-close').onclick = hidePopover;

popoverEl.querySelector('.popover-actions').addEventListener('click', async e => {
  const btn = e.target.closest('.btn');
  if (!btn) return;
  const act = btn.dataset.act;
  const node = S.devices.find(n => n.id === S.popover);
  if (!node) return;
  if (act === 'edit') { hidePopover(); openEditModal(node); }

  else if (act === 'agent-exempt') {
    const r = await api('/netscope/api/devices/' + node.id, {
      method: 'PUT', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({agent_exempt: !node.agent_exempt})
    });
    if (r.error) { toast(t('Erro: {e}', {e: r.error}), 'err'); return; }
    toast(node.agent_exempt
      ? t('{n} volta a contar como sem agente', {n: node.name})
      : t('{n} fora do computo sem agente', {n: node.name}), 'ok');
    hidePopover(); loadDevices();
  }

  else if (act === 'switch-ports') { hidePopover(); openSwitchPortModal(node.id); }
  else if (act === 'ping') {
    toast(t('Pingando {ip}...', {ip: node.ip}), 'ok');
    const r = await api('/netscope/api/devices/' + node.id + '/ping', { method: 'POST' });
    if (r.error) { toast(t('Ping falhou: {e}', {e: r.error}), 'err'); return; }
    toast(node.ip + ': ' + (r.reachable ? r.avg_rtt + 'ms' : t('sem resposta')), r.reachable ? 'ok' : 'err'); loadDevices();
  }
  else if (act === 'ports') {

    hidePopover(); openPortScanModal(node);
  }
  else if (act === 'link') {
    S.ctrlLink = node.id;
    updateClasses();
    toast(t('Ctrl+Clique no FILHO para associar a {n}', {n: node.name}), 'ok');
  }
  else if (act === 'unlink') {
    if (!node.parent_id) { toast(t('Sem associação'), 'warn'); return; }
    const r = await api('/netscope/api/links', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ mac: node.id }) });
    if (r.error) { toast(r.error, 'err'); return; }
    hidePopover(); toast(t('Desassociado'), 'ok'); loadDevices();
  }
  else if (act === 'trash') {
    hidePopover();
    if (confirm(t('Mover {n} para lixeira?', {n: node.name}))) {
      const r = await api('/netscope/api/devices/' + node.id, { method: 'DELETE' });
      if (r.error) { toast(r.error, 'err'); return; }
      loadDevices(); toast(t('Movido para lixeira'), 'warn');
    }
  }

});

const linkBanner = $('link-banner'); const linkText = $('link-text');

function handleCtrlLink(mac) {
  hidePopover();
  if (!S.ctrlLink) {
    S.ctrlLink = mac;
    const p = S.devices.find(n => n.id === mac);
    linkText.textContent = t('Pai: {n} — Ctrl+Clique no FILHO', {n: p?.name || mac});
    linkBanner.classList.remove('hidden');
    updateClasses();
  } else {
    if (mac === S.ctrlLink) { toast(t('Não pode conectar a si mesmo'), 'err'); cancelCtrlLink(); return; }
    const parentMac = S.ctrlLink;
    let circ = false, cur = S.devices.find(n => n.id === parentMac);
    while (cur) { if (cur.parent_id === mac) { circ = true; break; } if (!cur.parent_id) break; cur = S.devices.find(n => n.id === cur.parent_id); }
    if (circ) { toast(t('Link circular detectado'), 'err'); cancelCtrlLink(); return; }
    api('/netscope/api/links', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ child: mac, parent: parentMac }) }).then(r => {
      if (r.error) { toast(r.error, 'err'); return; }
      toast(t('Associado'), 'ok'); cancelCtrlLink(); loadDevices();
    });
  }
}

function cancelCtrlLink() {
  S.ctrlLink = null;
  linkBanner.classList.add('hidden');
  updateClasses();
}

$('btn-link').onclick = () => {
  if (S.ctrlLink) { cancelCtrlLink(); return; }
  toast(t('Ctrl+Clique em um nó PAI, depois Ctrl+Clique no FILHO'), 'ok');
};
$('link-cancel').onclick = cancelCtrlLink;

function openEditModal(node) {
  S.selected = node.id;
  $('ed-id').value = node.id; $('ed-ip').value = node.ip;
  $('ed-mac-vis').value = node.mac || ''; $('ed-vendor').value = node.vendor || '';
  $('ed-dns').value = node.dns_name || '-';
  $('ed-subnet').value = (node.subnet || '') + '.0/24';
  $('ed-name').value = node.hostname || '';

  const edTypeSel = $('ed-type');
  const edVal = node.type || 'desktop';

  edTypeSel.querySelectorAll('option[data-legacy]').forEach(o => o.remove());
  if (edVal && !edTypeSel.querySelector('option[value="' + edVal + '"]')) {
    const opt = document.createElement('option');
    opt.value = edVal; opt.dataset.legacy = '1';
    opt.textContent = t(TYPE_LABELS[edVal] || edVal);
    edTypeSel.appendChild(opt);
  }
  edTypeSel.value = edVal;
  $('ed-notes').value = node.notes || '';

  $('ed-user').value = node.user || '';
  $('ed-department').value = node.department || '';
  $('ed-location').value = node.location || '';
  $('ed-asset-tag').value = node.asset_tag || '';
  $('ed-model').value = node.model || '';
  $('ed-serial').value = node.serial_number || '';
  $('ed-os').value = node.os || '';
  $('ed-seal').value = node.seal_number || '';
  $('ed-vlan').value = (node.switch_port && node.switch_port.vlan) || '';

  $('ed-agent-status').value = node.has_agent ? t('Sim — agente instalado') : t('Não instalado');
  $('ed-agent-info').value = node.has_agent
    ? ('ID ' + (node.agent_id || '?') + ' · ' + (node.agent_status || '?') + (node.agent_last_keepalive ? ' · ' + fmtDate(node.agent_last_keepalive) : ''))
    : '—';

  $('ed-agent-exempt').checked = !!node.agent_exempt;

  const parentSel = $('ed-parent'); parentSel.innerHTML = '<option value="">' + t('Nenhum') + '</option>';
  S.devices.forEach(n => {
    if (n.id !== node.id) {
      const opt = document.createElement('option'); opt.value = n.id;
      opt.textContent = n.name + ' (' + n.ip + ')';
      if (n.id === node.parent_id) opt.selected = true;
      parentSel.appendChild(opt);
    }
  });

  const switchSel = $('ed-switch'); switchSel.innerHTML = '<option value="">' + t('Nenhum') + '</option>';
  S.devices.forEach(n => {
    if (n.id !== node.id && n.type === 'switch') {
      const opt = document.createElement('option'); opt.value = n.id;
      opt.textContent = n.name + ' (' + n.ip + ')';
      if (node.switch_port && node.switch_port.switch_mac === n.id) opt.selected = true;
      switchSel.appendChild(opt);
    }
  });
  $('ed-switch-port').value = (node.switch_port && node.switch_port.port) || '';
  openModal('modal-edit');
}

function closeEditModal() { closeModal('modal-edit'); S.selected = null; updateClasses(); renderList(); }

$('ed-btn-save').onclick = async () => {

  const key = $('ed-id').value; if (!key) return;
  const body = {
    mac: $('ed-mac-vis').value.trim(),
    hostname: $('ed-name').value,
    ip: $('ed-ip').value,
    type: $('ed-type').value,
    parent_id: $('ed-parent').value || null,
    notes: $('ed-notes').value,
    user: $('ed-user').value,
    department: $('ed-department').value,
    location: $('ed-location').value,
    asset_tag: $('ed-asset-tag').value,
    vendor: $('ed-vendor').value,
    model: $('ed-model').value,
    serial_number: $('ed-serial').value,
    os: $('ed-os').value,
    seal_number: $('ed-seal').value,

    agent_exempt: $('ed-agent-exempt').checked,
  };

  const switchMac = $('ed-switch').value;
  const portNum = parseInt($('ed-switch-port').value, 10);
  if (switchMac && portNum > 0) {
    body.switch_port = {
      switch_mac: switchMac,
      port: portNum,
      label: 'Fa0/' + portNum,
      vlan: $('ed-vlan').value,
      speed: '',
      duplex: '',
    };
  } else {
    body.switch_port = null;
  }
  const r = await api('/netscope/api/devices/' + key, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if (r.error) { toast(t('Erro: {e}', {e: r.error}), 'err'); return; }
  closeEditModal(); loadDevices(); toast(t('Salvo'), 'ok');
};
$('ed-btn-unlink').onclick = async () => {
  const key = $('ed-id').value; if (!key) return;
  const r = await api('/netscope/api/links', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ mac: key }) });
  if (r.error) { toast(r.error, 'err'); return; }
  closeEditModal(); loadDevices(); toast(t('Desassociado'), 'ok');
};
$('ed-btn-del').onclick = async () => {
  const key = $('ed-id').value; if (!key || !confirm(t('Mover para lixeira?'))) return;
  const r = await api('/netscope/api/devices/' + key, { method: 'DELETE' });
  if (r.error) { toast(r.error, 'err'); return; }
  closeEditModal(); loadDevices(); toast(t('Movido para lixeira'), 'warn');
};

$('btn-new').onclick = () => {
  ['add-ip','add-mac','add-name','add-subnet','add-notes','add-user','add-department'].forEach(id => $(id).value = '');
  $('add-type').value = 'desktop'; openModal('modal-add');
};
$('add-btn-cancel').onclick = () => closeModal('modal-add');
$('add-btn-save').onclick = async () => {
  const ip = $('add-ip').value.trim();
  if (!ip) { toast(t('IP obrigatório'), 'err'); return; }

  const body = {
    ip, mac: $('add-mac').value.trim(),
    hostname: $('add-name').value.trim(),
    type: $('add-type').value,
    subnet: $('add-subnet').value.trim(),
    notes: $('add-notes').value.trim(),
    user: $('add-user').value.trim(),
    department: $('add-department').value.trim(),
  };
  const r = await api('/netscope/api/devices', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if (r.error) { toast(r.error, 'err'); return; }
  closeModal('modal-add'); toast(t('Criado: {ip}', {ip}), 'ok'); loadDevices();
};

let _currentSwitchMac = null;
let _switchPortEdits = {};

async function loadSwitches() {
  const r = await api('/netscope/api/switches');
  S.switches = r.switches || [];
  return S.switches;
}

$('btn-switches').onclick = async () => {
  await loadSwitches();
  openModal('modal-switches');
  renderSwitchTabs();
  if (S.switches.length) {
    selectSwitchTab(S.switches[0].mac);
  } else {
    $('switch-empty').classList.remove('hidden');
    $('switch-port-table').innerHTML = '';
    $('switch-tabs').innerHTML = '';
  }
};

function renderSwitchTabs() {
  const el = $('switch-tabs');
  if (!S.switches.length) { el.innerHTML = ''; return; }
  el.innerHTML = S.switches.map(sw =>
    '<button class="switch-tab ' + (sw.mac === _currentSwitchMac ? 'active' : '') + '" data-mac="' + esc(sw.mac) + '">' +
    esc(sw.hostname || sw.name || sw.ip) + ' <span class="switch-tab-ip">' + esc(sw.ip) + '</span></button>'
  ).join('');
  el.querySelectorAll('.switch-tab').forEach(b => {
    b.onclick = () => selectSwitchTab(b.dataset.mac);
  });
}

async function selectSwitchTab(mac) {
  _currentSwitchMac = mac;
  renderSwitchTabs();
  const sw = S.switches.find(s => s.mac === mac);
  if (!sw) return;
  _switchPortEdits = {};

  sw.ports.forEach(p => {
    _switchPortEdits[p.port] = {
      label: p.label,
      device_mac: p.device_mac,
      vlan: p.vlan,
      speed: p.speed,
      duplex: p.duplex,
      notes: p.notes,
    };
  });
  renderSwitchPortTable(sw);
}

function renderSwitchPortTable(sw) {
  const el = $('switch-port-table');

  const deviceOpts = S.devices.filter(d => d.id !== sw.mac).map(d =>
    '<option value="' + esc(d.id) + '"' + '>' + esc(d.name) + ' (' + esc(d.ip) + ')</option>'
  ).join('');
  let html = '<div class="switch-meta">';
  html += '<div><strong>' + esc(sw.hostname || sw.name || sw.ip) + '</strong> · ' + esc(sw.mac) + '</div>';
  html += '<div class="switch-meta-actions">';
  html += '<label>' + t('Portas: ') + '<input type="number" id="sw-port-count" value="' + sw.port_count + '" min="1" max="96" style="width:60px"></label>';
  html += '<button class="btn btn-sm btn-primary" id="sw-save"><i class="fas fa-save"></i> ' + t('Salvar Portas') + '</button>';
  html += '</div></div>';
  html += '<table class="port-table"><thead><tr><th>#</th><th>' + t('Label') + '</th><th>' + t('Dispositivo Conectado') + '</th><th>VLAN</th><th>' + t('Speed') + '</th><th>' + t('Duplex') + '</th></tr></thead><tbody>';
  for (let i = 1; i <= sw.port_count; i++) {
    const p = _switchPortEdits[i] || { label: 'Fa0/' + i, device_mac: '', vlan: '', speed: '', duplex: '', notes: '' };
    const assignedDev = S.devices.find(d => d.id === p.device_mac);
    html += '<tr class="' + (p.device_mac ? 'assigned' : '') + '">';
    html += '<td class="port-num">' + i + '</td>';
    html += '<td><input type="text" data-port="' + i + '" data-field="label" value="' + esc(p.label) + '" placeholder="Fa0/' + i + '"></td>';
    html += '<td><select data-port="' + i + '" data-field="device_mac"><option value="">' + t('— livre —') + '</option>';
    S.devices.forEach(d => {
      if (d.id === sw.mac) return;
      const sel = d.id === p.device_mac ? ' selected' : '';
      html += '<option value="' + esc(d.id) + '"' + sel + '>' + esc(d.name) + ' (' + esc(d.ip) + ')</option>';
    });
    html += '</select></td>';
    html += '<td><input type="text" data-port="' + i + '" data-field="vlan" value="' + esc(p.vlan) + '" placeholder="10" style="width:50px"></td>';
    html += '<td><input type="text" data-port="' + i + '" data-field="speed" value="' + esc(p.speed) + '" placeholder="1G" style="width:55px"></td>';
    html += '<td><input type="text" data-port="' + i + '" data-field="duplex" value="' + esc(p.duplex) + '" placeholder="full" style="width:60px"></td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;

  el.querySelectorAll('input[data-port], select[data-port]').forEach(inp => {
    inp.onchange = () => {
      const port = parseInt(inp.dataset.port, 10);
      const field = inp.dataset.field;
      if (!_switchPortEdits[port]) _switchPortEdits[port] = { label: 'Fa0/'+port, device_mac: '', vlan: '', speed: '', duplex: '', notes: '' };
      _switchPortEdits[port][field] = inp.value;
    };
  });

  $('sw-save').onclick = async () => {
    const portCount = parseInt($('sw-port-count').value, 10) || 24;

    const ports = {};
    for (let i = 1; i <= portCount; i++) {
      const p = _switchPortEdits[i] || { label: 'Fa0/' + i };
      if (p.device_mac || p.label !== 'Fa0/' + i || p.vlan || p.speed || p.duplex || p.notes) {
        ports[String(i)] = {
          label: p.label || ('Fa0/' + i),
          device_mac: p.device_mac || '',
          vlan: p.vlan || '',
          speed: p.speed || '',
          duplex: p.duplex || '',
          notes: p.notes || '',
        };
      }
    }
    const r = await api('/netscope/api/switches/' + _currentSwitchMac, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ port_count: portCount, ports })
    });
    if (r.error) { toast(r.error, 'err'); return; }
    toast(t('Portas salvas'), 'ok');
    await loadSwitches();
    await loadDevices();
    selectSwitchTab(_currentSwitchMac);
  };
}

function openSwitchPortModal(mac) {
  $('btn-switches').click();
  setTimeout(() => selectSwitchTab(mac), 200);
}

async function loadSnapshots() {
  const r = await api('/netscope/api/snapshots');
  S.snapshots = r.snapshots || [];
  return S.snapshots;
}

$('btn-snapshots').onclick = async () => {
  await loadSnapshots();
  openModal('modal-snapshots');
  renderSnapshotList();

  setTimeout(() => { const el = $('snap-label'); if (el) el.focus(); }, 150);
};

$('snap-create-btn').onclick = async () => {
  const label = $('snap-label').value.trim();
  const notes = $('snap-notes').value.trim();
  if (!label) { toast(t('Digite um rótulo'), 'err'); return; }
  const r = await api('/netscope/api/snapshots', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ label, notes }) });
  if (r.error) { toast(r.error, 'err'); return; }
  toast(t('Snapshot criado: {l}', {l: label}), 'ok');
  $('snap-label').value = ''; $('snap-notes').value = '';
  await loadSnapshots();
  renderSnapshotList();
};

function renderSnapshotList() {
  const el = $('snapshot-list');
  const empty = $('snapshot-empty');
  if (!S.snapshots.length) { el.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  el.innerHTML = S.snapshots.map(s => {
    const isViewing = S.snapshotView === s.id;
    return '<div class="snap-item ' + (isViewing ? 'viewing' : '') + '">' +
      '<div class="snap-info">' +
        '<div class="snap-label">' + esc(s.label) + (s.auto ? ' <span class="snap-auto">auto</span>' : '') + '</div>' +
        '<div class="snap-meta">' + esc(fmtDate(s.created_at)) + ' · ' + s.device_count + ' ' + t('disp.') + ' · ' + s.link_count + ' links</div>' +
        (s.notes ? '<div class="snap-notes">' + esc(s.notes) + '</div>' : '') +
      '</div>' +
      '<div class="snap-actions">' +
        '<button class="btn btn-sm btn-outline" data-act="view" data-id="' + esc(s.id) + '"><i class="fas fa-eye"></i> ' + t('Ver') + '</button>' +
        '<button class="btn btn-sm btn-outline" data-act="compare" data-id="' + esc(s.id) + '"><i class="fas fa-exchange-alt"></i> ' + t('Comparar') + '</button>' +
        '<button class="btn btn-sm btn-danger" data-act="delete" data-id="' + esc(s.id) + '"><i class="fas fa-trash"></i></button>' +
      '</div>' +
    '</div>';
  }).join('');
  el.querySelectorAll('.snap-actions button').forEach(b => {
    b.onclick = async () => {
      const act = b.dataset.act;
      const id = b.dataset.id;
      if (act === 'view') {
        viewSnapshot(id);
      } else if (act === 'compare') {

        const cur = await api('/netscope/api/snapshots', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ label: '__temp_compare__', notes: '' }) });
        if (cur.error) { toast(cur.error, 'err'); return; }
        const cmp = await api('/netscope/api/snapshots/' + id + '/compare/' + cur.id);

        await api('/netscope/api/snapshots/' + cur.id, { method: 'DELETE' });
        if (cmp.error) { toast(cmp.error, 'err'); return; }
        showCompareResult(cmp);
      } else if (act === 'delete') {
        if (!confirm(t('Excluir snapshot?'))) return;
        const r = await api('/netscope/api/snapshots/' + id, { method: 'DELETE' });
        if (r.error) { toast(r.error, 'err'); return; }
        toast(t('Snapshot excluído'), 'ok');
        await loadSnapshots();
        renderSnapshotList();
      }
    };
  });
}

async function viewSnapshot(id) {
  S.snapshotView = id;
  closeModal('modal-snapshots');
  $('snapshot-banner').classList.remove('hidden');
  const snap = S.snapshots.find(s => s.id === id);
  $('snapshot-text').textContent = t('Visualizando: {l}', {l: snap ? snap.label : id});
  await loadDevices();

  setTimeout(() => fitView(true), 600);
  toast(t('Modo snapshot — voltar ao atual para editar'), 'ok');
}

$('snapshot-exit').onclick = async () => {
  S.snapshotView = null;
  S.snapshotDevices = null;
  $('snapshot-banner').classList.add('hidden');
  await loadDevices();
};

function showCompareResult(cmp) {
  let html = '<div class="compare-result">';
  html += '<div class="compare-header">' + t('Comparação: {a} ↔ atual', {a: cmp.a.label}) + '</div>';
  html += '<div class="compare-section added"><strong>' + t('Adicionados ({n})', {n: cmp.added.length}) + '</strong>';
  if (cmp.added.length) {
    html += '<ul>' + cmp.added.map(d => '<li>' + esc(d.hostname || d.ip) + ' · ' + esc(d.ip) + ' · ' + esc(d.mac) + '</li>').join('') + '</ul>';
  } else { html += '<p class="muted">' + t('nenhum') + '</p>'; }
  html += '</div>';
  html += '<div class="compare-section removed"><strong>' + t('Removidos ({n})', {n: cmp.removed.length}) + '</strong>';
  if (cmp.removed.length) {
    html += '<ul>' + cmp.removed.map(d => '<li>' + esc(d.hostname || d.ip) + ' · ' + esc(d.ip) + ' · ' + esc(d.mac) + '</li>').join('') + '</ul>';
  } else { html += '<p class="muted">' + t('nenhum') + '</p>'; }
  html += '</div>';
  html += '<div class="compare-section changed"><strong>' + t('Alterados ({n})', {n: cmp.changed.length}) + '</strong>';
  if (cmp.changed.length) {
    html += '<ul>' + cmp.changed.map(d => {
      const changes = Object.keys(d.diffs).map(k => k + ': ' + (d.diffs[k].old || '∅') + ' → ' + (d.diffs[k].new || '∅')).join('; ');
      return '<li>' + esc(d.hostname || d.ip) + ' · ' + esc(d.ip) + ' — ' + esc(changes) + '</li>';
    }).join('') + '</ul>';
  } else { html += '<p class="muted">' + t('nenhum') + '</p>'; }
  html += '</div></div>';
  $('json-out').textContent = '';
  $('json-out').innerHTML = html;
  openModal('modal-json');
}

$('btn-assets').onclick = async () => {
  openModal('modal-assets');
  renderAssetTable();
};

$('asset-search').oninput = e => { S.assetFilter = e.target.value.trim().toLowerCase(); renderAssetTable(); };

document.querySelector('#asset-table thead').addEventListener('click', e => {
  const th = e.target.closest('th.sortable');
  if (!th) return;
  if (S.assetSort.key === th.dataset.key) S.assetSort.dir *= -1;
  else { S.assetSort.key = th.dataset.key; S.assetSort.dir = 1; }
  renderAssetTable();
});

function _ipCmp(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10));
  const pb = String(b).split('.').map(n => parseInt(n, 10));
  if (pa.length === 4 && pb.length === 4 && pa.every(n => !isNaN(n)) && pb.every(n => !isNaN(n))) {
    for (let i = 0; i < 4; i++) { if (pa[i] !== pb[i]) return pa[i] - pb[i]; }
    return 0;
  }
  return String(a).localeCompare(String(b));
}

const ASORT_GET = {
  hostname: d => (d.hostname || d.name || '').toLowerCase(),
  ip: d => d.ip || '',
  mac: d => d.mac || '',
  type: d => t(TYPE_LABELS[d.type] || d.type || ''),
  vendor: d => (d.vendor || '').toLowerCase(),
  model: d => (d.model || '').toLowerCase(),
  user: d => (d.user || '').toLowerCase(),
  department: d => (d.department || '').toLowerCase(),
  location: d => (d.location || '').toLowerCase(),
  switch: d => (d.switch_port && d.switch_port.switch_mac ? (S.devices.find(x => x.id === d.switch_port.switch_mac)?.name || '') : '').toLowerCase(),
  port: d => (d.switch_port && d.switch_port.port != null ? d.switch_port.port : ''),
  asset_tag: d => (d.asset_tag || '').toLowerCase(),
  seal_number: d => (d.seal_number || '').toLowerCase(),

  agent: d => (d.has_agent ? 0 : (d.agent_exempt ? 2 : 1)),
  status: d => d.status || ''
};

function renderAssetTable() {
  const tbody = $('asset-tbody');
  let devs = S.devices.slice();
  if (S.assetFilter) {
    devs = devs.filter(d => {
      const blob = [d.ip, d.mac, d.name, d.hostname, d.user, d.department, d.location, d.asset_tag, d.vendor, d.model, d.type, d.seal_number, d.serial_number, d.agent_id, d.has_agent ? t('sim agente com') : t('nao sem agente')]
        .filter(Boolean).join(' ').toLowerCase();
      return blob.includes(S.assetFilter);
    });
  }

  if (S.assetSort.key && ASORT_GET[S.assetSort.key]) {
    const key = S.assetSort.key, dir = S.assetSort.dir, g = ASORT_GET[key];
    const isNum = (key === 'port' || key === 'agent');
    const isIp = (key === 'ip');
    const rows = devs.map(d => ({ d, v: g(d) }));
    rows.sort((a, b) => {
      const va = a.v, vb = b.v;
      const ea = (va === '' || va == null), eb = (vb === '' || vb == null);
      if (ea && eb) return 0;
      if (ea) return 1;
      if (eb) return -1;
      let r;
      if (isNum) r = (Number(va) || 0) - (Number(vb) || 0);
      else if (isIp) r = _ipCmp(va, vb);
      else r = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: 'base' });
      return r * dir;
    });
    devs = rows.map(r => r.d);
  }

  const live = new Set(S.devices.map(d => d.id));
  S.assetSel.forEach(k => { if (!live.has(k)) S.assetSel.delete(k); });
  if (!devs.length) {
    tbody.innerHTML = '<tr><td colspan="17" style="text-align:center;padding:1.5rem;color:var(--gray)">' + t('Nenhum ativo') + '</td></tr>';
    _updateBulkBar();
    return;
  }
  tbody.innerHTML = devs.map(d => {
    const sp = d.switch_port || {};
    const sw = sp.switch_mac ? (S.devices.find(x => x.id === sp.switch_mac)?.name || '') : '';
    const statusCls = d.status === 'online' ? 'asset-on' : 'asset-off';

    const DUP_R = { ip: 'mesmo IP', hostname: 'mesmo hostname', 'mac-prefix': 'mesmo fabricante (prefixo de MAC)' };
    const dupReasons = d.dup ? String(d.dup).split(',').filter(Boolean) : [];
    const dupHtml = dupReasons.length
      ? '<span class="dup-tag" title="' + esc(t('Duplicado') + ' — ' + dupReasons.map(r => t(DUP_R[r] || r)).join(', ')) + '"><i class="fas fa-clone"></i> ' + esc(t('Duplicado')) + '</span> '
      : '';
    const checked = S.assetSel.has(d.id) ? ' checked' : '';
    return '<tr' + (S.assetSel.has(d.id) ? ' class="row-selected"' : '') + '>' +
      '<td class="sel-col"><input type="checkbox" class="asset-sel-cb" data-id="' + esc(d.id) + '"' + checked + '></td>' +
      '<td>' + dupHtml + esc(d.hostname || d.name) + '</td>' +
      '<td class="mono">' + esc(d.ip) + '</td>' +

      '<td class="mono">' + esc(d.mac || '—') + '</td>' +

      '<td><span class="type-badge type-' + esc(d.type) + '">' + esc(t(TYPE_LABELS[d.type] || d.type)) + '</span></td>' +
      '<td>' + esc(d.vendor || '-') + '</td>' +
      '<td>' + esc(d.model || '-') + '</td>' +
      '<td>' + esc(d.user || '-') + '</td>' +
      '<td>' + esc(d.department || '-') + '</td>' +
      '<td>' + esc(d.location || '-') + '</td>' +
      '<td>' + esc(sw || '-') + '</td>' +
      '<td class="mono">' + (sp.port ? esc(sp.label || ('P' + sp.port)) : '-') + '</td>' +
      '<td class="mono">' + esc(d.asset_tag || '-') + '</td>' +
      '<td class="mono">' + esc(d.seal_number || '-') + '</td>' +
      '<td><span class="agent-pill ' + (d.has_agent ? 'yes' : (d.agent_exempt ? 'na' : 'no')) + '" title="' + (d.has_agent ? ('ID ' + esc(d.agent_id || '?') + ' · ' + esc(d.agent_status || '?')) : (d.agent_exempt ? t('Sem possibilidade de agente — não conta como sem agente') : t('Instalar agente Wazuh'))) + '">' + (d.has_agent ? t('Sim') : (d.agent_exempt ? 'N/A' : t('Não'))) + '</span></td>' +
      '<td class="' + statusCls + '">' + esc(d.status) + '</td>' +
      '<td><button class="btn btn-sm btn-outline" data-id="' + esc(d.id) + '"><i class="fas fa-pen"></i></button></td>' +
    '</tr>';
  }).join('');

  tbody.querySelectorAll('button[data-id]').forEach(b => {
    b.onclick = () => {
      const n = S.devices.find(d => d.id === b.dataset.id);
      if (n) { closeModal('modal-assets'); openEditModal(n); }
    };
  });

  tbody.querySelectorAll('.asset-sel-cb').forEach(cb => {
    cb.onchange = () => {
      if (cb.checked) S.assetSel.add(cb.dataset.id);
      else S.assetSel.delete(cb.dataset.id);
      const tr = cb.closest('tr');
      if (tr) tr.classList.toggle('row-selected', cb.checked);
      _syncSelAll(devs);
      _updateBulkBar();
    };
  });

  document.querySelectorAll('#asset-table thead th').forEach(th => {
    if (!th.dataset.key) return;
    th.classList.toggle('sort-asc', S.assetSort.key === th.dataset.key && S.assetSort.dir === 1);
    th.classList.toggle('sort-desc', S.assetSort.key === th.dataset.key && S.assetSort.dir === -1);
  });
  _syncSelAll(devs);
  _updateBulkBar();
}

function _syncSelAll(visibleDevs) {
  const all = $('asset-sel-all');
  if (!all) return;
  const vis = visibleDevs.filter(d => !d.deleted);
  const selVis = vis.filter(d => S.assetSel.has(d.id)).length;
  all.checked = vis.length > 0 && selVis === vis.length;
  all.indeterminate = selVis > 0 && selVis < vis.length;
}

function _updateBulkBar() {
  const bar = $('asset-bulkbar');
  if (!bar) return;
  const n = S.assetSel.size;
  bar.style.display = n ? 'flex' : 'none';
  const cnt = $('asset-bulk-count');
  if (cnt) cnt.textContent = n ? t('{n} selecionado(s)', {n: n}) : '';
}

$('asset-sel-all').onchange = () => {
  const all = $('asset-sel-all');
  const devs = S.devices.filter(d => !S.assetFilter
    || [d.ip, d.mac, d.name, d.hostname, d.user, d.vendor, d.model].filter(Boolean).join(' ').toLowerCase().includes(S.assetFilter));
  devs.forEach(d => {
    if (all.checked) S.assetSel.add(d.id);
    else S.assetSel.delete(d.id);
  });
  renderAssetTable();
};

$('asset-bulk-delete').onclick = async () => {
  const uids = Array.from(S.assetSel);
  if (!uids.length) return;
  const n = uids.length;
  if (!confirm(t('Excluir {n} ativo(s)? Eles vão para a lixeira e podem ser restaurados.', {n: n}))) return;
  const btn = $('asset-bulk-delete');
  btn.disabled = true;
  const r = await api('/netscope/api/devices/bulk-delete', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ uids })
  });
  btn.disabled = false;
  if (r.error) { toast(r.error, 'err'); return; }
  S.assetSel.clear();
  toast(t('{n} ativo(s) movido(s) para a lixeira', {n: r.deleted || 0}), 'ok');
  _updateBulkBar();
  await loadDevices();
  renderAssetTable();
};

async function _gwDownload(url, fallbackName) {
  try {
    const r = await fetch(url);
    if (!r.ok) { toast(t('Falha na exportação: {e}', {e: r.status}), 'err'); return; }
    const blob = await r.blob();
    const cd = r.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename\*?=(?:UTF-8''|"?)([^";]+)/i);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (m && m[1]) ? decodeURIComponent(m[1]) : fallbackName;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  } catch (e) {
    toast(t('Falha na exportação: {e}', {e: e.message}), 'err');
  }
}

$('assets-export-csv').onclick = () => {
  _gwDownload('/netscope/api/export/csv', 'netscope_assets.csv');
};

$('btn-trash').onclick = async () => {
  openModal('modal-trash');
  const d = await api('/netscope/api/trash'); const list = d.devices || [];
  const el = $('trash-list'); const empty = $('trash-empty');
  if (!list.length) { el.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  el.innerHTML = list.map(dev => {

    const dk = dev.uid || dev.mac;

    let mergeHtml = '';
    if (dev.merged_into) {
      const R = { ip: 'mesmo IP', 'mac-prefix': 'mesmo fabricante (prefixo de MAC)', hostname: 'mesmo hostname' };
      mergeHtml = '<div class="merge-tag"><i class="fas fa-code-merge"></i> '
        + esc(t('Mesclado automaticamente') + (R[dev.merge_reason] ? ' (' + t(R[dev.merge_reason]) + ')' : '')
        + (dev.merged_into_name ? ' ' + t('em') + ' ' + dev.merged_into_name : '')) + '</div>';
    }
    return '<div class="del-item"><div class="del-info"><div class="del-name">' + esc(dev.hostname || dev.ip) + '</div><div class="del-detail">' + esc(dev.ip) + ' · ' + esc(dev.mac || '—') + ' · ' + esc(dev.deleted_at_fmt || '') + '</div>' + mergeHtml + '</div><div class="del-actions"><button class="btn-restore" data-id="' + esc(dk) + '">' + t('Restaurar') + '</button><button class="btn-perma" data-id="' + esc(dk) + '">Del</button></div></div>';
  }).join('');
  el.querySelectorAll('.btn-restore').forEach(b => {
    b.onclick = async () => {
      const r = await api('/netscope/api/trash/' + b.dataset.id + '/restore', { method: 'POST' });
      if (r.error) { toast(r.error, 'err'); return; }
      toast(t('Restaurado'), 'ok'); b.closest('.del-item').remove();
      if (!el.children.length) empty.classList.remove('hidden'); loadDevices();
    };
  });
  el.querySelectorAll('.btn-perma').forEach(b => {
    b.onclick = async () => {
      if (!confirm(t('Excluir permanentemente?'))) return;
      const r = await api('/netscope/api/trash/' + b.dataset.id, { method: 'DELETE' });
      if (r.error) { toast(r.error, 'err'); return; }
      toast(t('Excluído'), 'err'); b.closest('.del-item').remove();
      if (!el.children.length) empty.classList.remove('hidden');
    };
  });
};

$('btn-json').onclick = () => {
  const safe = JSON.parse(JSON.stringify(S.devices));
  safe.forEach(n => { delete n.x; delete n.y; delete n.vx; delete n.vy; delete n.fx; delete n.fy; });
  $('json-out').textContent = JSON.stringify(safe, null, 2);
  openModal('modal-json');
};

$('btn-export-png').onclick = () => {

  const svgEl = $('graph');
  const g = gMain.node();
  const bbox = g.getBBox();
  if (bbox.width === 0 || bbox.height === 0) { toast(t('Nada para exportar'), 'warn'); return; }
  const pad = 60;
  const x = bbox.x - pad, y = bbox.y - pad;
  const w = bbox.width + pad * 2, h = bbox.height + pad * 2;
  const zt = d3.zoomTransform(svgEl);
  const scale = 2;
  const clone = svgEl.cloneNode(true);
  clone.setAttribute('width', w * scale);
  clone.setAttribute('height', h * scale);
  clone.setAttribute('viewBox', x + ' ' + y + ' ' + w + ' ' + h);

  const cloneMain = clone.querySelector('g');
  if (cloneMain) cloneMain.removeAttribute('transform');

  const isDark = document.documentElement.classList.contains('dark-mode');
  const bg = isDark ? '#0f172a' : '#dfe9f9';

  const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bgRect.setAttribute('x', x); bgRect.setAttribute('y', y);
  bgRect.setAttribute('width', w); bgRect.setAttribute('height', h);
  bgRect.setAttribute('fill', bg);
  clone.insertBefore(bgRect, clone.firstChild);

  const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
  const css = `
    .link { stroke: ${isDark ? '#cbd5e1' : '#64748b'}; stroke-width: 1.5; fill: none; }
    .link.inferred { stroke: ${isDark ? '#94a3b8' : '#94a3b8'}; stroke-dasharray: 6 4; opacity: .5; }
    .ring { fill: none; stroke-width: 2; opacity: .8; }
    .ring.unknown { stroke: ${isDark ? '#f87171' : '#ef4444'}; stroke-dasharray: 3 2; }
    .ring.known { stroke: ${isDark ? '#34d399' : '#10b981'}; }
    .nlabel { font-size: 11px; font-weight: 600; fill: ${isDark ? '#f8fafc' : '#1e293b'}; font-family: Inter, sans-serif; }
    .nsub { font-size: 10px; fill: ${isDark ? '#94a3b8' : '#64748b'}; font-family: monospace; }
    .conf { font-size: 9px; fill: ${isDark ? '#94a3b8' : '#64748b'}; font-family: monospace; }
    .port-label-bg { fill: ${isDark ? '#334155' : '#fff'}; stroke: ${isDark ? '#475569' : '#cbd5e1'}; stroke-width: 1; }
    .port-label-text { font-size: 9px; fill: ${isDark ? '#fbbf24' : '#d97706'}; font-family: monospace; font-weight: 600; }
    .agent-badge { stroke: #fff; stroke-width: 1.5; }
  `;
  styleEl.textContent = css;
  clone.insertBefore(styleEl, clone.firstChild);
  const xml = new XMLSerializer().serializeToString(clone);
  const svgBlob = new Blob([xml], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(svgBlob);
  const img = new Image();
  img.onload = () => {
    const canvasEl = document.createElement('canvas');
    canvasEl.width = w * scale; canvasEl.height = h * scale;
    const ctx = canvasEl.getContext('2d');
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);
    canvasEl.toBlob(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'netscope_topology_' + new Date().toISOString().slice(0,19).replace(/[:T]/g,'-') + '.png';
      a.click();
      URL.revokeObjectURL(a.href);
      toast(t('PNG exportado'), 'ok');
    }, 'image/png');
  };
  img.onerror = () => { toast(t('Falha ao gerar PNG'), 'err'); URL.revokeObjectURL(url); };
  img.src = url;
};

$('btn-export-csv').onclick = () => {
  toast(t('Exportando CSV...'), 'ok');
  _gwDownload('/netscope/api/export/csv', 'netscope_assets.csv');
};

function openModal(id) {
  const m = $(id);
  clearTimeout(m._fadeT);
  m.classList.add('active'); m.style.display = 'flex';
  requestAnimationFrame(() => m.style.opacity = '1');
}
function closeModal(id) {
  const m = $(id);
  m.style.opacity = '0';
  clearTimeout(m._fadeT);
  m._fadeT = setTimeout(() => { m.classList.remove('active'); m.style.display = 'none'; }, 300);
}
document.querySelectorAll('.modal .close').forEach(btn => btn.addEventListener('click', () => closeModal(btn.dataset.modal)));
document.querySelectorAll('.modal').forEach(m => m.addEventListener('click', e => { if (e.target === m) closeModal(m.id); }));

(function initSidebarResize() {
  const sb = $('sidebar');
  const handle = $('sb-resize-handle');
  let dragging = false, startX = 0, startW = 0;
  const saved = localStorage.getItem('netscope-sb-width');
  if (saved) sb.style.setProperty('--sb-width', saved + 'px');
  handle.addEventListener('mousedown', e => {
    e.preventDefault(); dragging = true; startX = e.clientX;
    startW = sb.offsetWidth; handle.classList.add('active');
    document.body.style.cursor = 'col-resize'; document.body.style.userSelect = 'none';
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const newW = Math.max(200, Math.min(500, startW + (e.clientX - startX)));
    sb.style.setProperty('--sb-width', newW + 'px');
  });
  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false; handle.classList.remove('active');
    document.body.style.cursor = ''; document.body.style.userSelect = '';
    localStorage.setItem('netscope-sb-width', sb.offsetWidth);
    resize();
  });
})();

const _sbTransEnd = () => resize();

function updateSidebarToggle() {
  const sb = $('sidebar');
  const icon = document.getElementById('toggle-sb-icon');
  if (!sb || !icon) return;
  const collapsed = sb.classList.contains('collapsed');

  icon.className = collapsed ? 'fas fa-chevron-right' : 'fas fa-chevron-left';
  $('btn-toggle-sb').title = collapsed ? t('Mostrar barra lateral') : t('Ocultar barra lateral');
  $('btn-toggle-sb').setAttribute('aria-label', $('btn-toggle-sb').title);
}

$('btn-toggle-sb').onclick = () => {
  const sb = $('sidebar');
  sb.classList.toggle('collapsed');
  sb.addEventListener('transitionend', _sbTransEnd, { once: true });

  setTimeout(resize, 320);
  updateSidebarToggle();
};
updateSidebarToggle();

$('inp-search').oninput = e => { S.search = e.target.value.trim(); renderList(); };

$('filter-select').onchange = e => {
  S.filter = e.target.value;
  renderList();
  updateClasses();
};

(function initFilterFromUrl() {
  const q = new URLSearchParams(location.search).get('filter');
  const valid = ['all', 'online', 'offline', 'new', 'undoc', 'agent', 'noagent'];
  if (q && valid.includes(q)) {
    S.filter = q;
    const sel = $('filter-select');
    if (sel) sel.value = q;
  }
})();

document.querySelectorAll('.layout-switcher button').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.layout-switcher button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    S.layoutMode = b.dataset.layout;
    applyLayoutMode();
    toast('Layout: ' + S.layoutMode, 'ok');

    setTimeout(() => fitView(true), 650);
  };
});

let _scanPoll = null;
function pollScanStatus() {

  let polls = 0;
  _scanPoll = setInterval(async () => {
    if (++polls > 600) {
      clearInterval(_scanPoll); _scanPoll = null;
      S.scanning = false; setBtnLoading($('btn-scan'), false);
      return;
    }
    const r = await api('/netscope/api/scan/status');
    if (r.error) { clearInterval(_scanPoll); _scanPoll = null; S.scanning = false; setBtnLoading($('btn-scan'), false); toast(t('Scan falhou: {e}', {e: r.error}), 'err'); return; }
    if (r.status === 'scanning') return;
    clearInterval(_scanPoll); _scanPoll = null; S.scanning = false;
    setBtnLoading($('btn-scan'), false);

    const arpN = r.arp_found || 0;
    if (r.new > 0) {
      toast(t('Scan: {total} dispositivos, {n} novos', {total: r.total, n: r.new}) +
        (arpN > 0 ? t(' ({a} via ARP)', {a: arpN}) : ''), 'ok');
    } else {
      toast(t('Scan: {total} dispositivos, nenhum novo', {total: r.total || 0}) +
        (arpN > 0 ? t(' ({a} via ARP)', {a: arpN}) : ''), 'warn');
    }
    loadDevices();
  }, 2000);
}

$('btn-scan').onclick = async () => {
  if (S.scanning) return;

  if (!S._nets || S._nets.length === 0) { openCidrModal(); return; }
  const btn = $('btn-scan'); setBtnLoading(btn, true); S.scanning = true;
  const r = await api('/netscope/api/scan', { method: 'POST' });
  if (r.error) {
    S.scanning = false; setBtnLoading(btn, false);

    if (r.reason === 'already_running') {
      toast(t('Já existe uma varredura em andamento — aguardando a conclusão…'), 'warn');
      pollScanStatus();
      return;
    }
    toast(t('Scan falhou: {e}', {e: r.error}), 'err'); return;
  }
  toast(t('Scan iniciado em {n} rede(s)...', {n: r.subnets}), 'ok');
  pollScanStatus();
};

$('btn-infer').onclick = async () => {
  const btn = $('btn-infer'); setBtnLoading(btn, true);
  const r = await api('/netscope/api/infer', { method: 'POST' }); setBtnLoading(btn, false);
  if (r.error) { toast(t('Falha: {e}', {e: r.error}), 'err'); return; }
  toast(r.changed ? t('{n} conexões inferidas', {n: r.changed}) : t('Nada alterado'), r.changed ? 'ok' : 'warn'); loadDevices();
};

$('btn-subnet-add').onclick = async () => {
  const inpSubnet = $('inp-subnet'); const inpGw = $('inp-gateway');
  let subnet = inpSubnet.value.trim();
  if (!subnet) { toast(t('Digite a sub-rede (ex: 172.16.0)'), 'err'); return; }
  if (subnet.includes('/')) {
    const m = subnet.match(/^(\d{1,3}(?:\.\d{1,3}){2,3})\/(\d{1,2})$/);
    if (!m || m[2] !== '24') {
      toast(t('Somente redes /24 são suportadas — ex: 192.168.0.0/24. Para redes maiores, adicione cada /24.'), 'err');
      return;
    }
    subnet = m[1].replace(/\.0$/, '');
  }
  let gateway = inpGw.value.trim();
  if (!gateway) gateway = subnet + '.1';
  const r = await api('/netscope/api/subnets', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ subnet, gateway }) });
  if (r.error) { toast(r.error, 'err'); return; }
  inpSubnet.value = ''; inpGw.value = '';
  await loadConfig(); loadSubnets(); toast(t('Rede {s}.0/24 (GW: {g})', {s: subnet, g: gateway}), 'ok');
};
$('inp-subnet').addEventListener('keydown', e => { if (e.key === 'Enter') $('inp-gateway').focus(); });
$('inp-gateway').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-subnet-add').click(); });

let _editingSubnet = null;

function openCidrModal(net = null) {
  const fb = $('cidr-feedback');
  fb.className = 'cidr-feedback';
  fb.textContent = '';
  const title = $('cidr-modal-title');
  const btnAdd = $('cidr-btn-add');
  const btnSkip = $('cidr-btn-skip');
  if (net) {
    _editingSubnet = net.subnet;
    if (title) title.textContent = t('Editar Rede de Varredura (CIDR)');
    if (btnAdd) btnAdd.innerHTML = '<i class="fas fa-save"></i> ' + t('Salvar Rede');
    if (btnSkip) btnSkip.textContent = t('Cancelar');
    $('cidr-input').value = net.subnet + '.0/24';
    $('cidr-gateway').value = net.gateway || '';
  } else {
    _editingSubnet = null;
    if (title) title.textContent = t('Configurar Rede de Varredura (CIDR)');
    if (btnAdd) btnAdd.innerHTML = '<i class="fas fa-plus"></i> ' + t('Adicionar Rede');
    if (btnSkip) btnSkip.textContent = t('Agora não');
    $('cidr-input').value = '';
    $('cidr-gateway').value = '';
  }
  openModal('modal-cidr');
  setTimeout(() => $('cidr-input').focus(), 120);
}

function validateCidr(raw) {
  const v = (raw || '').trim();
  if (!v) return { err: t('CIDR inválido — use o formato 192.168.1.0/24') };

  if (v.includes('/')) {
    const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!m) return { err: t('CIDR inválido — use o formato 192.168.1.0/24') };
    const oct = m.slice(1, 5).map(Number);
    if (oct.some(n => n > 255)) return { err: t('CIDR inválido — use o formato 192.168.1.0/24') };
    if (Number(m[5]) !== 24) return { err: t('Somente redes /24 são suportadas na varredura') };
    return { prefix: `${m[1]}.${m[2]}.${m[3]}` };
  }

  const p = v.split('.');
  if (p.length === 3 && p.every(x => x !== '' && Number(x) <= 255)) return { prefix: v };

  if (p.length === 4 && p.every(x => x !== '' && Number(x) <= 255)) return { prefix: p.slice(0, 3).join('.') };
  return { err: t('CIDR inválido — use o formato 192.168.1.0/24') };
}

function cidrFeedback(cls, msg) {
  const fb = $('cidr-feedback');
  fb.className = 'cidr-feedback ' + cls;
  fb.innerHTML = (cls === 'ok' ? '<i class="fas fa-circle-check"></i> ' : '<i class="fas fa-circle-xmark"></i> ') + esc(msg);
}

async function addCidrNetwork() {
  const raw = $('cidr-input').value.trim();
  const gw = $('cidr-gateway').value.trim();
  const check = validateCidr(raw);
  if (check.err) { cidrFeedback('err', check.err); $('cidr-input').focus(); return; }

  if (_editingSubnet) {
    const r = await api('/netscope/api/subnets', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ original: _editingSubnet, subnet: raw, gateway: gw })
    });
    if (r.error) {
      cidrFeedback('err', r.error);
      $('cidr-input').focus();
      return;
    }
    _editingSubnet = null;
    closeModal('modal-cidr');
    toast(t('Rede atualizada: {s} (GW: {g})', { s: r.subnet + '.0/24', g: r.gateway }), 'ok');
    await loadConfig();
    await loadSubnets();
    return;
  }

  const r = await api('/netscope/api/subnets', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subnet: raw, gateway: gw })
  });
  if (r.error) {
    cidrFeedback('err', r.error);
    $('cidr-input').focus();
    return;
  }

  cidrFeedback('ok', t('Rede adicionada: {s} (GW: {g})', { s: r.subnet + '.0/24', g: r.gateway }));
  $('cidr-input').value = '';
  $('cidr-gateway').value = '';
  await loadConfig();
  await loadSubnets();
  $('cidr-input').focus();
}

$('cidr-btn-add').onclick = addCidrNetwork;

$('cidr-btn-skip').onclick = () => { _editingSubnet = null; closeModal('modal-cidr'); };

$('cidr-input').addEventListener('keydown', e => { if (e.key === 'Enter') addCidrNetwork(); });
$('cidr-gateway').addEventListener('keydown', e => { if (e.key === 'Enter') addCidrNetwork(); });

$('cidr-input').addEventListener('input', () => {
  const fb = $('cidr-feedback');
  if (fb.classList.contains('err')) { fb.className = 'cidr-feedback'; fb.textContent = ''; }
});

$('z-in').onclick = () => svg.transition().duration(200).call(zoom.scaleBy, 1.4);
$('z-out').onclick = () => svg.transition().duration(200).call(zoom.scaleBy, 0.7);

function fitView(animate = true) {
  if (!S.devices.length) return;
  let x0=Infinity,y0=Infinity,x1=-Infinity,y1=-Infinity;
  S.devices.forEach(n => { if(n.x!=null){x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y);} });
  if (x0 === Infinity) return;
  const bw=x1-x0+120,bh=y1-y0+120;
  const s=Math.min(canvas.clientWidth/bw,canvas.clientHeight/bh,2);
  const cx=(x0+x1)/2,cy=(y0+y1)/2;
  const transform = d3.zoomIdentity.translate(canvas.clientWidth/2-cx*s,canvas.clientHeight/2-cy*s).scale(s);
  if (animate) {
    svg.transition().duration(500).call(zoom.transform, transform);
  } else {
    svg.call(zoom.transform, transform);
  }
}

$('z-fit').onclick = () => fitView(true);

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); $('inp-search').focus(); }
  if (e.key === 'Escape') {
    hideCtxMenu();
    if (S.ctrlLink) { cancelCtrlLink(); return; }
    ['modal-edit','modal-add','modal-trash','modal-json','modal-switches','modal-snapshots','modal-assets','modal-agents','modal-cidr','modal-portscan'].forEach(id => { if ($(id).classList.contains('active')) { closeModal(id); _editingSubnet = null; return; } });
    hidePopover();
  }
});

document.addEventListener('click', e => {
  if (S.ctrlLink && !e.target.closest('.node') && !e.ctrlKey && !e.metaKey) {
    cancelCtrlLink();
  }
  if (S.popover && !popoverEl.contains(e.target) && !e.target.closest('.node') && !e.target.closest('.dev-card')) {
    hidePopover(); S.selected = null; updateClasses(); renderList();
  }
});

async function syncWazuh() {
  const btn = $('btn-wazuh-sync');
  setBtnLoading(btn, true);
  try {
    const r = await api('/netscope/api/wazuh_sync', { method: 'POST' });
    if (r.error || r.ok === false) { toast(t('Falha: {e}', {e: r.error || 'erro'}), 'err'); return; }
    toast(t('Wazuh: {m} com agente, {c} novos, {w} sem agente', {m: r.matched || 0, c: r.created || 0, w: r.without_agent || 0}), 'ok');
    await loadDevices();
    await loadSubnets();
  } finally {
    setBtnLoading(btn, false);
  }
}

$('btn-wazuh-sync').onclick = syncWazuh;
if ($('agents-sync-btn')) $('agents-sync-btn').onclick = async () => { await syncWazuh(); renderAgentsModal(); };

let _agentsFilter = '';

$('btn-wazuh-agents').onclick = async () => renderAgentsModal();

if ($('agents-search')) $('agents-search').oninput = e => { _agentsFilter = e.target.value.trim().toLowerCase(); renderAgentsModal(true); };

async function renderAgentsModal(skipLoad) {
  openModal('modal-agents');
  const tbody = $('agent-tbody');

  const COLS = 9;
  tbody.innerHTML = '<tr><td colspan="' + COLS + '" style="text-align:center;padding:1.2rem;color:var(--gray)"><i class="fas fa-spinner fa-spin"></i></td></tr>';
  if (!skipLoad) {
    const r = await api('/netscope/api/wazuh_agents');
    if (r.error) { tbody.innerHTML = '<tr><td colspan="' + COLS + '" style="text-align:center;color:var(--danger)">' + t('Erro: {e}', {e: r.error}) + '</td></tr>'; return; }
    S._wazuhAgents = r.agents || [];
  }
  const agents = S._wazuhAgents || [];
  let list = agents;
  if (_agentsFilter) {
    list = agents.filter(a => [a.hostname, a.ip, a.agent_id, (a.groups || []).join(' ')]
      .filter(Boolean).join(' ').toLowerCase().includes(_agentsFilter));
  }
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="' + COLS + '" style="text-align:center;padding:1.5rem;color:var(--gray)">' + t('Nenhum agente Wazuh sincronizado') + '</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(a => {
    const st = a.status || 'unknown';

    const mUrl = (a.hostname && _HOST_RE.test(String(a.hostname)))
      ? '/machine/' + encodeURIComponent(a.hostname) : null;
    const ficha = mUrl
      ? '<a class="agent-ficha-btn" href="' + esc(mUrl) + '" title="' + t('Abrir a ficha completa da máquina no Inventory') + '"><i class="fas fa-id-card"></i> ' + t('Ficha da Máquina') + '</a>'
      : '<span style="color:var(--gray);opacity:.6">—</span>';
    return '<tr>' +
      '<td>' + esc(a.hostname || '-') + '</td>' +
      '<td class="mono">' + esc(a.agent_id || '-') + '</td>' +
      '<td class="mono">' + esc(a.ip || '-') + '</td>' +
      '<td class="mono">' + esc(a.mac || '-') + '</td>' +
      '<td><span class="agent-status-chip ' + esc(st) + '">' + esc(st) + '</span></td>' +
      '<td>' + esc((a.groups || []).join(', ') || '-') + '</td>' +
      '<td>' + (a.in_netscope ? '<span class="agent-pill yes">' + t('Sim') + '</span>' : '<span class="agent-pill no">' + t('Não') + '</span>') + '</td>' +
      '<td>' + esc(fmtDate(a.last_keepalive)) + '</td>' +
      '<td class="agents-col-actions">' + ficha + '</td>' +
    '</tr>';
  }).join('');
}

let _psTimer = null;
let _psNode = null;

function _psPhaseLabel(phase) {
  return phase === 'udp' ? 'UDP' : 'TCP';
}

function _psFmtDT(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const p = n => String(n).padStart(2, '0');
  return p(d.getDate()) + '/' + p(d.getMonth() + 1) + '/' + d.getFullYear() +
    ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

function _psPortName(p, proto) {
  return p.name || t('desconhecido');
}

function _psRenderResults(st) {
  const box = $('ps-results');
  const sum = $('ps-summary');
  const tcp = st.tcp || [];
  const udpOpen = st.udp_open || [];
  const udpOf = st.udp_open_filtered || [];
  const total = tcp.length + udpOpen.length + udpOf.length;

  sum.classList.remove('hidden');
  sum.innerHTML =
    '<span class="ps-chip ok"><i class="fas fa-plug"></i> TCP: <b>' + tcp.length + '</b> ' + t('abertas') + '</span>' +
    '<span class="ps-chip ok"><i class="fas fa-plug"></i> UDP: <b>' + (udpOpen.length + udpOf.length) + '</b> ' + t('abertas') + '</span>' +
    (st.udp_closed ? '<span class="ps-chip muted">' + st.udp_closed + ' ' + t('fechadas (UDP)') + '</span>' : '') +
    (st.duration_s != null ? '<span class="ps-chip muted"><i class="fas fa-clock"></i> ' + t('{s}s', {s: st.duration_s}) + '</span>' : '') +

    (st.scanned_at ? '<span class="ps-chip muted"><i class="fas fa-calendar-check"></i> ' + t('Última varredura: {d}', {d: _psFmtDT(st.scanned_at)}) + '</span>' : '');

  if (!total) {
    box.classList.remove('hidden');
    box.innerHTML = '<div class="ps-empty"><i class="fas fa-shield-halved"></i>' + t('Nenhuma porta aberta encontrada') + '</div>';
    return;
  }

  let html = '';
  if (tcp.length) {
    html += '<div class="ps-table-title">TCP</div><div class="ps-table-wrap"><table class="ps-table"><thead><tr>' +
      '<th>' + t('Porta') + '</th><th>' + t('Serviço') + '</th><th>Banner</th></tr></thead><tbody>' +
      tcp.map(p => '<tr><td class="mono">' + p.port + '</td><td>' + esc(_psPortName(p, 'tcp')) + '</td><td class="ps-banner">' + esc(p.banner || '—') + '</td></tr>').join('') +
      '</tbody></table></div>';
  }
  if (udpOpen.length || udpOf.length) {
    html += '<div class="ps-table-title">UDP</div><div class="ps-table-wrap"><table class="ps-table"><thead><tr>' +
      '<th>' + t('Porta') + '</th><th>' + t('Serviço') + '</th><th>' + t('Estado') + '</th></tr></thead><tbody>' +
      udpOpen.map(p => '<tr><td class="mono">' + p.port + '</td><td>' + esc(_psPortName(p, 'udp')) + '</td><td><span class="ps-state open">open</span></td></tr>').join('') +
      udpOf.map(p => '<tr><td class="mono">' + p.port + '</td><td>' + esc(_psPortName(p, 'udp')) + '</td><td><span class="ps-state filtered">open|filtered</span></td></tr>').join('') +
      '</tbody></table></div>';
  }
  box.classList.remove('hidden');
  box.innerHTML = html;
}

function _psRenderStatus(st) {
  if (st.status === 'running') {
    $('ps-progress-box').classList.remove('hidden');
    $('ps-summary').classList.add('hidden');
    $('ps-results').classList.add('hidden');
    $('ps-fill').style.width = (st.progress || 0) + '%';
    $('ps-phase').innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + _psPhaseLabel(st.phase) + ' · ' + t('Escaneando todas as portas de {ip}...', {ip: st.ip || ''});
    $('ps-meta').textContent = (st.progress || 0).toFixed ? (st.progress || 0).toFixed(1) + '%' : (st.progress || 0) + '%';
    $('ps-foot-note').textContent = '';

    $('ps-rescan').disabled = true;
    return;
  }
  $('ps-progress-box').classList.add('hidden');
  $('ps-rescan').disabled = false;
  if (st.status === 'error') {
    $('ps-foot-note').textContent = t('Falha: {e}', {e: st.error || ''});
    $('ps-summary').classList.remove('hidden');
    $('ps-summary').innerHTML = '<span class="ps-chip err"><i class="fas fa-triangle-exclamation"></i> ' + t('Falha: {e}', {e: st.error || ''}) + '</span>';
    return;
  }
  if (st.status === 'done') {
    _psRenderResults(st);
    $('ps-foot-note').textContent = t('Concluído em {s}s', {s: st.duration_s || 0});
  }
}

async function pollPortScan() {
  if (_psTimer) clearInterval(_psTimer);
  _psTimer = setInterval(async () => {
    if (!$('modal-portscan').classList.contains('active') || !_psNode) {
      clearInterval(_psTimer); _psTimer = null; return;
    }
    const st = await api('/netscope/api/portscan/status');
    if (st.error) return;
    const mine = (st.jobs || []).find(j => j.mac === _psNode.id);
    if (!mine) { clearInterval(_psTimer); _psTimer = null; return; }
    if (mine.status !== 'running' && _psTimer) {
      clearInterval(_psTimer); _psTimer = null;
      loadDevices();
    }
    _psRenderStatus(mine);
  }, 1000);
}

async function _psStartScan(node) {
  const r = await api('/netscope/api/devices/' + node.id + '/portscan', { method: 'POST' });
  if (r.error) {
    if (r.reason === 'limit') {
      toast(t('Limite de {n} varreduras simultâneas — aguarde a conclusão de uma.', {n: r.max_parallel || 3}), 'warn');
    } else {
      toast(r.error, r.same === true ? 'warn' : 'err');
    }
    return false;
  }
  toast(t('Varredura de portas iniciada'), 'ok');
  pollPortScan();
  return true;
}

async function openPortScanModal(node) {
  _psNode = node;
  $('ps-title').textContent = '— ' + (node.name || node.ip) + ' (' + node.ip + ')';
  $('ps-summary').classList.add('hidden');
  $('ps-results').classList.add('hidden');
  $('ps-foot-note').textContent = '';
  $('ps-progress-box').classList.remove('hidden');
  $('ps-fill').style.width = '0%';
  $('ps-phase').innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + t('Escaneando todas as portas de {ip}...', {ip: node.ip});
  $('ps-meta').textContent = '';
  $('ps-rescan').disabled = false;
  openModal('modal-portscan');

  const st = await api('/netscope/api/portscan/status');
  const mine = ((st && st.jobs) || []).find(j => j.mac === node.id);
  if (mine && mine.status === 'running') { _psRenderStatus(mine); pollPortScan(); return; }
  if (mine && (mine.status === 'done' || mine.status === 'error')) { _psRenderStatus(mine); return; }

  const last = node.port_scan;
  if (last && Array.isArray(last.tcp)) {
    $('ps-progress-box').classList.add('hidden');
    _psRenderResults(last);
    $('ps-foot-note').textContent = t('Última varredura: {d}', {d: _psFmtDT(last.scanned_at || last.started_at)});
    return;
  }
  await _psStartScan(node);
}

$('ps-rescan').onclick = async () => {
  if (!_psNode) return;

  await _psStartScan(_psNode);
};

loadConfig().then(() => loadSubnets()).then(list => {
  if (!list || list.length === 0) openCidrModal();
});
loadDevices().then(() => {

  if (!S._didInitialFit) {
    S._didInitialFit = true;
    setTimeout(() => fitView(true), 600);
  }
});
