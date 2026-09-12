
'use strict';

const PALETTE = [
    '#6366F1', '#8B5CF6', '#0EA5E9', '#EC4899', '#F43F5E',
    '#F97316', '#F59E0B', '#10B981', '#3B82F6', '#EAB308',
    '#A21CAF', '#BE185D', '#64748B', '#6B7280', '#EF4444',
    '#34D399', '#F472B6', '#22D3EE', '#D1FAE5', '#8BC34A',
];

const COLOR = {
    ok:      '#10B981',
    warn:    '#F59E0B',
    danger:  '#EF4444',
    primary: '#6366F1',
    primaryL:'#818CF8',
    primaryD:'#4F46E5',
    tcp:     '#3B82F6',
    udp:     '#10B981',
};

const TYPE_COLORS = {
    router: '#F59E0B', switch: '#0EA5E9', ap: '#8B5CF6',
    desktop: '#6366F1', vm: '#A21CAF', rpi: '#EF4444',
    phone: '#EC4899', smarttv: '#22D3EE', printer: '#6B7280',
    camera: '#F97316', nas: '#10B981', other: '#64748B',

    firewall: '#DC2626', loadbalancer: '#0284C7', server: '#0891B2',
    hypervisor: '#7C3AED', storage: '#0D9488', laptop: '#3B82F6',
    tablet: '#14B8A6', voip: '#84CC16', iot: '#D946EF',
};

const TYPE_LABELS = {
    router: 'Router', switch: 'Switch', ap: 'Access Point',
    desktop: 'Desktop', vm: 'VM', rpi: 'Raspberry Pi',
    phone: 'Phone', smarttv: 'Smart TV', printer: 'Printer',
    camera: 'Camera', nas: 'NAS', other: 'Other',

    firewall: 'Firewall', loadbalancer: 'Load Balancer', server: 'Servidor (Server)',
    hypervisor: 'Hypervisor', storage: 'Storage (SAN / NAS)',
    laptop: 'Laptop / Notebook', tablet: 'Tablet',
    voip: 'Telefone IP (VoIP)', iot: 'Dispositivos IoT',
};

const T = Object.assign({
    machines: 'Máquinas', devices: 'Dispositivos', quantity: 'Quantidade',
    occurrences: 'Ocorrências', withAgent: 'Com agente', withoutAgent: 'Sem agente',
    withAgentWazuh: 'Com agente Wazuh', withoutAgentWazuh: 'Sem agente Wazuh',
    protectedDevices: 'dispositivos protegidos',

    activeMachines: 'Agentes Wazuh Online', inactiveMachines: 'Agentes Wazuh Offline',
    noData: 'Sem dados', notIdentified: 'Não identificado',

    agentsActive: 'Agentes Ativos', agentsDisconnected: 'Agentes Desconectados',
    agentsNever: 'Nunca Conectaram',
    kaToday: 'Hoje', kaWeek: '1-7 dias', kaMonth: '8-30 dias', kaOld: 'Mais de 30 dias',
    daysKeepalive: 'dias desde o último keepalive',
    ramInUse: 'em uso', installedOn: 'instalado em', machinesF: 'máquinas',

    loading: 'Carregando…',
}, window.DASH_T || {});

const FONT = "Inter, 'Segoe UI', -apple-system, sans-serif";

function isDark() {
    return document.documentElement.classList.contains('dark-mode')
        || document.body.classList.contains('dark-mode');
}

function textMain()  { return isDark() ? '#E2E8F0' : '#1E293B'; }

function textSub()   { return isDark() ? '#94A3B8' : '#64748B'; }

function splitLine() { return isDark() ? 'rgba(148,163,184,.18)' : 'rgba(100,116,139,.15)'; }

function sliceBorder() { return isDark() ? '#0F172A' : '#FFFFFF'; }

function tipBg() { return isDark() ? 'rgba(15,23,42,.96)' : 'rgba(255,255,255,.97)'; }
function tipBorder() { return isDark() ? '#334155' : '#E2E8F0'; }

function tooltipBase() {
    return {
        backgroundColor: tipBg(),
        borderColor: tipBorder(),
        borderWidth: 1,
        padding: [8, 12],
        textStyle: { color: textMain(), fontSize: 12, fontFamily: FONT },
        extraCssText: 'box-shadow: 0 4px 12px rgba(0,0,0,.15); border-radius: 8px;',
    };
}

const charts = {};

let DATA = null;

function mount(id) {
    if (charts[id]) return charts[id];
    const el = document.getElementById(id);
    if (!el) return null;
    charts[id] = echarts.init(el, null, { renderer: 'canvas' });
    return charts[id];
}

function goSearch(query) {
    if (!query) return;
    window.location.href = '/search?query=' + encodeURIComponent(query);
}

function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function debounce(fn, ms) {
    let t;
    return function (...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), ms); };
}

function vGradient(from, to) {
    return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
        { offset: 0, color: from }, { offset: 1, color: to },
    ]);
}

function hGradient(from, to) {
    return new echarts.graphic.LinearGradient(0, 0, 1, 0, [
        { offset: 0, color: from }, { offset: 1, color: to },
    ]);
}

function legendBottom(extra) {
    return Object.assign({
        bottom: 0, left: 'center',
        type: 'scroll',
        selectedMode: true,
        itemWidth: 10, itemHeight: 10, itemGap: 14,
        icon: 'circle',
        textStyle: { color: textSub(), fontSize: 11, fontFamily: FONT },
        pageIconColor: textSub(), pageIconInactiveColor: splitLine(),
        pageTextStyle: { color: textSub() },
    }, extra || {});
}

function noDataGraphic() {
    return [{
        type: 'text', left: 'center', top: 'middle', silent: true,
        style: { text: T.noData, fill: textSub(), fontSize: 14, fontFamily: FONT },
    }];
}

function coverageOption() {
    const total = Number(DATA.ns_total || 0);
    const com = Number(DATA.ns_with_agent || 0);
    const sem = Number(DATA.ns_without_agent || 0);

    const sup = com + sem;
    const cov = Number(DATA.ns_agent_coverage || 0) ||
                (sup ? Math.round(100 * com / sup) : 0);

    const rAll = [8, 8, 8, 8];
    const rLeft = com ? [8, 0, 0, 8] : rAll;
    const rRight = sem ? [0, 8, 8, 0] : rAll;

    return {
        animationDuration: 900,
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'item',
            formatter: p => {
                const v = Number(p.value) || 0;
                const pct = sup ? Math.round(100 * v / sup) : 0;
                return p.name + ': ' + v + ' (' + pct + '% ' + T.devices.toLowerCase() + ')';
            },
        }),

        legend: legendBottom({ data: [T.withAgentWazuh, T.withoutAgentWazuh] }),

        grid: { left: 16, right: 16, top: 86, bottom: 8, containLabel: true },

        xAxis: { type: 'value', max: sup || 1, show: false },
        yAxis: {
            type: 'category', data: [''],
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: { show: false },
        },
        series: [
            {
                name: T.withAgentWazuh,
                type: 'bar',
                stack: 'cobertura',
                barWidth: 34,
                itemStyle: {
                    borderRadius: com && !sem ? rAll : rLeft,
                    color: hGradient('#34D399', COLOR.ok),
                },

                label: {
                    show: com > 0, position: 'inside',
                    color: '#FFFFFF', fontSize: 13, fontWeight: 700, fontFamily: FONT,
                    formatter: () => com + ' (' + cov + '%)',
                },
                emphasis: { itemStyle: { opacity: .88 } },
                data: [com],
            },
            {
                name: T.withoutAgentWazuh,
                type: 'bar',
                stack: 'cobertura',
                barWidth: 34,
                itemStyle: {
                    borderRadius: sem && !com ? rAll : rRight,
                    color: hGradient('#FBBF24', '#F97316'),
                },
                label: {
                    show: sem > 0, position: 'inside',
                    color: '#FFFFFF', fontSize: 13, fontWeight: 700, fontFamily: FONT,
                    formatter: () => String(sem),
                },
                emphasis: { itemStyle: { opacity: .88 } },
                data: [sem],
            },
        ],

        graphic: total ? [
            {
                type: 'text', left: 'center', top: 14, silent: true,
                style: {
                    text: cov + '% ' + T.coverage,
                    fill: textMain(), fontSize: 30, fontWeight: 700, fontFamily: FONT,
                },
            },
            {
                type: 'text', left: 'center', top: 52, silent: true,
                style: {
                    text: com + ' ' + T.protectedDevices + '  ·  ' + sup + ' ' + T.devices,
                    fill: textSub(), fontSize: 11.5, fontWeight: 500, fontFamily: FONT,
                },
            },
        ] : noDataGraphic(),

    };
}

function agentStatusOption() {
    const d = DATA.agent_status_detail || {};
    const entries = [
        { name: T.agentsActive,       value: d.active || 0,          color: COLOR.ok },
        { name: T.agentsDisconnected, value: d.disconnected || 0,    color: COLOR.danger },
        { name: T.agentsNever,        value: d.never_connected || 0, color: COLOR.warn },
    ].filter(e => e.value > 0);
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'item',
            formatter: p => p.name + ': ' + p.value + ' (' + p.percent + '%)',
        }),

        legend: legendBottom({ data: entries.map(e => e.name) }),
        series: [{
            type: 'pie',
            radius: ['40%', '70%'],
            center: ['50%', '44%'],
            avoidLabelOverlap: true,
            itemStyle: { borderRadius: 6, borderColor: sliceBorder(), borderWidth: 2 },

            label: {
                position: 'inner',
                formatter: '{c}\n{d}%',
                color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONT,
                lineHeight: 13,
            },
            labelLine: { show: false },
            emphasis: { scale: true, scaleSize: 5 },
            data: entries.map(e => ({
                name: e.name, value: e.value, itemStyle: { color: e.color },
            })),
        }],
        graphic: entries.length ? [] : noDataGraphic(),
    };
}

function keepaliveOption() {
    const b = DATA.keepalive_buckets || {};
    const buckets = [
        { name: T.kaToday, value: b.today || 0,  color: COLOR.ok },
        { name: T.kaWeek,  value: b.week || 0,   color: '#84CC16' },
        { name: T.kaMonth, value: b.month || 0,  color: COLOR.warn },
        { name: T.kaOld,   value: b.old || 0,    color: COLOR.danger },
    ];
    const total = buckets.reduce((s, e) => s + e.value, 0);

    let acc = 0;
    const cumulative = buckets.map(e => {
        acc += e.value;
        return total ? Math.round(100 * acc / total) : 0;
    });

    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },

            formatter: ps => {
                if (!ps || !ps.length) return '';
                const i = ps[0].dataIndex;
                const e = buckets[i];
                const pct = total ? Math.round(100 * e.value / total) : 0;
                let html = '<b>' + esc(e.name) + '</b>';
                html += '<br/>' + T.agents + ': ' + e.value + ' (' + pct + '%)';
                html += '<br/>' + T.cumulative + ': ' + cumulative[i] + '%';
                html += '<br/><span style="color:' + textSub() + '">' +
                        T.daysKeepalive + '</span>';
                return html;
            },
        }),

        legend: legendBottom({ data: [T.agents, T.cumulative], bottom: 2 }),
        grid: { left: 8, right: 8, top: 34, bottom: 34, containLabel: true },
        xAxis: {
            type: 'category',
            data: buckets.map(e => e.name),
            axisTick: { show: false },
            axisLine: { lineStyle: { color: splitLine() } },
            axisLabel: { color: textMain(), fontSize: 11, fontFamily: FONT, fontWeight: 600 },
        },
        yAxis: [
            {

                type: 'value',
                minInterval: 1,
                max: total || 1,
                splitLine: { lineStyle: { color: splitLine() } },
                axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
            },
            {

                type: 'value',
                min: 0, max: 100,
                splitLine: { show: false },
                axisLabel: {
                    color: textSub(), fontSize: 10.5, fontFamily: FONT,
                    formatter: '{value}%',
                },
            },
        ],
        series: [
            {

                name: T.agents,
                type: 'bar',
                barMaxWidth: 44,
                label: {
                    show: true, position: 'top',
                    color: textMain(), fontSize: 12, fontWeight: 700, fontFamily: FONT,
                },
                data: buckets.map(e => ({
                    value: e.value,
                    itemStyle: {
                        borderRadius: [6, 6, 0, 0],
                        color: vGradient(e.color, e.color),
                    },
                })),
                emphasis: { itemStyle: { opacity: .85 } },
            },
            {

                name: T.cumulative,
                type: 'line',
                yAxisIndex: 1,
                smooth: true,
                symbol: 'circle',
                symbolSize: 8,

                itemStyle: {
                    color: COLOR.primary,
                    borderColor: sliceBorder(), borderWidth: 2,
                },
                lineStyle: { width: 3, color: COLOR.primary },

                areaStyle: {
                    color: {
                        type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
                        colorStops: [
                            { offset: 0, color: 'rgba(99,102,241,0.28)' },
                            { offset: 1, color: 'rgba(99,102,241,0.02)' },
                        ],
                    },
                },

                label: {
                    show: true, position: 'top', distance: 6,
                    color: COLOR.primary, fontSize: 10.5, fontWeight: 600,
                    fontFamily: FONT, formatter: '{c}%',
                },
                data: cumulative,
            },
        ],
        graphic: total ? [] : noDataGraphic(),
    };
}

function ramUsageOption() {
    const list = (DATA.ram_usage_top || []).slice(0, 10);
    const labels = list.map(m => m.name);
    const values = list.map(m => m.usage);

    const colorFor = (u) => u >= 85 ? COLOR.danger : (u >= 60 ? COLOR.warn : COLOR.ok);
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },

            formatter: ps => {
                const p = ps[0];
                const m = list[p.dataIndex] || {};
                let tip = p.name + ': <b>' + p.value + '%</b> ' + T.ramInUse;
                if (m.total_gb) {
                    const used = (m.usage / 100) * m.total_gb;
                    tip += '<br/>' + used.toFixed(1).replace('.', ',') +
                           ' GB ' + T.ramOf + ' ' +
                           String(m.total_gb).replace('.', ',') + ' GB';
                }
                return tip;
            },
        }),
        grid: { left: 8, right: 38, top: 10, bottom: 8, containLabel: true },
        xAxis: {
            type: 'value',
            max: 100,
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT, formatter: '{value}%' },
            splitLine: { lineStyle: { color: splitLine() } },
        },
        yAxis: {
            type: 'category',
            inverse: true,
            data: labels,
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: {
                color: textMain(), fontSize: 11, fontFamily: FONT, fontWeight: 600,
                width: 110, overflow: 'truncate',
            },
        },
        series: [{
            type: 'bar',
            barMaxWidth: 18,
            itemStyle: { borderRadius: [0, 6, 6, 0] },
            label: {
                show: true, position: 'right',
                color: textSub(), fontSize: 11, fontFamily: FONT,
                formatter: '{c}%',
            },
            data: values.map((v, i) => ({
                value: v,
                itemStyle: { color: hGradient(colorFor(v), colorFor(v)) },
            })),
        }],
        graphic: list.length ? [] : noDataGraphic(),
    };
}

function softwareOption() {
    const list = (DATA.software_top || []).slice(0, 10);
    const labels = list.map(s => s.name);
    const values = list.map(s => s.count);
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            formatter: ps => ps[0].name + ': ' + T.installedOn + ' ' + ps[0].value + ' ' + T.machinesF,
        }),
        grid: { left: 8, right: 34, top: 10, bottom: 8, containLabel: true },
        xAxis: {
            type: 'value',
            minInterval: 1,
            splitLine: { lineStyle: { color: splitLine() } },
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
        },
        yAxis: {
            type: 'category',
            inverse: true,
            data: labels,
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: {
                color: textMain(), fontSize: 11, fontFamily: FONT, fontWeight: 600,
                width: 130, overflow: 'truncate',
            },
        },
        series: [{
            type: 'bar',
            barMaxWidth: 18,
            itemStyle: {
                borderRadius: [0, 6, 6, 0],
                color: hGradient('#0EA5E9', '#6366F1'),
            },
            label: {
                show: true, position: 'right',
                color: textSub(), fontSize: 11, fontFamily: FONT,
            },
            data: values,
        }],
        graphic: list.length ? [] : noDataGraphic(),
    };
}

function roseTypesOption() {
    const types = DATA.ns_types || {};
    const entries = Object.entries(types).sort((a, b) => b[1] - a[1]);
    const data = entries.map(([k, v], i) => ({
        name: T.types && T.types[k] ? T.types[k] : (TYPE_LABELS[k] || k),
        value: v,
        itemStyle: { color: TYPE_COLORS[k] || PALETTE[i % PALETTE.length] },
    }));
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'item',
            formatter: p => p.name + ': ' + p.value + ' (' + p.percent + '%)',
        }),
        legend: legendBottom(),
        series: [{
            type: 'pie',
            roseType: 'area',
            radius: ['14%', '72%'],
            center: ['50%', '46%'],
            itemStyle: { borderRadius: 5, borderColor: sliceBorder(), borderWidth: 1.5 },
            label: { color: textSub(), fontSize: 11, fontFamily: FONT },
            labelLine: { lineStyle: { color: splitLine() } },
            emphasis: { scale: true, scaleSize: 6 },
            data: data,
        }],
        graphic: data.length ? [] : noDataGraphic(),
    };
}

function donutOption(labels, values, colors) {
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'item',
            formatter: p => p.name + ': ' + p.value + ' (' + p.percent + '%)',
        }),
        legend: legendBottom(),
        series: [{
            type: 'pie',
            radius: ['38%', '70%'],
            center: ['50%', '44%'],
            itemStyle: { borderRadius: 6, borderColor: sliceBorder(), borderWidth: 2 },

            label: {
                position: 'inner',
                formatter: '{d}%',
                color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONT,
            },
            labelLine: { show: false },
            emphasis: { scale: true, scaleSize: 5 },
            data: (labels || []).map((n, i) => ({
                name: n, value: values[i],
                itemStyle: { color: (colors || PALETTE)[i % (colors || PALETTE).length] },
            })),
        }],
        graphic: (labels || []).length ? [] : noDataGraphic(),
    };
}

function cpuBarOption() {
    const labels = DATA.cpu_labels || [];
    const values = DATA.cpu_data || [];
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            formatter: ps => ps[0].name + ': ' + ps[0].value + ' ' + T.quantity,
        }),
        grid: { left: 8, right: 8, top: 24, bottom: 8, containLabel: true },
        xAxis: {
            type: 'category',
            data: labels,
            axisTick: { show: false },
            axisLine: { lineStyle: { color: splitLine() } },
            axisLabel: {
                color: textSub(), fontSize: 10, fontFamily: FONT,
                interval: 0,
                rotate: labels.length > 6 ? 32 : 0,

                formatter: (v) => {
                    const s = String(v || '');

                    const m = s.match(/(?:Core|Ryzen|Xeon|EPYC|Celeron|Pentium|Athlon|Duron)\s*\(?(?:TM|R)?\)?\s+(.+)/i);
                    const short = m ? m[1].trim() : s;
                    return short.length > 16 ? short.slice(0, 15) + '…' : short;
                },
            },
        },
        yAxis: {
            type: 'value',
            minInterval: 1,
            splitLine: { lineStyle: { color: splitLine() } },
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
        },
        series: [{
            type: 'bar',
            barMaxWidth: 42,
            itemStyle: {
                borderRadius: [6, 6, 0, 0],
                color: vGradient(COLOR.primaryL, COLOR.primaryD),
            },
            emphasis: { itemStyle: { color: vGradient(COLOR.primary, COLOR.primaryD) } },
            data: values,
        }],
        graphic: labels.length ? [] : noDataGraphic(),
    };
}

function hBarOption(labels, values, itemColors, unit) {
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            formatter: ps => ps[0].name + ': ' + ps[0].value + ' ' + (unit || T.quantity),
        }),
        grid: { left: 8, right: 30, top: 10, bottom: 8, containLabel: true },
        xAxis: {
            type: 'value',
            minInterval: 1,
            splitLine: { lineStyle: { color: splitLine() } },
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
        },
        yAxis: {
            type: 'category',
            inverse: true,
            data: labels,
            axisTick: { show: false },
            axisLine: { show: false },
            axisLabel: { color: textMain(), fontSize: 11, fontFamily: FONT, fontWeight: 600 },
        },
        series: [{
            type: 'bar',
            barMaxWidth: 22,
            itemStyle: { borderRadius: [0, 6, 6, 0] },
            label: {
                show: true, position: 'right',
                color: textSub(), fontSize: 11, fontFamily: FONT,
            },
            data: values.map((v, i) => ({
                value: v,
                itemStyle: { color: itemColors[i % itemColors.length] },
            })),
        }],
        graphic: labels.length ? [] : noDataGraphic(),
    };
}

function treemapGroupsOption() {
    const groups = (DATA.groups || [])
        .filter(g => g.quantidade_agentes > 0)
        .sort((a, b) => b.quantidade_agentes - a.quantidade_agentes);
    const data = groups.map((g, i) => ({
        name: g.grupo,
        value: g.quantidade_agentes,
        itemStyle: { color: PALETTE[i % PALETTE.length] },
        label: { fontSize: g.quantidade_agentes >= 8 ? 12 : (g.quantidade_agentes >= 4 ? 11 : 10) },
    }));
    return {
        tooltip: Object.assign(tooltipBase(), {
            formatter: p => p.name + ': ' + p.value + ' ' + T.machines,
        }),
        series: [{
            type: 'treemap',
            width: '96%', height: '88%',
            top: '6%', left: '2%',
            roam: false,
            nodeClick: false,
            breadcrumb: { show: false, bottom: 0 },
            itemStyle: { borderColor: sliceBorder(), borderWidth: 2, gapWidth: 2, borderRadius: 8 },
            label: {
                show: true,
                formatter: '{b}\n{c}',
                fontSize: 11, fontFamily: FONT, color: '#FFFFFF',
                fontWeight: 600,
                width: '90%',
                overflow: 'breakAll',
                lineHeight: 13,
                ellipsis: '…',
            },
            upperLabel: { show: false },
            data: data,
        }],
        graphic: data.length ? [] : noDataGraphic(),
    };
}

function timelineOption() {

    const hexToRgba = (hex, alpha) => {
        const n = parseInt(hex.slice(1), 16);
        return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
    };
    const areaGrad = (c) => new echarts.graphic.LinearGradient(0, 0, 0, 1, [
        { offset: 0, color: hexToRgba(c, .25) },
        { offset: 1, color: hexToRgba(c, 0) },
    ]);
    const mk = (name, values, color) => ({
        name, type: 'line', smooth: true, symbol: 'circle',
        symbolSize: 7, data: values,
        lineStyle: { width: 3, color },
        itemStyle: { color, borderColor: sliceBorder(), borderWidth: 2 },
        emphasis: { focus: 'series' },
        areaStyle: { color: areaGrad(color) },
    });
    return {
        tooltip: Object.assign(tooltipBase(), {
            trigger: 'axis',
            axisPointer: { type: 'cross', label: { backgroundColor: tipBg() } },
        }),
        legend: legendBottom(),
        grid: { left: 8, right: 16, top: 20, bottom: 34, containLabel: true },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: DATA.timeline_dates || [],
            axisTick: { show: false },
            axisLine: { lineStyle: { color: splitLine() } },
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
        },
        yAxis: {
            type: 'value',
            minInterval: 1,
            splitLine: { lineStyle: { color: splitLine(), type: 'dashed' } },
            axisLabel: { color: textSub(), fontSize: 11, fontFamily: FONT },
        },
        series: [
            mk(T.activeMachines,   DATA.timeline_active   || [], COLOR.ok),
            mk(T.inactiveMachines, DATA.timeline_inactive || [], COLOR.danger),
        ],
        graphic: (DATA.timeline_dates || []).length ? [] : noDataGraphic(),
    };
}

function bindClicks() {
    const on = (id, fn) => {
        const c = charts[id];
        if (!c) return;
        c.off('click');
        c.on('click', (params) => {
            if (!params || params.name == null) return;
            fn(params);
        });
    };

    on('chartOs', p => goSearch('inventory:os:' + String(p.name).toLowerCase()));

    on('chartCpu', p => goSearch('inventory:hardware:' + String(p.name).toLowerCase()));

    on('chartRam', p => {
        const label = String(p.name).toLowerCase();
        const q = label.includes('+')
            ? 'ram_gb:>' + label.replace('+', '').replace('gb', '').trim()
            : 'ram_gb:' + label;
        goSearch(q);
    });

    on('chartPorts', p => {
        const digits = String(p.name).replace(/\D/g, '');
        goSearch('ports:' + (digits || String(p.name).toLowerCase()));
    });

    on('chartProcess', p => {
        if (p.name) goSearch('inventory:processes:' + String(p.name).toLowerCase());
    });

    on('chartGroups', p => goSearch('groups:' + String(p.name)));

    on('chartCoverage', p => {
        if (String(p.name) === T.withAgentWazuh) window.location.href = '/netscope?filter=agent';
        else if (String(p.name) === T.withoutAgentWazuh) window.location.href = '/netscope?filter=noagent';
    });

    on('agentStatus', p => {
        const map = {};
        map[T.agentsActive] = 'active';
        map[T.agentsDisconnected] = 'disconnected';
        const st = map[String(p.name)];
        if (st) goSearch('agent_info:status:' + st);
    });

    on('chartRamUsage', p => {
        window.location.href = '/machine/' + encodeURIComponent(String(p.name));
    });

    on('chartSoftware', p => {
        goSearch('inventory:packages:' + String(p.name).toLowerCase());
    });
}

function renderRecentMachines() {
    const tbody = document.getElementById('recent-machines');
    if (!tbody || !DATA.recent_machines) return;

    tbody.innerHTML = DATA.recent_machines.map(m =>
        `<tr><td>${esc(m.name)}</td>` +

        `<td style="font-family: var(--font-mono, monospace);">${esc(m.agent_id || '—')}</td>` +
        `<td>${esc(m.ip || '—')}</td>` +
        `<td>${esc(m.os)}</td>` +
        `<td><span class="badge ${m.status_key === 'Ativo' ? 'green' : 'orange'}">${esc(m.status)}</span></td></tr>`
    ).join('');
}

function renderAll() {
    if (!DATA) return;

    const batches = [

        function () {

            mount('chartCoverage'); charts.chartCoverage && charts.chartCoverage.setOption(coverageOption(), true);

            mount('agentStatus');  charts.agentStatus  && charts.agentStatus.setOption(agentStatusOption(), true);
            mount('roseTypes');    charts.roseTypes    && charts.roseTypes.setOption(roseTypesOption(), true);
        },

        function () {
            mount('chartOs');   charts.chartOs && charts.chartOs.setOption(donutOption(DATA.os_labels, DATA.os_data), true);
            mount('chartCpu');  charts.chartCpu && charts.chartCpu.setOption(cpuBarOption(), true);
            mount('chartRam');  charts.chartRam && charts.chartRam.setOption(donutOption(DATA.ram_labels, DATA.ram_data), true);
        },

        function () {

            mount('chartPorts');
            if (charts.chartPorts) {
                const portColors = (DATA.port_protocols || []).map(pr => pr === 'tcp' ? COLOR.tcp : COLOR.udp);
                charts.chartPorts.setOption(hBarOption(DATA.port_labels, DATA.port_data, portColors, T.occurrences), true);
            }

            mount('chartProcess');
            if (charts.chartProcess) {
                const procColors = (DATA.process_labels || []).map(() => vGradient('#A78BFA', '#7C3AED'));
                charts.chartProcess.setOption(hBarOption(DATA.process_labels, DATA.process_data, procColors, T.quantity), true);
            }

            mount('chartGroups');
            if (charts.chartGroups) charts.chartGroups.setOption(treemapGroupsOption(), true);
            const groupsActive = (DATA.groups || []).some(g => g.quantidade_agentes > 0);
            const gc = document.getElementById('chartGroups');
            if (gc && gc.closest('.chart-card')) {
                gc.closest('.chart-card').style.display = groupsActive ? '' : 'none';
            }
        },

        function () {
            mount('chartKeepalive'); charts.chartKeepalive && charts.chartKeepalive.setOption(keepaliveOption(), true);
            mount('chartRamUsage');  charts.chartRamUsage  && charts.chartRamUsage.setOption(ramUsageOption(), true);
            mount('chartSoftware');  charts.chartSoftware  && charts.chartSoftware.setOption(softwareOption(), true);
        },

        function () {
            mount('chartTimeline');
            charts.chartTimeline && charts.chartTimeline.setOption(timelineOption(), true);
            renderRecentMachines();
            bindClicks();

            Object.keys(charts).forEach(id => charts[id] && charts[id].hideLoading());
        },
    ];

    let i = 0;
    (function next() {
        if (i >= batches.length) return;
        const fn = batches[i++];
        requestAnimationFrame(() => {
            try { fn(); } catch (e) { console.error('[Dashboard ECharts] lote de gráficos falhou:', e); }
            next();
        });
    })();
}

function updateKpis() {
    if (!DATA) return;
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el && String(el.textContent) !== String(val)) el.textContent = val;
    };
    set('kpi-online', DATA.active_count);
    set('kpi-offline', DATA.inactive_count);
    set('kpi-total', DATA.ns_total);
    set('kpi-agent', DATA.ns_with_agent);
    set('kpi-noagent', DATA.ns_without_agent);
    set('kpi-with-agent', DATA.ns_with_agent);
    set('kpi-without-agent', DATA.ns_without_agent);

    const exWrap = document.getElementById('kpi-exempt-wrap');
    if (exWrap) {
        exWrap.style.display = Number(DATA.ns_agent_exempt) > 0 ? 'block' : 'none';
        set('kpi-agent-exempt', DATA.ns_agent_exempt);
    }
}

function showLoadingAll() {
    Object.keys(charts).forEach(id => {
        const c = charts[id];
        if (!c) return;
        c.showLoading({
            text: T.loading || '',
            color: COLOR.primaryL,
            maskColor: isDark() ? 'rgba(15,23,42,.4)' : 'rgba(248,250,252,.6)',
            textColor: textSub(),
            fontSize: 11,
            spinnerRadius: 8,
        });
    });
}

function rebuildAll() {
    Object.keys(charts).forEach(id => {
        if (charts[id]) {
            charts[id].dispose();
            delete charts[id];
        }
    });
    renderAll();
}

function watchTheme() {
    const mo = new MutationObserver(() => rebuildAll());
    mo.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class'],
    });
    mo.observe(document.body, {
        attributes: true,
        attributeFilter: ['class'],
    });
}

function watchResize() {
    window.addEventListener('resize', debounce(() => {
        Object.values(charts).forEach(c => c && c.resize());
    }, 150));
}

const POLL_INTERVAL_MS = 60000;

let _loadedOnce = false;

function refreshData() {
    return fetch('/get_chart_data')
        .then(res => res.ok ? res.json() : Promise.reject('HTTP ' + res.status))
        .then(json => {
            DATA = json;
            _loadedOnce = true;
            updateKpis();
            renderAll();

            window.dispatchEvent(new CustomEvent('app:data-ready'));
            playEntrance();
        })
        .catch(err => {

            if (_loadedOnce) {
                console.debug('[Dashboard ECharts] Poll adiado (retry no próximo ciclo):', err);
            } else {
                console.error('[Dashboard ECharts] Falha ao carregar dados:', err);

                window.dispatchEvent(new CustomEvent('app:data-ready'));
                playEntrance();
            }
        });
}

let _entranceDone = false;

function playEntrance() {
    if (_entranceDone) return;
    _entranceDone = true;

    const items = document.querySelectorAll('.kpi-card, .chart-card, .detailed-card');
    items.forEach((el, i) => {

        el.style.setProperty('--enter-delay', Math.min(i * 70, 900) + 'ms');
        el.classList.add('enter-anim');
        el.addEventListener('animationend', function onEnd() {

            el.classList.remove('enter-anim');
            el.classList.add('entered');
        }, { once: true });
    });

    setTimeout(() => {
        items.forEach(el => el.classList.add('entered'));
    }, 1600);
}

window.addEventListener('app:splash-hidden', () => playEntrance());

document.addEventListener('DOMContentLoaded', () => {

    ['chartCoverage', 'agentStatus', 'roseTypes',
     'chartOs', 'chartCpu', 'chartRam',
     'chartPorts', 'chartProcess', 'chartGroups',
     'chartKeepalive', 'chartRamUsage', 'chartSoftware', 'chartTimeline',
    ].forEach(mount);
    showLoadingAll();

    refreshData();

    setInterval(() => {
        if (document.hidden) return;
        refreshData();
    }, POLL_INTERVAL_MS);

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) refreshData();
    });

    watchTheme();
    watchResize();
});
