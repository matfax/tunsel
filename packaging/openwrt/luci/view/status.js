'use strict';
'require view';
'require dom';
'require poll';
'require rpc';

// Reads the daemon's report through the rpcd plugin (ubus object "tunsel",
// which runs `tunsel status -json`). Flows are polled with the report; the
// RTT history, which changes once per probe interval, less often.

const callFlows = rpc.declare({ object: 'tunsel', method: 'flows', expect: { '': {} } });
const callHistory = rpc.declare({ object: 'tunsel', method: 'history', expect: { '': {} } });

const SVGNS = 'http://www.w3.org/2000/svg';
// Counts from here on are shown in magnitude only (IPv6 /64s); JSON
// numbers lose precision there anyway.
const EXACT_BELOW = 10 ** 12;
// Polls between history refreshes (every 30 s at 5 s per poll).
const HISTORY_EVERY = 6;

const stateColors = new Map([ [ 'healthy', '#2e9d4f' ], [ 'unhealthy', '#d23f31' ] ]);

function svg(tag, attrs, children) {
	const el = document.createElementNS(SVGNS, tag);
	for (const [ k, v ] of Object.entries(attrs))
		el.setAttribute(k, v);
	for (const c of children ?? [])
		el.appendChild(c);
	return el;
}

function text(s) {
	return document.createTextNode(s === null || s === undefined ? '' : String(s));
}

function bytes(n) {
	const units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB' ];
	let i = 0;
	n = n || 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return `${i ? n.toFixed(1) : n} ${units.at(i)}`;
}

function ms(v) {
	return v === null || v === undefined ? '–' : `${v.toFixed(v < 1 ? 2 : 1)} ms`;
}

function count(n) {
	n = n || 0;
	return n < EXACT_BELOW ? n.toLocaleString() : n.toExponential(1).replace(/e\+?/, ' × 10^');
}

function since(iso) {
	const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
	if (s < 120) return _('%d s').format(s);
	if (s < 7200) return _('%d min').format(Math.round(s / 60));
	if (s < 172800) return _('%d h').format(Math.round(s / 3600));
	return _('%d days').format(Math.round(s / 86400));
}

function badge(state) {
	const color = stateColors.get(state) ?? '#888';
	return E('span', { style: 'white-space:nowrap' }, [
		E('span', { style: `display:inline-block;width:.7em;height:.7em;border-radius:50%;margin-right:.4em;background:${color}` }),
		text(state)
	]);
}

function cell(c) {
	if (Array.isArray(c))
		return c;
	return [ typeof c === 'object' ? c : text(c) ];
}

function table(titles, rows) {
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, titles.map((t) => E('th', { 'class': 'th' }, [ text(t) ])))
	].concat(rows.map((r) => E('tr', { 'class': 'tr' }, r.map((c) => E('td', { 'class': 'td' }, cell(c)))))));
}

function lines(items) {
	const out = [];
	items.forEach((it, i) => {
		if (i) out.push(E('br'));
		out.push(typeof it === 'object' ? it : text(it));
	});
	return out;
}

function ranges(s) {
	if (!s?.prefixes)
		return _('none');
	const parts = [ _('%d prefixes').format(s.prefixes) ];
	if (s.ipv4_addresses) parts.push(_('%s IPv4 addresses').format(count(s.ipv4_addresses)));
	if (s.ipv6_64s) parts.push(_('%s IPv6 /64s').format(count(s.ipv6_64s)));
	if (!s.ranges) parts.push(_('inactive'));
	return parts.join(', ');
}

// One bar per probe, scaled to the slowest answer; lost probes are red ticks.
function sparkline(samples) {
	const w = 360, h = 36, bw = w / Math.max(samples.length, 1);
	const hi = samples.reduce((m, s) => (s.ok ? Math.max(m, s.rtt_ms) : m), 0);
	const bars = samples.map((s, i) => {
		if (!s.ok)
			return svg('rect', { x: i * bw, y: 0, width: Math.max(bw, 1), height: h, fill: '#d23f31', 'fill-opacity': 0.35 });
		const bh = hi ? Math.max(1, s.rtt_ms / hi * h) : 1;
		return svg('rect', { x: i * bw, y: h - bh, width: Math.max(bw, 1), height: bh, fill: '#3478c6' });
	});
	return svg('svg', { width: w, height: h, viewBox: `0 0 ${w} ${h}`, preserveAspectRatio: 'none',
		style: 'max-width:100%;background:rgba(127,127,127,.08);vertical-align:middle' }, bars);
}

function stateCell(r, t) {
	const defaults = [];
	if (r.default_ipv4 === t.name) defaults.push('IPv4');
	if (r.default_ipv6 === t.name) defaults.push('IPv6');
	const state = [ badge(t.state), _('link %s, %d/%d answered').format(t.link || '?', t.ok || 0, t.total || 0) ];
	if (defaults.length) state.push(_('default for %s').format(defaults.join(', ')));
	for (const e of t.errors ?? [])
		state.push(E('small', {}, [ text(e) ]));
	return lines(state);
}

// The flow groups of a report by tunnel name.
function flowGroups(r) {
	return new Map(Object.entries(r.flows?.tunnels ?? {}));
}

function tunnelRow(r, groups, t) {
	const f = groups.get(t.name) ?? {};
	return [
		E('strong', {}, [ text(t.name) ]),
		stateCell(r, t),
		lines((t.latency ?? []).map((l) =>
			_('%s: %s (avg %s, jitter %s), %s%% lost').format(l.target, ms(l.last_ms), ms(l.avg_ms), ms(l.jitter_ms), l.loss_pct))),
		lines([ _('%s static').format(count(t.connections_static)), _('%s default').format(count(t.connections_default)) ]),
		r.flows ? lines([ _('%s flows').format(count(f.flows)), _('%s destinations').format(count(f.destinations)) ]) : '–',
		lines([
			r.flows ? _('%s out / %s in').format(bytes(f.bytes_out), bytes(f.bytes_in)) : '',
			_('upstream %s, %s pkts').format(bytes(t.upstream?.bytes), count(t.upstream?.packets))
		]),
		ranges(t.static_ranges)
	];
}

function summary(r) {
	const c = r.connections ?? {};
	const rows = [
		[ _('Version'), r.version ],
		[ _('Running for'), since(r.started_at) ],
		[ _('Default IPv4 / IPv6'), `${r.default_ipv4 || _('none')} / ${r.default_ipv6 || _('none')}` ],
		[ _('New connections'), _('%s (excluded %s, local %s, unmarked %s)').format(count(c.new), count(c.excluded), count(c.local), count(c.unmarked)) ],
		[ _('Excluded prefixes'), ranges(r.exclude) ]
	];
	if (r.flows)
		rows.push([ _('Connections without a tunnel mark'), count(r.flows.other) ]);
	if (r.last_apply?.error)
		rows.push([ _('Last apply failed'), r.last_apply.error ]);
	for (const w of r.warnings ?? [])
		rows.push([ _('Warning'), w ]);
	return table([ _('Overview'), '' ], rows);
}

function latencySection(history) {
	if (!history?.tunnels)
		return E('div');
	const rows = [];
	for (const t of history.tunnels) {
		for (const h of t.history ?? []) {
			const ok = h.samples.filter((s) => s.ok);
			const hi = ok.reduce((m, s) => Math.max(m, s.rtt_ms), 0);
			rows.push([ t.name, h.target, sparkline(h.samples), ok.length ? _('max %s').format(ms(hi)) : _('no answers') ]);
		}
	}
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ text(_('RTT history')) ]),
		E('p', { 'class': 'cbi-section-descr' }, [ text(_('One bar per probe, oldest first, scaled per target; red marks a probe without an answer.')) ]),
		table([ _('Tunnel'), _('Target'), _('Last hour'), '' ], rows)
	]);
}

function topSection(r) {
	if (!r.flows)
		return E('div');
	const rows = [];
	const groups = flowGroups(r);
	for (const t of r.tunnels)
		for (const d of groups.get(t.name)?.top ?? [])
			rows.push([ t.name, d.addr, count(d.flows), bytes(d.bytes) ]);
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ text(_('Top destinations')) ]),
		E('p', { 'class': 'cbi-section-descr' }, [ text(_('Current conntrack entries per tunnel, by bytes in both directions.')) ]),
		rows.length ? table([ _('Tunnel'), _('Destination'), _('Flows'), _('Bytes') ], rows) : E('em', {}, [ text(_('No flows.')) ])
	]);
}

function report(r, history) {
	if (r.error)
		return E('div', { 'class': 'alert-message warning' }, [
			E('p', {}, [ text(_('tunsel is not running or not reachable:')) ]),
			E('pre', {}, [ text(r.error) ]),
			E('p', {}, [ E('a', { href: L.url('admin/services/tunsel/config') }, [ text(_('Check the configuration')) ]) ])
		]);
	const groups = flowGroups(r);
	return E('div', {}, [
		E('div', { 'class': 'cbi-section' }, [ summary(r) ]),
		E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ text(_('Tunnels')) ]),
			table([ _('Tunnel'), _('State'), _('Latency'), _('New connections'), _('Active flows'), _('Traffic'), _('Static preferences') ],
				r.tunnels.map((t) => tunnelRow(r, groups, t)))
		]),
		latencySection(history),
		topSection(r)
	]);
}

function fetchFlows() {
	return L.resolveDefault(callFlows(), { error: _('rpcd plugin not reachable') });
}

return view.extend({
	load: () => Promise.all([ fetchFlows(), L.resolveDefault(callHistory(), {}) ]),

	render: ([ first, firstHistory ]) => {
		const node = E('div');
		let history = firstHistory;
		let polls = 0;
		dom.content(node, report(first, history));

		poll.add(() => {
			polls++;
			// The history only gains one sample per probe interval.
			const nextHistory = polls % HISTORY_EVERY === 0 ? L.resolveDefault(callHistory(), history) : Promise.resolve(history);
			return Promise.all([ fetchFlows(), nextHistory ]).then(([ r, h ]) => {
				history = h;
				dom.content(node, report(r, history));
			});
		}, 5);

		return E('div', {}, [
			E('h2', {}, [ text(_('tunsel')) ]),
			E('p', { 'class': 'cbi-map-descr' }, [ text(_('Health, latency and traffic of the steered tunnels. Counters run since the nftables table was created, normally since boot.')) ]),
			node
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
