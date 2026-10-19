'use strict';
'require view';
'require dom';
'require poll';
'require rpc';

// Reads the daemon's report through the rpcd plugin (ubus object "tunsel",
// which runs `tunsel status -json`). Flows are polled with the report; the
// RTT history, which changes once per probe interval, less often.

var callFlows = rpc.declare({ object: 'tunsel', method: 'flows', expect: { '': {} } });
var callHistory = rpc.declare({ object: 'tunsel', method: 'history', expect: { '': {} } });

var SVGNS = 'http://www.w3.org/2000/svg';

function svg(tag, attrs, children) {
	var el = document.createElementNS(SVGNS, tag);
	for (var k in attrs)
		el.setAttribute(k, attrs[k]);
	(children || []).forEach(function(c) { el.appendChild(c); });
	return el;
}

function text(s) {
	return document.createTextNode(s == null ? '' : String(s));
}

function bytes(n) {
	var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'], i = 0;
	n = n || 0;
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return (i ? n.toFixed(1) : n) + ' ' + units[i];
}

function ms(v) {
	return v == null ? '–' : v.toFixed(v < 1 ? 2 : 1) + ' ms';
}

// Exact below a trillion; IPv6 /64 counts beyond that are only shown in
// magnitude (JSON numbers lose precision there anyway).
function count(n) {
	n = n || 0;
	return n < 1e12 ? n.toLocaleString() : n.toExponential(1).replace(/e\+?/, ' × 10^');
}

function since(iso) {
	var s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
	if (s < 120) return _('%d s').format(s);
	if (s < 7200) return _('%d min').format(Math.round(s / 60));
	if (s < 172800) return _('%d h').format(Math.round(s / 3600));
	return _('%d days').format(Math.round(s / 86400));
}

var stateColor = { healthy: '#2e9d4f', unhealthy: '#d23f31', unknown: '#888' };

function badge(state) {
	return E('span', { style: 'white-space:nowrap' }, [
		E('span', { style: 'display:inline-block;width:.7em;height:.7em;border-radius:50%;margin-right:.4em;background:' + (stateColor[state] || '#888') }),
		text(state)
	]);
}

function table(titles, rows) {
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, titles.map(function(t) { return E('th', { 'class': 'th' }, [ text(t) ]); }))
	].concat(rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, r.map(function(c) {
			return E('td', { 'class': 'td' }, Array.isArray(c) ? c : [ typeof c == 'object' ? c : text(c) ]);
		}));
	})));
}

function lines(items) {
	var out = [];
	items.forEach(function(it, i) {
		if (i) out.push(E('br'));
		out.push(typeof it == 'object' ? it : text(it));
	});
	return out;
}

// One bar per probe, scaled to the slowest answer; lost probes are red ticks.
function sparkline(samples) {
	var w = 360, h = 36, n = Math.max(samples.length, 1), bw = w / n, hi = 0;
	samples.forEach(function(s) { if (s.ok && s.rtt_ms > hi) hi = s.rtt_ms; });
	var bars = samples.map(function(s, i) {
		if (!s.ok)
			return svg('rect', { x: i * bw, y: 0, width: Math.max(bw, 1), height: h, fill: '#d23f31', 'fill-opacity': 0.35 });
		var bh = hi ? Math.max(1, s.rtt_ms / hi * h) : 1;
		return svg('rect', { x: i * bw, y: h - bh, width: Math.max(bw, 1), height: bh, fill: '#3478c6' });
	});
	return svg('svg', { width: w, height: h, viewBox: '0 0 ' + w + ' ' + h, preserveAspectRatio: 'none',
		style: 'max-width:100%;background:rgba(127,127,127,.08);vertical-align:middle' }, bars);
}

return view.extend({
	history: null,

	load: function() {
		return Promise.all([
			L.resolveDefault(callFlows(), { error: _('rpcd plugin not reachable') }),
			L.resolveDefault(callHistory(), {})
		]);
	},

	renderSummary: function(r) {
		var c = r.connections || {}, rows = [
			[ _('Version'), r.version ],
			[ _('Running for'), since(r.started_at) ],
			[ _('Default IPv4 / IPv6'), (r.default_ipv4 || _('none')) + ' / ' + (r.default_ipv6 || _('none')) ],
			[ _('New connections'), _('%s (excluded %s, local %s, unmarked %s)').format(count(c.new), count(c.excluded), count(c.local), count(c.unmarked)) ],
			[ _('Excluded prefixes'), this.ranges(r.exclude) ]
		];
		if (r.flows)
			rows.push([ _('Connections without a tunnel mark'), count(r.flows.other) ]);
		if (r.last_apply && r.last_apply.error)
			rows.push([ _('Last apply failed'), r.last_apply.error ]);
		(r.warnings || []).forEach(function(w) { rows.push([ _('Warning'), w ]); });
		return table([ _('Overview'), '' ], rows);
	},

	ranges: function(s) {
		if (!s || !s.prefixes)
			return _('none');
		var parts = [ _('%d prefixes').format(s.prefixes) ];
		if (s.ipv4_addresses) parts.push(_('%s IPv4 addresses').format(count(s.ipv4_addresses)));
		if (s.ipv6_64s) parts.push(_('%s IPv6 /64s').format(count(s.ipv6_64s)));
		if (s.prefixes && !s.ranges) parts.push(_('inactive'));
		return parts.join(', ');
	},

	renderTunnels: function(r) {
		var self = this, flows = (r.flows || {}).tunnels || {};
		return table([
			_('Tunnel'), _('State'), _('Latency'), _('New connections'), _('Active flows'), _('Traffic'), _('Static preferences')
		], r.tunnels.map(function(t) {
			var f = flows[t.name] || {}, defaults = [];
			if (r.default_ipv4 == t.name) defaults.push('IPv4');
			if (r.default_ipv6 == t.name) defaults.push('IPv6');
			var state = [ badge(t.state), _('link %s, %d/%d answered').format(t.link || '?', t.ok || 0, t.total || 0) ];
			if (defaults.length) state.push(_('default for %s').format(defaults.join(', ')));
			(t.errors || []).forEach(function(e) { state.push(E('small', {}, [ text(e) ])); });
			return [
				E('strong', {}, [ text(t.name) ]),
				lines(state),
				lines((t.latency || []).map(function(l) {
					return _('%s: %s (avg %s, jitter %s), %s%% lost').format(l.target, ms(l.last_ms), ms(l.avg_ms), ms(l.jitter_ms), l.loss_pct);
				})),
				lines([ _('%s static').format(count(t.connections_static)), _('%s default').format(count(t.connections_default)) ]),
				r.flows ? lines([ _('%s flows').format(count(f.flows)), _('%s destinations').format(count(f.destinations)) ]) : '–',
				lines([
					r.flows ? _('%s out / %s in').format(bytes(f.bytes_out), bytes(f.bytes_in)) : '',
					_('upstream %s, %s pkts').format(bytes((t.upstream || {}).bytes), count((t.upstream || {}).packets))
				]),
				self.ranges(t.static_ranges)
			];
		}));
	},

	renderLatency: function(r) {
		var hist = this.history;
		if (!hist || !hist.tunnels)
			return E('div');
		var rows = [];
		hist.tunnels.forEach(function(t) {
			(t.history || []).forEach(function(h) {
				var ok = h.samples.filter(function(s) { return s.ok; });
				var hi = ok.reduce(function(m, s) { return Math.max(m, s.rtt_ms); }, 0);
				rows.push([ t.name, h.target, sparkline(h.samples), ok.length ? _('max %s').format(ms(hi)) : _('no answers') ]);
			});
		});
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ text(_('RTT history')) ]),
			E('p', { 'class': 'cbi-section-descr' }, [ text(_('One bar per probe, oldest first, scaled per target; red marks a probe without an answer.')) ]),
			table([ _('Tunnel'), _('Target'), _('Last hour'), '' ], rows)
		]);
	},

	renderTop: function(r) {
		if (!r.flows)
			return E('div');
		var rows = [];
		r.tunnels.forEach(function(t) {
			((r.flows.tunnels[t.name] || {}).top || []).forEach(function(d) {
				rows.push([ t.name, d.addr, count(d.flows), bytes(d.bytes) ]);
			});
		});
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ text(_('Top destinations')) ]),
			E('p', { 'class': 'cbi-section-descr' }, [ text(_('Current conntrack entries per tunnel, by bytes in both directions.')) ]),
			rows.length ? table([ _('Tunnel'), _('Destination'), _('Flows'), _('Bytes') ], rows) : E('em', {}, [ text(_('No flows.')) ])
		]);
	},

	renderReport: function(r) {
		if (r.error)
			return E('div', { 'class': 'alert-message warning' }, [
				E('p', {}, [ text(_('tunsel is not running or not reachable:')) ]),
				E('pre', {}, [ text(r.error) ]),
				E('p', {}, [ E('a', { href: L.url('admin/services/tunsel/config') }, [ text(_('Check the configuration')) ]) ])
			]);
		return E('div', {}, [
			E('div', { 'class': 'cbi-section' }, [ this.renderSummary(r) ]),
			E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ text(_('Tunnels')) ]), this.renderTunnels(r) ]),
			this.renderLatency(r),
			this.renderTop(r)
		]);
	},

	render: function(data) {
		var self = this, node = E('div'), last = data[0], polls = 0;
		this.history = data[1];
		dom.content(node, this.renderReport(last));

		poll.add(function() {
			// The history only gains one sample per probe interval.
			var history = (++polls % 6 == 0) ? L.resolveDefault(callHistory(), self.history) : Promise.resolve(self.history);
			return Promise.all([ L.resolveDefault(callFlows(), { error: _('rpcd plugin not reachable') }), history ]).then(function(res) {
				self.history = res[1];
				dom.content(node, self.renderReport(res[0]));
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
