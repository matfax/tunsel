'use strict';
'require view';
'require form';
'require uci';
'require tools.widgets as widgets';

// Provided by LuCI's loader: the modules required above, plus L (and _,
// which ESLint already knows).
/* global L, form, uci, view, widgets */

// Mirrors the UCI schema read by the daemon (internal/config/uci.go). The
// daemon validates everything again on reload; these checks only catch
// typos early.

// One Go duration term, e.g. "1.5s"; a duration is one or more of them.
// Without nested quantifiers, so matching stays linear.
const DURATION_TERM = /\d+\.?\d*(?:ns|us|µs|ms|s|m|h)/y;

function number(_sid, value) {
	if (value === '' || /^(?:0x[\da-fA-F]+|\d+)$/.test(value))
		return true;
	return _('Expecting a number, e.g. 0x1 or 1');
}

function isDuration(value) {
	DURATION_TERM.lastIndex = 0;
	while (DURATION_TERM.lastIndex < value.length)
		if (!DURATION_TERM.test(value))
			return false;
	return true;
}

function duration(_sid, value) {
	if (value === '' || isDuration(value))
		return true;
	return _('Expecting a duration, e.g. 10s or 500ms');
}

function percent(_sid, value) {
	if (value === '' || /^\d+\.?\d*%$/.test(value))
		return true;
	return _('Expecting a percentage, e.g. 15%');
}

function probe(_sid, value) {
	if (value === '' || value === 'icmp' || /^tcp:\d+$/.test(value))
		return true;
	return _('Expecting icmp or tcp:PORT');
}

function generalOptions(s) {
	let o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
	o.rmempty = false;

	o = s.taboption('general', form.DynamicList, 'default_order', _('Default order'),
		_('Tunnel interfaces; the first healthy one carries traffic without a static preference.'));
	for (const t of uci.sections('tunsel', 'tunnel'))
		if (t.iface)
			o.value(t.iface);

	o = s.taboption('general', widgets.DeviceSelect, 'ingress', _('Ingress devices'),
		_('Only traffic entering on these devices is steered.'));
	o.multiple = true;
	o.noaliases = true;

	s.taboption('general', form.Flag, 'include_local_output', _('Steer router traffic'),
		_('Also steer connections the router itself opens.'));

	o = s.taboption('general', form.DynamicList, 'exclude', _('Exclude'),
		_('Destinations that are never steered, e.g. tunnel endpoints and private ranges.'));
	o.datatype = 'or(cidr,ipaddr)';
}

function advancedOptions(s) {
	let o = s.taboption('advanced', form.Value, 'mark_mask', _('Mark mask'),
		_('Only these firewall mark bits are read and written.'));
	o.placeholder = '0xf';
	o.rmempty = false;
	o.validate = number;

	o = s.taboption('advanced', form.Flag, 'flush_on_unhealthy', _('Flush failed tunnels'),
		_('Delete the conntrack entries of a tunnel that becomes unhealthy, so its flows are decided anew.'));
	o.default = o.enabled;

	o = s.taboption('advanced', form.Value, 'table', _('nftables table'));
	o.placeholder = 'tunsel';
	o.datatype = 'and(minlength(1),maxlength(64))';

	s.taboption('advanced', form.Flag, 'cleanup_on_exit', _('Remove table on stop'),
		_('Restores plain host routing when the service stops.'));

	o = s.taboption('advanced', form.ListValue, 'log_level', _('Log level'));
	for (const l of [ 'debug', 'info', 'warn', 'error' ])
		o.value(l);
	o.default = 'info';

	o = s.taboption('advanced', form.ListValue, 'log_format', _('Log format'));
	o.value('text');
	o.value('json');
	o.default = 'text';

	o = s.taboption('advanced', form.Value, 'socket', _('Status socket'),
		_('Changes take effect after a restart.'));
	o.placeholder = '/run/tunsel/tunsel.sock';
	o.datatype = 'string';
}

// Phase 2 parameters (design §7). The switch itself is left out until
// learning is implemented; the daemon rejects learning=1.
function learningOptions(s) {
	const value = (name, title, description, placeholder, check) => {
		const o = s.taboption('learning', form.Value, name, title, description);
		o.placeholder = placeholder;
		if (typeof check === 'function')
			o.validate = check;
		else
			o.datatype = check;
		return o;
	};
	const count = 'and(uinteger,min(1))';

	value('learn_top_n', _('Destinations per refresh'),
		_('The busiest destinations by bytes that have no learned tunnel yet are measured.'), '100', count);
	value('learn_refresh', _('Refresh interval'), null, '5m', duration);
	value('learn_port', _('Probe port'),
		_('TCP handshake time to this port via each healthy tunnel.'), '443', 'port');
	value('learn_samples', _('Samples'), _('Handshakes per tunnel; the median counts.'), '3', count);
	value('learn_timeout', _('Probe timeout'), null, '2s', duration);
	value('learn_min_gain_abs', _('Minimum gain'),
		_('A tunnel replaces the current choice only if it is faster by this much…'), '5ms', duration);
	value('learn_min_gain_rel', _('Minimum relative gain'), _('…and by this share.'), '15%', percent);
	value('learn_ttl', _('Lifetime'),
		_('How long a learned tunnel is kept; the destination is measured again only after it expires.'), '1h', duration);
	value('learn_damp_window', _('Damping window'), null, '30m', duration);
	value('learn_damp_max_switches', _('Switches per window'),
		_('At most this many tunnel changes per destination within the damping window.'), '2', count);
}

function tunnelGeneralOptions(s) {
	let o = s.taboption('general', widgets.DeviceSelect, 'iface', _('Interface'));
	o.noaliases = true;
	o.rmempty = false;

	o = s.taboption('general', form.Value, 'mark', _('Mark'),
		_('Unique, non-zero, within the mark mask.'));
	o.placeholder = '0x1';
	o.rmempty = false;
	o.validate = number;

	o = s.taboption('general', form.MultiValue, 'family', _('Families'),
		_('Families the tunnel carries; both if none is selected.'));
	o.value('ipv4', 'IPv4');
	o.value('ipv6', 'IPv6');
	o.placeholder = _('both');
	o.textvalue = function(sid) {
		const v = L.toArray(this.cfgvalue(sid));
		return v.length ? v.join(', ') : _('both');
	};

	o = s.taboption('static', form.DynamicList, 'prefer', _('Preferred prefixes'),
		_('Routed via this tunnel while it is healthy; more specific prefixes of other tunnels win.'));
	o.datatype = 'or(cidr,ipaddr)';
	o.modalonly = true;
}

// Adds a modal-only health option with a placeholder and a check.
function healthValue(s, name, title, description, placeholder, check) {
	const o = s.taboption('health', form.Value, name, title, description);
	o.placeholder = placeholder;
	if (typeof check === 'function')
		o.validate = check;
	else
		o.datatype = check;
	o.modalonly = true;
	return o;
}

function tunnelHealthOptions(s) {
	const o = s.taboption('health', form.DynamicList, 'target', _('Targets'),
		_('Addresses probed through the tunnel.'));
	o.datatype = 'ipaddr';
	o.rmempty = false;
	o.modalonly = true;

	const p = s.taboption('health', form.Value, 'probe', _('Probe'),
		_('icmp, or tcp:PORT (a handshake or a reset counts as an answer).'));
	p.value('icmp', _('ICMP echo'));
	p.value('tcp:443', _('TCP port 443'));
	p.placeholder = 'icmp';
	p.validate = probe;

	healthValue(s, 'interval', _('Interval'), null, '10s', duration);
	healthValue(s, 'timeout', _('Timeout'), null, '2s', duration);
	healthValue(s, 'min_ok', _('Answers needed'), _('Targets that must answer for a round to pass.'), '1', 'uinteger');
	healthValue(s, 'fail_after', _('Fail after'), _('Consecutive failed rounds before the tunnel is unhealthy.'), '3', 'uinteger');
	healthValue(s, 'recover_after', _('Recover after'), _('Consecutive passed rounds before the tunnel is healthy again.'), '3', 'uinteger');
}

return view.extend({
	load: () => uci.load('tunsel'),

	render: () => {
		const m = new form.Map('tunsel', _('Tunsel'),
			_('Health-aware selection between VPN tunnels. Per tunnel, the router must provide a routing table with a default route via the tunnel and a rule "fwmark MARK/MASK lookup TABLE". Unmarked traffic falls through to normal routing.'));

		const main = m.section(form.NamedSection, 'main', 'tunsel', _('General'));
		main.addremove = false;
		main.tab('general', _('General'));
		main.tab('advanced', _('Advanced'));
		main.tab('learning', _('Latency learning'),
			_('Per-destination selection of the fastest tunnel. Not active yet: this version stores these settings but does not learn.'));
		generalOptions(main);
		advancedOptions(main);
		learningOptions(main);

		const tunnels = m.section(form.GridSection, 'tunnel', _('Tunnels'));
		tunnels.addremove = true;
		tunnels.anonymous = true;
		tunnels.nodescriptions = true;
		tunnels.tab('general', _('General'));
		tunnels.tab('health', _('Health check'));
		tunnels.tab('static', _('Static preferences'));
		tunnelGeneralOptions(tunnels);
		tunnelHealthOptions(tunnels);

		return m.render();
	}
});
