'use strict';
'require view';
'require form';
'require uci';
'require tools.widgets as widgets';

// Mirrors the UCI schema read by the daemon (internal/config/uci.go). The
// daemon validates everything again on reload; these checks only catch
// typos early.

function number(section_id, value) {
	if (value == '' || /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value))
		return true;
	return _('Expecting a number, e.g. 0x1 or 1');
}

function duration(section_id, value) {
	if (value == '' || /^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$/.test(value))
		return true;
	return _('Expecting a duration, e.g. 10s or 500ms');
}

function probe(section_id, value) {
	if (value == '' || value == 'icmp' || /^tcp:[0-9]+$/.test(value))
		return true;
	return _('Expecting icmp or tcp:<port>');
}

return view.extend({
	load: function() {
		return uci.load('tunsel');
	},

	render: function() {
		var m, s, o;

		m = new form.Map('tunsel', _('tunsel'),
			_('Health-aware selection between VPN tunnels. Per tunnel, the router must provide a routing table with a default route via the tunnel and a rule <code>fwmark &lt;mark&gt;/&lt;mark mask&gt; lookup &lt;table&gt;</code>. Unmarked traffic falls through to normal routing.'));

		s = m.section(form.NamedSection, 'main', 'tunsel', _('General'));
		s.addremove = false;
		s.tab('general', _('General'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.taboption('general', form.DynamicList, 'default_order', _('Default order'),
			_('Tunnel interfaces; the first healthy one carries traffic without a static preference.'));
		uci.sections('tunsel', 'tunnel', function(t) {
			if (t.iface)
				o.value(t.iface);
		});

		o = s.taboption('general', widgets.DeviceSelect, 'ingress', _('Ingress devices'),
			_('Only traffic entering on these devices is steered.'));
		o.multiple = true;
		o.noaliases = true;

		o = s.taboption('general', form.Flag, 'include_local_output', _('Steer router traffic'),
			_('Also steer connections the router itself opens.'));

		o = s.taboption('general', form.DynamicList, 'exclude', _('Exclude'),
			_('Destinations that are never steered, e.g. tunnel endpoints and private ranges.'));
		o.datatype = 'or(cidr,ipaddr)';

		o = s.taboption('advanced', form.Value, 'mark_mask', _('Mark mask'),
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

		o = s.taboption('advanced', form.Flag, 'cleanup_on_exit', _('Remove table on stop'),
			_('Restores plain host routing when the service stops.'));

		o = s.taboption('advanced', form.ListValue, 'log_level', _('Log level'));
		['debug', 'info', 'warn', 'error'].forEach(function(l) { o.value(l); });
		o.default = 'info';

		o = s.taboption('advanced', form.ListValue, 'log_format', _('Log format'));
		o.value('text');
		o.value('json');
		o.default = 'text';

		o = s.taboption('advanced', form.Value, 'socket', _('Status socket'),
			_('Changes take effect after a restart.'));
		o.placeholder = '/run/tunsel/tunsel.sock';
		o.datatype = 'string';

		s = m.section(form.GridSection, 'tunnel', _('Tunnels'));
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.tab('general', _('General'));
		s.tab('health', _('Health check'));
		s.tab('static', _('Static preferences'));

		o = s.taboption('general', widgets.DeviceSelect, 'iface', _('Interface'));
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
		o.textvalue = function(section_id) {
			var v = L.toArray(this.cfgvalue(section_id));
			return v.length ? v.join(', ') : _('both');
		};

		o = s.taboption('health', form.DynamicList, 'target', _('Targets'),
			_('Addresses probed through the tunnel.'));
		o.datatype = 'ipaddr';
		o.rmempty = false;
		o.modalonly = true;

		o = s.taboption('health', form.Value, 'probe', _('Probe'),
			_('<code>icmp</code> or <code>tcp:&lt;port&gt;</code> (a handshake or a reset counts as an answer).'));
		o.value('icmp', _('ICMP echo'));
		o.value('tcp:443', _('TCP port 443'));
		o.placeholder = 'icmp';
		o.validate = probe;

		o = s.taboption('health', form.Value, 'interval', _('Interval'));
		o.placeholder = '10s';
		o.validate = duration;
		o.modalonly = true;

		o = s.taboption('health', form.Value, 'timeout', _('Timeout'));
		o.placeholder = '2s';
		o.validate = duration;
		o.modalonly = true;

		o = s.taboption('health', form.Value, 'min_ok', _('Answers needed'),
			_('Targets that must answer for a round to pass.'));
		o.placeholder = '1';
		o.datatype = 'uinteger';
		o.modalonly = true;

		o = s.taboption('health', form.Value, 'fail_after', _('Fail after'),
			_('Consecutive failed rounds before the tunnel is unhealthy.'));
		o.placeholder = '3';
		o.datatype = 'uinteger';
		o.modalonly = true;

		o = s.taboption('health', form.Value, 'recover_after', _('Recover after'),
			_('Consecutive passed rounds before the tunnel is healthy again.'));
		o.placeholder = '3';
		o.datatype = 'uinteger';
		o.modalonly = true;

		o = s.taboption('static', form.DynamicList, 'prefer', _('Preferred prefixes'),
			_('Routed via this tunnel while it is healthy; more specific prefixes of other tunnels win.'));
		o.datatype = 'or(cidr,ipaddr)';
		o.modalonly = true;

		return m.render();
	}
});
