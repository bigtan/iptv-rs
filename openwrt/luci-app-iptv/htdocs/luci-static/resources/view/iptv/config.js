'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function serviceStatus() {
	return callServiceList('iptv').then(function(res) {
		var service = res['iptv'];
		var instances = service && service.instances ? service.instances : {};

		for (var name in instances) {
			if (instances[name].running)
				return _('Running');
		}

		return _('Stopped');
	});
}

return L.view.extend({
	load: function() {
		return Promise.all([
			uci.load('iptv'),
			serviceStatus()
		]);
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('iptv', _('IPTV'));

		s = m.section(form.NamedSection, 'main', 'service', _('Service'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_status', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			return E('span', { 'class': 'ifacebadge' }, [ data[1] ]);
		};

		o = s.option(form.Button, '_restart', _('Apply restart'));
		o.inputtitle = _('Restart service');
		o.inputstyle = 'apply';
		o.onclick = function() {
			return m.save().then(function() {
				return callInitAction('iptv', 'restart');
			}).then(function() {
				ui.addNotification(null, E('p', _('IPTV restarted.')));
			});
		};

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		o = s.option(form.Value, 'bind', _('Bind address'));
		o.placeholder = '[::]:7088';

		o = s.option(form.Value, 'bind_interface', _('Bind interface'));
		o.placeholder = 'br-lan';
		o.rmempty = true;
		o.description = _('Restrict HTTP listening to a LAN interface (such as br-lan) via SO_BINDTODEVICE to prevent exposure on WAN or IPTV interfaces.');

		o = s.option(form.Value, 'workers', _('Worker threads'));
		o.datatype = 'min(1)';
		o.placeholder = '2';
		o.rmempty = true;
		o.description = _('HTTP server worker thread count. Defaults to CPU core count when empty.');

		o = s.option(form.Value, 'interface', _('IPTV interface'));
		o.placeholder = 'pppoe-iptv';

		o = s.option(form.Value, 'address', _('Local address or interface'));

		o = s.option(form.Flag, 'udp_proxy', _('UDP proxy'));
		o.rmempty = false;

		o = s.option(form.Flag, 'rtsp_proxy', _('RTSP proxy'));
		o.rmempty = false;

		o = s.option(form.Flag, 'manage_enabled', _('Management endpoints'));
		o.rmempty = false;

		s = m.section(form.NamedSection, 'main', 'service', _('Account'));
		s.anonymous = true;
		s.description = _('Upstream IPTV account credentials. Leave User, Password, and MAC empty to run in standalone UDP/RTSP proxy-only mode.');

		o = s.option(form.Value, 'user', _('User'));
		o.rmempty = true;

		o = s.option(form.Value, 'passwd', _('Password'));
		o.password = true;
		o.rmempty = true;

		o = s.option(form.Value, 'mac', _('MAC address'));
		o.placeholder = '00:11:22:33:44:55';
		o.rmempty = true;

		o = s.option(form.Value, 'imei', _('IMEI'));

		s = m.section(form.NamedSection, 'main', 'service', _('Authentication'));
		s.anonymous = true;

		o = s.option(form.Value, 'auth_token', _('API token'));
		o.password = true;

		o = s.option(form.DynamicList, 'auth_protect', _('Protected endpoints'));
		o.value('playlist', 'playlist');
		o.value('xmltv', 'xmltv');
		o.value('manage', 'manage');
		o.value('status', 'status');
		o.value('rtsp', 'rtsp');
		o.value('udp', 'udp');
		o.value('logo', 'logo');

		s = m.section(form.NamedSection, 'main', 'service', _('FCC'));
		s.anonymous = true;

		o = s.option(form.Flag, 'fcc_enabled', _('Enable FCC'));
		o.rmempty = false;

		o = s.option(form.Value, 'fcc_max_redirects', _('Max redirects'));
		o.datatype = 'uinteger';
		o.placeholder = '5';

		o = s.option(form.Value, 'fcc_switch_extra_packets', _('Switch extra packets'));
		o.datatype = 'uinteger';
		o.placeholder = '64';
		o.description = _('Request the FCC server to continue unicast this many RTP sequence numbers past the first multicast packet. Local handoff still switches at multicast overlap or the stall/deadline fallback.');

		o = s.option(form.Value, 'fcc_switch_min_unicast_ms', _('Minimum unicast time'));
		o.datatype = 'uinteger';
		o.placeholder = '500';
		o.description = _('Minimum FCC unicast duration (ms) that FCC_TERM and overlap handoff wait before seamlessly switching to multicast. Stall, buffer-cap, and deadline fallbacks may switch earlier if needed.');

		s = m.section(form.NamedSection, 'main', 'service', _('Playlist rules'));
		s.anonymous = true;

		o = s.option(form.ListValue, 'alias_mode', _('Alias mode'));
		o.value('first_match', _('First match'));
		o.value('chain', _('Chain'));

		o = s.option(form.Value, 'default_group', _('Default group'));

		o = s.option(form.DynamicList, 'same_alias', _('Same alias sort order'));
		o.value('resolution_desc', _('Resolution score'));
		o.value('prefer_resolution', _('Preferred labels'));
		o.value('original', _('Original order'));

		o = s.option(form.DynamicList, 'prefer_resolution', _('Preferred resolution labels'));
		o.placeholder = 'R4K Uhd Fhd Hd Sd Unknown';

		o = s.option(form.Flag, 'xmltv_use_alias_name', _('Use alias names in XMLTV'));
		o.rmempty = false;

		s = m.section(form.GridSection, 'alias_rule', _('Alias rules'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('regex', _('Regular expression'));
		o.value('map', _('Exact map'));
		o.default = 'regex';

		o = s.option(form.Value, 'pattern', _('Pattern'));
		o.rmempty = false;

		o = s.option(form.Value, 'replace', _('Replacement'));
		o.rmempty = false;

		s = m.section(form.GridSection, 'resolution_rule', _('Resolution rules'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'pattern', _('Pattern'));
		o.rmempty = false;

		o = s.option(form.Value, 'score', _('Score'));
		o.datatype = 'integer';
		o.rmempty = false;

		o = s.option(form.Value, 'label', _('Label'));

		s = m.section(form.GridSection, 'group', _('Groups'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Value, 'group', _('Group'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'channels', _('Channels'));

		o = s.option(form.Value, 'match_regex', _('Match regular expression'));

		poll.add(function() {
			return serviceStatus().then(function(status) {
				var node = document.querySelector('[data-name="_status"] .ifacebadge');
				if (node)
					node.textContent = status;
			});
		});

		return m.render();
	}
});
