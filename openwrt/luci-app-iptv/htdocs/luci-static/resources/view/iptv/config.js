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

		o = s.option(form.Value, 'user', _('User'));
		o.rmempty = false;

		o = s.option(form.Value, 'passwd', _('Password'));
		o.password = true;
		o.rmempty = false;

		o = s.option(form.Value, 'mac', _('MAC address'));
		o.placeholder = '00:11:22:33:44:55';
		o.rmempty = false;

		o = s.option(form.Value, 'imei', _('IMEI'));

		s = m.section(form.NamedSection, 'main', 'service', _('Authentication'));
		s.anonymous = true;

		o = s.option(form.Value, 'auth_token', _('API token'));
		o.password = true;

		o = s.option(form.DynamicList, 'auth_protect', _('Protected endpoints'));
		o.value('playlist', _('Playlist'));
		o.value('xmltv', _('XMLTV'));
		o.value('manage', _('Management'));
		o.value('status', _('Status'));

		s = m.section(form.NamedSection, 'main', 'service', _('FCC'));
		s.anonymous = true;

		o = s.option(form.Flag, 'fcc_enabled', _('Enable FCC'));
		o.rmempty = false;

		o = s.option(form.Value, 'fcc_signaling_timeout_ms', _('Signaling timeout'));
		o.datatype = 'uinteger';
		o.placeholder = '80';

		o = s.option(form.Value, 'fcc_unicast_idle_timeout_ms', _('Unicast idle timeout'));
		o.datatype = 'uinteger';
		o.placeholder = '1000';

		o = s.option(form.Value, 'fcc_max_redirects', _('Max redirects'));
		o.datatype = 'uinteger';
		o.placeholder = '5';

		o = s.option(form.Value, 'fcc_startup_buffer_ms', _('Startup buffer time'));
		o.datatype = 'uinteger';
		o.placeholder = '300';

		o = s.option(form.Value, 'fcc_startup_buffer_packets', _('Startup buffer packets'));
		o.datatype = 'uinteger';
		o.placeholder = '48';

		o = s.option(form.Value, 'fcc_switch_extra_packets', _('Switch extra packets'));
		o.datatype = 'uinteger';
		o.placeholder = '64';

		o = s.option(form.Value, 'fcc_switch_min_unicast_ms', _('Minimum unicast time'));
		o.datatype = 'uinteger';
		o.placeholder = '500';

		s = m.section(form.NamedSection, 'main', 'service', _('Extra sources'));
		s.anonymous = true;

		o = s.option(form.DynamicList, 'extra_playlist', _('Extra playlists'));
		o.datatype = 'url';

		o = s.option(form.DynamicList, 'extra_xmltv', _('Extra XMLTV'));
		o.datatype = 'url';

		s = m.section(form.NamedSection, 'main', 'service', _('Playlist rules'));
		s.anonymous = true;

		o = s.option(form.ListValue, 'alias_mode', _('Alias mode'));
		o.value('first_match', _('First match'));
		o.value('chain', _('Chain'));

		o = s.option(form.Value, 'default_group', _('Default group'));

		o = s.option(form.DynamicList, 'same_alias', _('Same alias sort order'));
		o.value('resolution_desc', _('Resolution score'));
		o.value('prefer_resolution', _('Preferred labels'));
		o.value('source_priority', _('Source priority'));
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
