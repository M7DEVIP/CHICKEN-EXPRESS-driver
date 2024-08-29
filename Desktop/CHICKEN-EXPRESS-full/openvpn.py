import os

def run_command(command):
    print(f"Running: {command}")
    os.system(command)

def setup_openvpn():
    # Create necessary directories
    openvpn_ca_dir = os.path.expanduser('~/openvpn-ca')
    if not os.path.exists(openvpn_ca_dir):
        os.makedirs(openvpn_ca_dir)
    run_command(f'make-cadir {openvpn_ca_dir}')
    os.chdir(openvpn_ca_dir)

    # Source vars
    with open('vars', 'a') as vars_file:
        vars_file.write("\nexport KEY_COUNTRY='US'\nexport KEY_PROVINCE='CA'\nexport KEY_CITY='SanFrancisco'\nexport KEY_ORG='MyOrg'\nexport KEY_EMAIL='email@example.com'\nexport KEY_OU='MyOU'\nexport KEY_NAME='server'\n")

    run_command('source vars')
    run_command('./clean-all')
    run_command('./build-ca --batch')

    # Build server key and certificate
    run_command('./build-key-server --batch server')
    run_command('./build-dh')
    run_command('openvpn --genkey --secret keys/ta.key')

    # Copy server config
    run_command('sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz /etc/openvpn/')
    os.chdir('/etc/openvpn/')
    run_command('sudo gunzip server.conf.gz')

    # Edit server.conf
    with open('server.conf', 'a') as server_conf:
        server_conf.write("\nca /etc/openvpn/ca.crt\ncert /etc/openvpn/server.crt\nkey /etc/openvpn/server.key\ndh /etc/openvpn/dh2048.pem\ntls-auth /etc/openvpn/ta.key 0\ncipher AES-256-CBC\nauth SHA256\n")

    # Copy keys to /etc/openvpn/
    run_command('sudo cp ~/openvpn-ca/keys/ca.crt /etc/openvpn/')
    run_command('sudo cp ~/openvpn-ca/keys/server.crt /etc/openvpn/')
    run_command('sudo cp ~/openvpn-ca/keys/server.key /etc/openvpn/')
    run_command('sudo cp ~/openvpn-ca/keys/dh2048.pem /etc/openvpn/')
    run_command('sudo cp ~/openvpn-ca/keys/ta.key /etc/openvpn/')

    # Enable and start OpenVPN service
    run_command('sudo systemctl start openvpn@server')
    run_command('sudo systemctl enable openvpn@server')

if __name__ == "__main__":
    setup_openvpn()
