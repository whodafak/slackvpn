#!/bin/bash
#
# https://github.com/whodafak/slackvpn
#
# Thanks to Nyr (If you want to buy him coffe https://www.paypal.com/donate/?cmd=_s-xclick&hosted_button_id=VBAYDL34Z7J6L ) for this great script. Here is slackware version. Currently tested and working on
# Slackware 15.0. Big thanks to Slackware team.. please if you find this scipt usefull consider donating to slackware project at : http://arm.slackware.com/sponsor/
# you can Donate directly to Patrick Volkerding (Supporting x86 Slackware)  or Stuart Winter (Supporting ARM / AArch64 Slackware)


# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if [[ -e /etc/slackware-version ]]; then
	if [[ -e /etc/rc.d/rc.local || -x /etc/rc.d/rc.local ]]; then
		rclocal='/etc/rc.d/rc.local'
		chmod +x $rclocal
		group_name=nobody
	fi
else
	echo "Who is the oldest linux system and why you are not using it?"
	exit
fi
if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

# Check if a package is installed.  Return 1 if it is otherwise return 0.
installed() {
	if ls /var/log/packages/$1* 1> /dev/null 2>&1; then
		return 1
	else
		return 0
	fi
}

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
	TUN needs to be enabled before running this installer."
	exit
fi

# ============================================================
# OpenVPN functions
# ============================================================

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/tc.key
	echo "</tls-crypt>"
	echo "iroute 10.8.0.0 255.255.255.0" > /etc/openvpn/ccd/"$client"
	} > ~/"$client".ovpn
}

# ============================================================
# WireGuard functions
# ============================================================

new_wg_client () {
	# Generate client key pair
	wg_client_private=$(wg genkey)
	wg_client_public=$(echo "$wg_client_private" | wg pubkey)
	wg_client_psk=$(wg genpsk)

	# Find next available IP in 10.9.0.0/24
	octet=2
	while grep -q "AllowedIPs = 10.9.0.$octet/32" /etc/wireguard/wg0.conf 2>/dev/null; do
		(( octet++ ))
	done
	wg_client_ip="10.9.0.$octet"

	# Assign an IPv6 client address if the server has IPv6
	if grep -q 'fddd:9090:9090:9090' /etc/wireguard/wg0.conf 2>/dev/null; then
		# Find next available IPv6 octet matching the IPv4 octet
		wg_client_ip6="fddd:9090:9090:9090::$octet"
		wg_client_allowed="$wg_client_ip/32, $wg_client_ip6/128"
		wg_client_addr="$wg_client_ip/32, $wg_client_ip6/128"
		wg_client_routes="0.0.0.0/0, ::/0"
	else
		wg_client_ip6=""
		wg_client_allowed="$wg_client_ip/32"
		wg_client_addr="$wg_client_ip/32"
		wg_client_routes="0.0.0.0/0"
	fi

	# Append peer to server config
	echo "
[Peer]
# $wg_client
PublicKey = $wg_client_public
PresharedKey = $wg_client_psk
AllowedIPs = $wg_client_allowed" >> /etc/wireguard/wg0.conf

	# Reload WireGuard to pick up new peer (non-disruptive)
	if wg show wg0 &>/dev/null; then
		wg addconf wg0 <(echo "[Peer]
PublicKey = $wg_client_public
PresharedKey = $wg_client_psk
AllowedIPs = $wg_client_allowed")
	fi

	# Determine DNS to push in client config
	case "$wg_dns" in
		1|"") wg_dns_line=$(grep '^nameserver' /etc/resolv.conf | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -2 | tr '\n' ',' | sed 's/,$//') ;;
		2) wg_dns_line="8.8.8.8, 8.8.4.4" ;;
		3) wg_dns_line="1.1.1.1, 1.0.0.1" ;;
		4) wg_dns_line="208.67.222.222, 208.67.220.220" ;;
		5) wg_dns_line="9.9.9.9, 149.112.112.112" ;;
		6) wg_dns_line="94.140.14.14, 94.140.15.15" ;;
	esac

	# Read server public key
	wg_server_public=$(cat /etc/wireguard/server_public.key)
	# Get endpoint
	wg_endpoint_ip=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d' ' -f3)
	wg_port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | awk '{print $3}')

	# Generate client config file
	cat > ~/"$wg_client".conf << EOF
[Interface]
Address = $wg_client_addr
DNS = $wg_dns_line
PrivateKey = $wg_client_private

[Peer]
PublicKey = $wg_server_public
PresharedKey = $wg_client_psk
Endpoint = $wg_endpoint_ip:$wg_port
AllowedIPs = $wg_client_routes
PersistentKeepalive = 25
EOF
}

# ============================================================
# Determine which VPN to work with
# ============================================================

openvpn_installed=0
wireguard_installed=0
[[ -e /etc/openvpn/server.conf ]] && openvpn_installed=1
[[ -e /etc/wireguard/wg0.conf ]] && wireguard_installed=1

if [[ "$openvpn_installed" -eq 0 && "$wireguard_installed" -eq 0 ]]; then
	# Fresh install — ask which VPN to install
	clear
	echo "Welcome to the Slackware VPN installer!"
	echo
	echo "Which VPN would you like to install?"
	echo "   1) OpenVPN"
	echo "   2) WireGuard"
	read -p "VPN [1]: " vpn_choice
	until [[ -z "$vpn_choice" || "$vpn_choice" =~ ^[12]$ ]]; do
		echo "$vpn_choice: invalid selection."
		read -p "VPN [1]: " vpn_choice
	done
	[[ -z "$vpn_choice" ]] && vpn_choice="1"
elif [[ "$openvpn_installed" -eq 1 && "$wireguard_installed" -eq 0 ]]; then
	vpn_choice="1"
elif [[ "$openvpn_installed" -eq 0 && "$wireguard_installed" -eq 1 ]]; then
	vpn_choice="2"
else
	# Both installed — ask which to manage
	clear
	echo "Both OpenVPN and WireGuard are installed."
	echo
	echo "Which VPN would you like to manage?"
	echo "   1) OpenVPN"
	echo "   2) WireGuard"
	read -p "VPN [1]: " vpn_choice
	until [[ -z "$vpn_choice" || "$vpn_choice" =~ ^[12]$ ]]; do
		echo "$vpn_choice: invalid selection."
		read -p "VPN [1]: " vpn_choice
	done
	[[ -z "$vpn_choice" ]] && vpn_choice="1"
fi

# ============================================================
# OPENVPN BRANCH
# ============================================================

if [[ "$vpn_choice" -eq 1 ]]; then

	if [[ ! -e /etc/openvpn/server.conf ]]; then

		clear
		echo 'Welcome to this OpenVPN road warrior installer!'
		# If system has a single IPv4, it is selected automatically. Else, ask the user
		if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
		else
			number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
			echo
			echo "Which IPv4 address should be used?"
			ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
			read -p "IPv4 address [1]: " ip_number
			until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
				echo "$ip_number: invalid selection."
				read -p "IPv4 address [1]: " ip_number
			done
			[[ -z "$ip_number" ]] && ip_number="1"
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
		fi
		# If $ip is a private IP address, the server must be behind NAT
		if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			echo
			echo "This server is behind NAT. What is the public IPv4 address or hostname?"
			get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
			read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
			until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
				echo "Invalid input."
				read -p "Public IPv4 address / hostname: " public_ip
			done
			[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
		fi
		# If system has a single IPv6, it is selected automatically
		if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
			ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
		fi
		# If system has multiple IPv6, ask the user to select one
		if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
			number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
			echo
			echo "Which IPv6 address should be used?"
			ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
			read -p "IPv6 address [1]: " ip6_number
			until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
				echo "$ip6_number: invalid selection."
				read -p "IPv6 address [1]: " ip6_number
			done
			[[ -z "$ip6_number" ]] && ip6_number="1"
			ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
		fi
		echo
		echo "Which protocol should OpenVPN use?"
		echo "   1) UDP (recommended)"
		echo "   2) TCP"
		read -p "Protocol [1]: " protocol
		until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
			echo "$protocol: invalid selection."
			read -p "Protocol [1]: " protocol
		done
		case "$protocol" in
			1|"")
			protocol=udp
			;;
			2)
			protocol=tcp
			;;
		esac
		echo
		echo "What port should OpenVPN listen to?"
		read -p "Port [1194]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -p "Port [1194]: " port
		done
		[[ -z "$port" ]] && port="1194"
		echo
		echo "Select a DNS server for the clients:"
		echo "   1) Current system resolvers"
		echo "   2) Google"
		echo "   3) 1.1.1.1"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard"
		read -p "DNS server [1]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
			echo "$dns: invalid selection."
			read -p "DNS server [1]: " dns
		done
		echo
		echo "Enter a name for the first client:"
		read -p "Name [client]: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
		[[ -z "$client" ]] && client="client"
		echo
		echo "OpenVPN installation is ready to begin."
		# Check that we have all necessary packages installed
		for pkg in "openvpn" "iptables" "openssl" "ca-certificates"
		do
			installed $pkg
			pkginstalled=$?

			if [ $pkginstalled -eq 0 ]; then
				pkgs+="$pkg "
			fi
		done

		if [[ -n $pkgs ]]; then
			echo "The following packages are not installed"
			echo "     $pkgs"
			read -p "Do you want to install them [Y/n]? " -e -i "Y" answer

			if [ $answer == "Y" ]; then
				slackpkg install $pkgs
			else
				echo "Cannot continue without all necessary packages."
				echo "Aborting!"
				exit 4
			fi
		fi
		# Get easy-rsa
		easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
		mkdir -p /etc/openvpn/easy-rsa/
		mkdir -p /etc/openvpn/ccd/
		mkdir -p /etc/iptables/
		{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/easy-rsa/ --strip-components 1
		chown -R root:root /etc/openvpn/easy-rsa/
		cd /etc/openvpn/easy-rsa/
		# Create the PKI, set up the CA and the server and client certificates
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		# Move the stuff we need
		cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/
		# CRL is read with each client connection, while OpenVPN is dropped to nobody
		chown nobody:"$group_name" /etc/openvpn/crl.pem
		# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
		chmod o+x /etc/openvpn/
		# Generate key for tls-crypt
		openvpn --genkey secret /etc/openvpn/tc.key
		# Create the DH parameters file using the predefined ffdhe2048 group
		echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAquPY/dyCUaxh2CQgMh9KwR/4UcuNU1HDqfsp5/+GNlGk0SVfUmf2
LM1NEwDT/rdnyd4c3OWPvanGVi3g4aWa/sJWqi7SSmcBOjKIcOtXjhk84zmBqw0t
5wLZ8q4nJbzTKdnDjT5LyymIgiwRXCgz/g+5VFkiv+Jdn6xAxRfSU+majqFNVumM
ZtvCF8aLl/CTN2BaF+rfPk1V1dBPuErBUkAY4JN5A+rWpFbt772FUhYHEv4TgJJW
ggAznvUIB9yq6TxNcmHpSp4HO3f8S86ycyB2Cvce0g57i6qO1+hljRxC78urB52w
rBhjPYuNE2bc7qEe6xYrtaTIht/LdNlg+wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/dh.pem
		# Generate server.conf
		echo "local $ip
port $port
proto $protocol
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
auth SHA512
tls-crypt /etc/openvpn/tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server.conf
		# IPv6
		if [[ -z "$ip6" ]]; then
			echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
		else
			echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server.conf
			echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server.conf
		fi
		echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server.conf
		# DNS
		case "$dns" in
			1|"")
				resolv_conf='/etc/resolv.conf'
				grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
					echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
				done
			;;
			2)
				echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
			;;
			3)
				echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
			;;
			4)
				echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
			;;
			5)
				echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server.conf
			;;
			6)
				echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server.conf
			;;
		esac
		echo "keepalive 10 120
cipher AES-256-CBC
data-ciphers AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify /etc/openvpn/crl.pem" >> /etc/openvpn/server.conf
		if [[ "$protocol" = "udp" ]]; then
			echo "explicit-exit-notify" >> /etc/openvpn/server.conf
		fi
		# Enable net.ipv4.ip_forward for the system
		if ! grep -q "echo 1 > /proc/sys/net/ipv4/ip_forward" "/etc/rc.d/rc.local"; then
			echo "echo 1 > /proc/sys/net/ipv4/ip_forward" >> /etc/rc.d/rc.local
		fi
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv4/ip_forward
		if [[ -n "$ip6" ]]; then
			if ! grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
				echo "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" >> /etc/rc.d/rc.local
			fi
			echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
		fi
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
		iptables -I INPUT -p $protocol --dport $port -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		if [[ -n "$ip6" ]]; then
			ip6tables -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
			ip6tables -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
			ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		fi
		iptables-save > /etc/iptables/rules.v4
		if [[ -n "$ip6" ]]; then
			ip6tables-save > /etc/iptables/rules.v6
		fi
		# Load them on boot time.
		if ! grep -q "iptables-restore < /etc/iptables/rules.v4" "/etc/rc.d/rc.local"; then
			echo "iptables-restore < /etc/iptables/rules.v4" >> /etc/rc.d/rc.local
		fi
		if ! grep -q "ip6tables-restore < /etc/iptables/rules.v6" "/etc/rc.d/rc.local"; then
			echo "ip6tables-restore < /etc/iptables/rules.v6" >> /etc/rc.d/rc.local
		fi
		# If the server is behind NAT, use the correct IP address
		[[ -n "$public_ip" ]] && ip="$public_ip"
		# client-common.txt is created so we have a template to add further users later
		echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
#data-ciphers AES-256-CBC #Enable this if you are using 2.5 version or higher
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/client-common.txt
		# Enable and start OpenVPN
		if [[ -e /etc/rc.d/rc.openvpn ]]; then
			if [ -x /etc/rc.d/rc.openvpn ]; then
				/etc/rc.d/rc.openvpn start
			else
				chmod +x /etc/rc.d/rc.openvpn
				/etc/rc.d/rc.openvpn start
			fi
		else
			# This is for older versions of Slackware. Kill openvpn if it is running
			/usr/bin/killall openvpn
			# Start openvpn
			/usr/sbin/openvpn --daemon --writepid /run/openvpn/server.conf.pid --user nobody --group nobody --config /etc/openvpn/server.conf
			echo "/etc/rc.d/rc.openvpn was not found, you must create one and modify"
			echo "/etc/rc.d/rc.local in order for OpenVPN to start automatically on reboot!"
		fi
		# Generates the custom client.ovpn
		new_client
		echo
		echo "Finished!"
		echo
		echo "The client configuration is available in:" ~/"$client.ovpn"
		echo "New clients can be added by running this script again."
		clear
	else
		# OpenVPN already installed — management menu
		echo "OpenVPN is already installed."
		echo
		echo "Select an option:"
		echo "   1) Add a new client"
		echo "   2) Revoke an existing client"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Option: " option
		until [[ "$option" =~ ^[1-4]$ ]]; do
			echo "$option: invalid selection."
			read -p "Option: " option
		done
		case "$option" in
			1)
				echo
				echo "Provide a name for the client:"
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
				while [[ -z "$client" || -e /etc/openvpn/easy-rsa/pki/issued/"$client".crt ]]; do
					echo "$client: invalid name."
					read -p "Name: " unsanitized_client
					client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
				done
				cd /etc/openvpn/easy-rsa/
				EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
				new_client
				echo
				echo "$client added. Configuration available in:" ~/"$client.ovpn"
				exit
			;;
			2)
				number_of_clients=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
				if [[ "$number_of_clients" = 0 ]]; then
					echo
					echo "There are no existing clients!"
					exit
				fi
				echo
				echo "Select the client to revoke:"
				tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
				read -p "Client: " client_number
				until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
					echo "$client_number: invalid selection."
					read -p "Client: " client_number
				done
				client=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
				echo
				read -p "Confirm $client revocation? [y/N]: " revoke
				until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
					echo "$revoke: invalid selection."
					read -p "Confirm $client revocation? [y/N]: " revoke
				done
				if [[ "$revoke" =~ ^[yY]$ ]]; then
					cd /etc/openvpn/easy-rsa/
					./easyrsa --batch revoke "$client"
					EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
					rm -f /etc/openvpn/crl.pem
					cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
					chown nobody:"$group_name" /etc/openvpn/crl.pem
					echo
					echo "$client revoked!"
				else
					echo
					echo "$client revocation aborted!"
				fi
				exit
			;;
			3)
				echo
				read -p "Confirm OpenVPN removal? [y/N]: " remove
				until [[ "$remove" =~ ^[yYnN]*$ ]]; do
					echo "$remove: invalid selection."
					read -p "Confirm OpenVPN removal? [y/N]: " remove
				done
				if [[ "$remove" =~ ^[yY]$ ]]; then
					port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
					protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
					ip=$(grep '^local ' /etc/openvpn/server.conf | cut -d " " -f 2)
					ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
					iptables -D INPUT -p $protocol --dport $port -j ACCEPT
					iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
					iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
					iptables-save > /etc/iptables/rules.v4
					if grep -q "iptables-restore < /etc/iptables/rules.v4" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "iptables-restore < /etc/iptables/rules.v4" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if grep -q "echo 1 > /proc/sys/net/ipv4/ip_forward" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "echo 1 > /proc/sys/net/ipv4/ip_forward" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if [[ -n "$ip6" ]]; then
						ip6tables -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
						ip6tables -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
						ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						ip6tables-save > /etc/iptables/rules.v6
						if grep -q "ip6tables-restore < /etc/iptables/rules.v6" "/etc/rc.d/rc.local"; then
							echo "$(grep -v "ip6tables-restore < /etc/iptables/rules.v6" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
						fi
						if grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
							echo "$(grep -v "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
						fi
					fi
					/etc/rc.d/rc.openvpn stop
					removepkg openvpn
					rm -rf /etc/openvpn
					rm -rf /usr/share/doc/openvpn*
					echo
					echo "OpenVPN removed!"
				else
					echo
					echo "OpenVPN removal aborted!"
				fi
				exit
			;;
			4)
				exit
			;;
		esac
	fi

# ============================================================
# WIREGUARD BRANCH
# ============================================================

elif [[ "$vpn_choice" -eq 2 ]]; then

	if [[ ! -e /etc/wireguard/wg0.conf ]]; then

		clear
		echo 'Welcome to this WireGuard road warrior installer!'

		# If system has a single IPv4, it is selected automatically. Else, ask the user
		if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
		else
			number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
			echo
			echo "Which IPv4 address should be used?"
			ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
			read -p "IPv4 address [1]: " ip_number
			until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
				echo "$ip_number: invalid selection."
				read -p "IPv4 address [1]: " ip_number
			done
			[[ -z "$ip_number" ]] && ip_number="1"
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
		fi

		# If $ip is a private IP address, the server must be behind NAT
		if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			echo
			echo "This server is behind NAT. What is the public IPv4 address or hostname?"
			get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
			read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
			until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
				echo "Invalid input."
				read -p "Public IPv4 address / hostname: " public_ip
			done
			[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
		fi

		# If system has a single IPv6, it is selected automatically
		if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
			ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
		fi
		# If system has multiple IPv6, ask the user to select one
		if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
			number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
			echo
			echo "Which IPv6 address should be used?"
			ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
			read -p "IPv6 address [1]: " ip6_number
			until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
				echo "$ip6_number: invalid selection."
				read -p "IPv6 address [1]: " ip6_number
			done
			[[ -z "$ip6_number" ]] && ip6_number="1"
			ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
		fi

		echo
		echo "What port should WireGuard listen to?"
		read -p "Port [51820]: " wg_port
		until [[ -z "$wg_port" || "$wg_port" =~ ^[0-9]+$ && "$wg_port" -le 65535 ]]; do
			echo "$wg_port: invalid port."
			read -p "Port [51820]: " wg_port
		done
		[[ -z "$wg_port" ]] && wg_port="51820"

		echo
		echo "Select a DNS server for the clients:"
		echo "   1) Current system resolvers"
		echo "   2) Google"
		echo "   3) 1.1.1.1"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard"
		read -p "DNS server [1]: " wg_dns
		until [[ -z "$wg_dns" || "$wg_dns" =~ ^[1-6]$ ]]; do
			echo "$wg_dns: invalid selection."
			read -p "DNS server [1]: " wg_dns
		done

		echo
		echo "Enter a name for the first client:"
		read -p "Name [client]: " unsanitized_wg_client
		wg_client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_wg_client")
		[[ -z "$wg_client" ]] && wg_client="client"

		echo
		echo "WireGuard installation is ready to begin."

		# Check that we have all necessary packages installed
		wg_pkgs=""
		for pkg in "wireguard-tools" "iptables"
		do
			installed $pkg
			pkginstalled=$?
			if [ $pkginstalled -eq 0 ]; then
				wg_pkgs+="$pkg "
			fi
		done

		if [[ -n $wg_pkgs ]]; then
			echo "The following packages are not installed:"
			echo "     $wg_pkgs"
			read -p "Do you want to install them [Y/n]? " -e -i "Y" wg_answer
			if [ "$wg_answer" == "Y" ]; then
				slackpkg install $wg_pkgs
			else
				echo "Cannot continue without all necessary packages."
				echo "Aborting!"
				exit 4
			fi
		fi

		# Generate server keys
		mkdir -p /etc/wireguard
		chmod 700 /etc/wireguard
		wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
		chmod 600 /etc/wireguard/server_private.key
		server_private=$(cat /etc/wireguard/server_private.key)

		# Detect network interface
		wg_if=$(ip -4 route | grep default | awk '{print $5}' | head -1)

		# Store endpoint for client config generation
		[[ -n "$public_ip" ]] && wg_endpoint="$public_ip" || wg_endpoint="$ip"

		# Build IPv6 address line and ip6tables rules if IPv6 is available
		if [[ -n "$ip6" ]]; then
			wg_addr_line="Address = 10.9.0.1/24, fddd:9090:9090:9090::1/64"
			wg_postup_ip6="; ip6tables -t nat -A POSTROUTING -s fddd:9090:9090:9090::/64 ! -d fddd:9090:9090:9090::/64 -j SNAT --to $ip6; ip6tables -I FORWARD -s fddd:9090:9090:9090::/64 -j ACCEPT; ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			wg_postdown_ip6="; ip6tables -t nat -D POSTROUTING -s fddd:9090:9090:9090::/64 ! -d fddd:9090:9090:9090::/64 -j SNAT --to $ip6; ip6tables -D FORWARD -s fddd:9090:9090:9090::/64 -j ACCEPT; ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
		else
			wg_addr_line="Address = 10.9.0.1/24"
			wg_postup_ip6=""
			wg_postdown_ip6=""
		fi

		# Generate server wg0.conf
		echo "# ENDPOINT $wg_endpoint
[Interface]
$wg_addr_line
ListenPort = $wg_port
PrivateKey = $server_private
PostUp = iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $ip; iptables -I INPUT -p udp --dport $wg_port -j ACCEPT; iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT; iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT$wg_postup_ip6
PostDown = iptables -t nat -D POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $ip; iptables -D INPUT -p udp --dport $wg_port -j ACCEPT; iptables -D FORWARD -s 10.9.0.0/24 -j ACCEPT; iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT$wg_postdown_ip6" > /etc/wireguard/wg0.conf
		chmod 600 /etc/wireguard/wg0.conf

		# Enable IP forwarding
		if ! grep -q "echo 1 > /proc/sys/net/ipv4/ip_forward" "/etc/rc.d/rc.local"; then
			echo "echo 1 > /proc/sys/net/ipv4/ip_forward" >> /etc/rc.d/rc.local
		fi
		echo 1 > /proc/sys/net/ipv4/ip_forward
		if [[ -n "$ip6" ]]; then
			if ! grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
				echo "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" >> /etc/rc.d/rc.local
			fi
			echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
		fi

		# Save iptables rules and restore on boot
        mkdir -p /etc/iptables/
		iptables-save > /etc/iptables/rules.v4
		if [[ -n "$ip6" ]]; then
			ip6tables-save > /etc/iptables/rules.v6
		fi
		if ! grep -q "iptables-restore < /etc/iptables/rules.v4" "/etc/rc.d/rc.local"; then
			echo "iptables-restore < /etc/iptables/rules.v4" >> /etc/rc.d/rc.local
		fi
		if [[ -n "$ip6" ]]; then
			if ! grep -q "ip6tables-restore < /etc/iptables/rules.v6" "/etc/rc.d/rc.local"; then
				echo "ip6tables-restore < /etc/iptables/rules.v6" >> /etc/rc.d/rc.local
			fi
		fi

		# Start WireGuard and enable on boot
		wg-quick up wg0
		if ! grep -q "wg-quick up wg0" "/etc/rc.d/rc.local"; then
			echo "wg-quick up wg0" >> /etc/rc.d/rc.local
		fi

		# Generate the first client config
		new_wg_client
		echo
		echo "Finished!"
		echo
		echo "The client configuration is available in:" ~/"$wg_client.conf"
		echo "New clients can be added by running this script again."
		clear
	else
		# WireGuard already installed — management menu
		echo "WireGuard is already installed."
		echo
		echo "Select an option:"
		echo "   1) Add a new client"
		echo "   2) Remove an existing client"
		echo "   3) Remove WireGuard"
		echo "   4) Exit"
		read -p "Option: " option
		until [[ "$option" =~ ^[1-4]$ ]]; do
			echo "$option: invalid selection."
			read -p "Option: " option
		done
		case "$option" in
			1)
				echo
				echo "Provide a name for the client:"
				read -p "Name: " unsanitized_wg_client
				wg_client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_wg_client")
				while [[ -z "$wg_client" ]] || grep -q "# $wg_client$" /etc/wireguard/wg0.conf 2>/dev/null; do
					echo "$wg_client: invalid name or already exists."
					read -p "Name: " unsanitized_wg_client
					wg_client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_wg_client")
				done
				# Re-read DNS setting from server config comment (or default to system)
				wg_dns="1"
				new_wg_client
				echo
				echo "$wg_client added. Configuration available in:" ~/"$wg_client.conf"
				exit
			;;
			2)
				# List clients by their comment lines
				number_of_clients=$(grep -c '^# ' /etc/wireguard/wg0.conf 2>/dev/null || echo 0)
				# Exclude the ENDPOINT comment line
				client_list=$(grep '^# ' /etc/wireguard/wg0.conf | grep -v '^# ENDPOINT')
				number_of_clients=$(echo "$client_list" | grep -c '^# ' || echo 0)
				if [[ "$number_of_clients" -eq 0 ]]; then
					echo
					echo "There are no existing clients!"
					exit
				fi
				echo
				echo "Select the client to remove:"
				echo "$client_list" | sed 's/^# //' | nl -s ') '
				read -p "Client: " client_number
				until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
					echo "$client_number: invalid selection."
					read -p "Client: " client_number
				done
				wg_client=$(echo "$client_list" | sed 's/^# //' | sed -n "${client_number}p")
				echo
				read -p "Confirm removal of $wg_client? [y/N]: " revoke
				until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
					echo "$revoke: invalid selection."
					read -p "Confirm removal of $wg_client? [y/N]: " revoke
				done
				if [[ "$revoke" =~ ^[yY]$ ]]; then
					# Get the public key of this client from the config
					wg_client_pub=$(awk "/^# $wg_client$/{found=1} found && /^PublicKey/{print \$3; exit}" /etc/wireguard/wg0.conf)
					# Remove the peer block from config (comment + [Peer] block)
					sed -i "/^# $wg_client$/,/^$/d" /etc/wireguard/wg0.conf
					# Remove live from running WireGuard
					if wg show wg0 &>/dev/null && [[ -n "$wg_client_pub" ]]; then
						wg set wg0 peer "$wg_client_pub" remove
					fi
					echo
					echo "$wg_client removed!"
				else
					echo
					echo "$wg_client removal aborted!"
				fi
				exit
			;;
			3)
				echo
				read -p "Confirm WireGuard removal? [y/N]: " remove
				until [[ "$remove" =~ ^[yYnN]*$ ]]; do
					echo "$remove: invalid selection."
					read -p "Confirm WireGuard removal? [y/N]: " remove
				done
				if [[ "$remove" =~ ^[yY]$ ]]; then
					wg-quick down wg0
					# Remove from rc.local
					if grep -q "wg-quick up wg0" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "wg-quick up wg0" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if grep -q "echo 1 > /proc/sys/net/ipv4/ip_forward" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "echo 1 > /proc/sys/net/ipv4/ip_forward" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if grep -q "iptables-restore < /etc/iptables/rules.v4" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "iptables-restore < /etc/iptables/rules.v4" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					if grep -q "ip6tables-restore < /etc/iptables/rules.v6" "/etc/rc.d/rc.local"; then
						echo "$(grep -v "ip6tables-restore < /etc/iptables/rules.v6" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
					fi
					removepkg wireguard-tools
					rm -rf /etc/wireguard
					echo
					echo "WireGuard removed!"
				else
					echo
					echo "WireGuard removal aborted!"
				fi
				exit
			;;
			4)
				exit
			;;
		esac
	fi

fi
