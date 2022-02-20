#!/bin/bash
#
# https://github.com/whodafak/slackvpn
#
# Thanks to Nyr (If you want to buy him coffe https://www.paypal.com/donate/?cmd=_s-xclick&hosted_button_id=VBAYDL34Z7J6L ) for this great script. Here is slackware version. Currently tested and working on # Slackware 15.0. Big thanks to Slackware team.. please if you find this scipt usefull consider donating to slackware project at : http://arm.slackware.com/sponsor/ 
# you can Donate directly to Patrick Volkerding (Supporting x86 Slackware)  or Stuart Winter (Supporting ARM / AArch64 Slackware)


# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if [[ -e /etc/slackware-version ]]; then
	group_name=nobody
	RCLOCAL='/etc/rc.d/rc.local'
	chmod +x $RCLOCAL
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
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
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
	# Allow a limited set of characters to avoid conflicts
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
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
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
		# Enable net.ipv6.conf.all.forwarding for the system
	if ! grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
		echo "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" >> /etc/rc.d/rc.local
	fi
		# Enable without waiting for a reboot or service restart
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
        iptables-save > /etc/openvpn/iptables
        if [[ -n "$ip6" ]]; then
        ip6tables-save > /etc/openvpn/iptables6
        fi
        # Load them on boot time.
        if ! grep -q "iptables-restore < /etc/openvpn/iptables" "/etc/rc.d/rc.local"; then
                echo "iptables-restore < /etc/openvpn/iptables" >> /etc/rc.d/rc.local
        fi
	if ! grep -q "ip6tables-restore < /etc/openvpn/iptables6" "/etc/rc.d/rc.local"; then
        echo "ip6tables-restore < /etc/openvpn/iptables6" >> /etc/rc.d/rc.local
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
data-ciphers AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/client-common.txt
        #Enable and start OpenVPN script is bugged.. so we need to do start/stop/start
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
		# Print a message telling the user that rc.openvpn needs to be created
		echo /etc/rc.d/rc.openvpn was not found, you must create one and modify
		echo /etc/rc.d/rc.local in order for OpenVPN to start automatically on reboot!
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
			# Generates the custom client.ovpn
			new_client
			echo
			echo "$client added. Configuration available in:" ~/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
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
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
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
iptables-save > /etc/openvpn/iptables
                       if grep -q "iptables-restore < /etc/openvpn/iptables" "/etc/rc.d/rc.local"; then
                       echo "$(grep -v "iptables-restore < /etc/openvpn/iptables" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
                       fi
                       if grep -q "echo 1 > /proc/sys/net/ipv4/ip_forward" "/etc/rc.d/rc.local"; then
                       echo "$(grep -v "echo 1 > /proc/sys/net/ipv4/ip_forward" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
                       fi
                       if [[ -n "$ip6" ]]; then
ip6tables -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ip6tables -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ip6tables-save > /etc/openvpn/iptables6
                       if grep -q "ip6tables-restore < /etc/openvpn/iptables6" "/etc/rc.d/rc.local"; then
                       echo "$(grep -v "ip6tables-restore < /etc/openvpn/iptables6" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
                       fi
                       if grep -q "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" "/etc/rc.d/rc.local"; then
                       echo "$(grep -v "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding" /etc/rc.d/rc.local)" > /etc/rc.d/rc.local
                       fi
                       fi
		 	/etc/rc.d/rc.openvpn stop
			removepkg openvpn
			rm -rf /etc/openvpn
			rm -rf /usr/share/doc/openvpn*
			rm -rf /tmp/iptables*
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
