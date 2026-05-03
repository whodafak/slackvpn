# slackvpn
OpenVPN and Wireguard installer for Slackware based on Nyr's OpenVPN road warrior script.

Currently tested and working on Slackware 15.0

# How to Install
as root

 If you want only OpenVPN (this one is AI free)

- wget https://raw.githubusercontent.com/whodafak/slackvpn/main/slackvpn.sh
- bash slackvpn.sh

 If you want + wireguard (this one have AI code in it) 

- wget https://raw.githubusercontent.com/whodafak/slackvpn/main/slackwirevpn.sh
- bash slackwirevpn.sh


And follow the screen.
   
   When the script is done, you can run it again to add/remove users or uninstall OpenVPN / WireGuard

# Iptables

If you have iptables rules before you run the script it will autosave them, append new rules for openvpn/wireguard and load them on every boot.                               
If you want to add more rules after you install the script, simply edit /etc/iptables/rules.v4 for ipv4 and /etc/iptables/rules.v6 for ipv6, append new rules there and reload them with 

  - iptables-restore < /etc/iptables/rules.v4 for v4                                                                                                             
  - ip6tables-restore < /etc/iptables/rules.v6 for v6

# Donations

If you find this useful please donate to [Nyr](https://github.com/Nyr/openvpn-install) Or [Slackware](https://www.patreon.com/slackwarelinux/overview) . Thank You
