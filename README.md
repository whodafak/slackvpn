# slackvpn
OpenVPN installer for Slackware based on Nyr's OpenVPN road warrior script.

Currently tested and working on Slackware 15.0

# How to Install
  - as root 
  - wget https://raw.githubusercontent.com/whodafak/slackvpn/main/slackvpn.sh
  - bash slackvpn.sh
   
   And follow the screen.
   
   After finish, you can run it again to add/remove users or uninstall OpenVPN

# Iptables

If you have iptables rules before you run the script it will autosave them, append new rules for openvpn and load them on every boot.                               
If you want to add more rules after you install the script, simply edit /etc/openvpn/iptables for v4 and /etc/openvpn/iptables6 for v6, append new rules there and restore them with iptables-restore < /etc/openvpn/iptables for v4 or ip6tables-restore < /etc/openvpn/iptables6 for v6
