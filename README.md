# Pi-ARP-RedirectALL.py
Python script for REDIRECT ALL CONNECTED DEVICES to speciffic IP address or LINK (for example RickRoll)
# USAGE
- Open terminal on your RPI4 with SUDO PERMISSONS
- python3 Pi-ARP-RedirectALL.py <IP_Addres_to_which_will_be_redirrected> <Router_IP_Address>

# HELP COMMANDS
- "-r_ip" or "--router_ip" for set IP address of WiFi Router.
- "-rt" or "--redirect_to" for set IP address on which will be all devices redirected.
# EXAMPLE
- example for apache2 : python3 Pi-ARP-RedirectALL.py -rt 192.168.101 -r_ip 192.168.1
- or : python3 Pi-ARP-RedirectALL.py -redirect_to 192.168.101 --router_ip 192.168.1
