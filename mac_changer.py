#!/usr/bin/python3

import subprocess
import optparse
import re


def macchanger(interface, macaddr):
    # Bring down the network interface
    subprocess.call(["ifconfig", interface, "down"])
    # Set the new MAC address for the interface
    subprocess.call(["ifconfig", interface, "hw", "ether", macaddr])
    # Bring up the network interface with the new MAC address
    subprocess.call(["ifconfig", interface, "up"])

    print("[+] Changing Mac Address of Interface {} to {}".format(interface, macaddr))


def get_argument():
    parser = optparse.OptionParser()
    # Define the command-line options for interface and new MAC address
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change the MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    # Parse the command-line arguments
    (options, _) = parser.parse_args()

    if not options.interface or not options.new_mac:
        # Display an error message if both the interface and new MAC address are not provided
        parser.error(
            "[-] Specify both the interface and new MAC address. Use python macchanger --help for more details.")

    return options


def get_mac(interface):
    # Get the ifconfig output for the specified interface
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # Use regular expression to search for the current MAC address in the ifconfig output
    current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result.decode())

    if current_mac:
        return current_mac.group(0)
    else:
        return None


options = get_argument()
# Extract the interface and new MAC address from the options object
interface = options.interface
new_mac = options.new_mac

# Get the current MAC address for the specified interface
current_mac = get_mac(interface)
print("[+] Current MAC Address: {}".format(current_mac))

# Change the MAC address of the interface to the new MAC address
macchanger(interface, new_mac)

# Get the updated MAC address for the specified interface
current_mac = get_mac(interface)
if current_mac == new_mac:
    print("[+] MAC Address successfully changed to {}".format(current_mac))
else:
    print("[-] Error occurred. Failed to change the MAC Address.")
