# P4Host.py
from mininet.node import Host
from mininet.util import quietRun
from mininet.link import Link
import os
import time

class P4Host(Host):
    def __init__(self, name, *args, **kwargs):
        super(P4Host, self).__init__(name, *args, **kwargs)
        print(f"Initializing P4 Host: {name}")
        
    def setIP(self, ip, netmask='255.255.255.0'):
        """Set the IP address and netmask for the host"""
        print(f"Setting IP for {self.name}: {ip}/{netmask}")
        quietRun(f"ifconfig {self.name}-eth0 {ip} netmask {netmask}")

    def setMAC(self, mac):
        """Set the MAC address for the host"""
        print(f"Setting MAC for {self.name}: {mac}")
        quietRun(f"ifconfig {self.name}-eth0 hw ether {mac}")

    def sendPacket(self, destination_ip, packet_data):
        """Send a packet to another host using raw sockets"""
        print(f"Sending packet from {self.name} to {destination_ip}")
        # This can be extended to send packets to a specific destination IP.
        # Here, we'll use a simple method to simulate sending data.
        time.sleep(1)  # Simulating delay
        print(f"Packet sent from {self.name}: {packet_data} -> {destination_ip}")

    def configureHost(self, ip, mac):
        """Configure host with IP, MAC and other parameters."""
        self.setIP(ip)
        self.setMAC(mac)
        print(f"Host {self.name} configured with IP: {ip} and MAC: {mac}")
    
    def customBehavior(self):
        """Add any custom behavior specific to the host (optional)"""
        # For example, testing the network, sending packets, or checking connectivity
        print(f"Host {self.name} is running custom behavior.")
        self.sendPacket("10.0.0.2", "Test packet")

# Example usage in a script
if __name__ == "__main__":
    host1 = P4Host(name="host1")
    host1.configureHost("10.0.0.1", "00:00:00:00:00:01")
    host1.customBehavior()
