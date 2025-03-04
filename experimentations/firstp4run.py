from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
import time

def setup_topology():
    net = Mininet(topo=None, build=False)

    # Add hosts with IP addresses
    h1 = net.addHost('h1', ip='10.0.0.1/24')  # Host 1 with IP 10.0.0.1
    h2 = net.addHost('h2', ip='10.0.0.2/24')  # Host 2 with IP 10.0.0.2

    # Add Open vSwitch
    s1 = net.addSwitch('s1', cls=OVSSwitch)

    # Add links between hosts and switch with bandwidth limit
    net.addLink(h1, s1, cls=TCLink, bw=10)  # 10 Mbps link
    net.addLink(h2, s1, cls=TCLink, bw=10)  # 10 Mbps link

    # Build and start the network
    net.build()
    net.start()

    # Flush iptables to prevent firewall issues
    h1.cmd('iptables -F')
    h2.cmd('iptables -F')

    # Enable IP forwarding (if required)
    h1.cmd('sysctl -w net.ipv4.ip_forward=1')
    h2.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Bring up network interfaces
    h1.cmd('ifconfig h1-eth0 up')
    h2.cmd('ifconfig h2-eth0 up')

    # Verify network interfaces
    print("h1 ifconfig:")
    print(h1.cmd('ifconfig'))
    print("h2 ifconfig:")
    print(h2.cmd('ifconfig'))

    # Dump node connections
    print("Dumping node connections...")
    dumpNodeConnections(net.hosts)

    # Wait for the network to stabilize (increase delay)
    print("Waiting for network to stabilize...")
    time.sleep(5)  # Increased time for network to fully stabilize

    # Test network connectivity (ping)
    print("Testing network connectivity:")
    print("Sending packet from h1 to h2 with dst_ip=10.0.0.2")
    h1.cmd('ping -c 1 10.0.0.2')  # Ping h2 from h1

    # Start the CLI for further interaction
    print("Starting Mininet CLI")
    CLI(net)

    # Stop the network after CLI interaction ends
    net.stop()

# Run the topology setup
setup_topology()
