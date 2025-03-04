# main.py

from mininet.net import Mininet
from mininet.node import Controller
from mininet.topo import Topo
from p4_host import P4Host  # Ensure the path to P4Host.py is correct
from p4_switch import P4Switch  # Ensure the path to P4Switch.py is correct
from mininet.cli import CLI

# Set up a custom topology with P4 switches and hosts
class SimpleP4Topo(Topo):
    def build(self):
        # Create the controller
        controller = self.addController('c0')

        # Add P4 switches (you should replace these with your specific P4Switch details)
        s1 = self.addSwitch('s1', cls=P4Switch, p4info_file='path_to_p4info.p4info', bmv2_json='path_to_bmv2.json')
        s2 = self.addSwitch('s2', cls=P4Switch, p4info_file='path_to_p4info.p4info', bmv2_json='path_to_bmv2.json')

        # Add P4 Hosts (again, replace with your actual host configuration)
        h1 = self.addHost('h1', cls=P4Host)
        h2 = self.addHost('h2', cls=P4Host)

        # Add links between hosts and switches
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(s1, s2)

# Create the Mininet object
def start_mininet():
    topo = SimpleP4Topo()
    net = Mininet(topo=topo, controller=Controller)

    # Start the network
    net.start()

    # You can optionally run a CLI to interact with the network (e.g., ping, iperf)
    CLI(net)

    # Stop the network after use
    net.stop()

if __name__ == '__main__':
    start_mininet()
