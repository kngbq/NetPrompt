from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import os

def create_p4_network():
    # Create Mininet instance
    net = Mininet(switch=OVSSwitch)

    # Create a controller
    info("*** Adding controller\n")
    net.addController('c0')

    # Create switches
    info("*** Creating switches\n")
    s1 = net.addSwitch('s1', cls=OVSSwitch, 
                       switchProtocol='OpenFlow13', 
                       datapath='kernel')

    # Create hosts
    info("*** Creating hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    # Link hosts to switch
    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # Start the network
    info("*** Starting network\n")
    net.start()

    # Optional: Run some initial commands
    info("*** Running initial host commands\n")
    h1.cmd('ping -c 4 10.0.0.2')  # Test connectivity

    # Start Jupyter Notebook in background (optional)
    info("*** Starting Jupyter Notebook\n")
    try:
        subprocess.Popen("jupyter notebook --no-browser --allow-root &", shell=True)
    except Exception as e:
        info(f"*** Failed to start Jupyter Notebook: {e}\n")

    # Interactive CLI
    info("*** Running CLI\n")
    CLI(net)

    # Cleanup
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    # Set logging level
    setLogLevel('info')

    # Run the network creation
    create_p4_network()from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import os

def create_p4_network():
    # Create Mininet instance
    net = Mininet(switch=OVSSwitch)

    # Create a controller
    info("*** Adding controller\n")
    net.addController('c0')

    # Create switches
    info("*** Creating switches\n")
    s1 = net.addSwitch('s1', cls=OVSSwitch, 
                       switchProtocol='OpenFlow13', 
                       datapath='kernel')

    # Create hosts
    info("*** Creating hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    # Link hosts to switch
    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # Start the network
    info("*** Starting network\n")
    net.start()

    # Optional: Run some initial commands
    info("*** Running initial host commands\n")
    h1.cmd('ping -c 4 10.0.0.2')  # Test connectivity

    # Start Jupyter Notebook in background (optional)
    info("*** Starting Jupyter Notebook\n")
    jupyter_cmd = "jupyter notebook --no-browser --allow-root &"
    subprocess.Popen(jupyter_cmd, shell=True)

    # Interactive CLI
    info("*** Running CLI\n")
    CLI(net)

    # Cleanup
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    # Set logging level
    setLogLevel('info')

    # Run the network creation
    create_p4_network()import os
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel
import jupyter

def create_p4_network():
    # Create Mininet instance
    net = Mininet(switch=OVSSwitch)

    # Create a controller
    net.addController('c0')

    # Create switches
    s1 = net.addSwitch('s1', cls=OVSSwitch, 
                       switchProtocol='OpenFlow13', 
                       datapath='kernel')

    # Create hosts
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')

    # Link hosts to switch
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # Start the network
    net.start()

    # Run Jupyter Notebook for telemetry monitoring
    import subprocess
    jupyter_process = subprocess.Popen(['jupyter', 'notebook'], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)

    # Interactive CLI
    CLI(net)

    # Cleanup
    net.stop()
    jupyter_process.terminate()

# Telemetry Monitoring Notebook (save as telemetry_monitor.ipynb)
# This would be a Jupyter Notebook with cells for monitoring network stats

if __name__ == '__main__':
    setLogLevel('info')
    create_p4_network()
