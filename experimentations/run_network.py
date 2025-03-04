# First let's write the contents of the script
# %%writefile /home/ubuntu/run_network.py
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Node
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib.switch import SwitchConnection
import os
import sys
import subprocess
import time

class SingleSwitchTopo(Topo):
    def __init__(self, n=2, **opts):
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost(f'h{h+1}',
                              ip=f"10.0.{h+1}.{h+1}/24",
                              mac=f"00:00:00:00:0{h+1}:0{h+1}")
            self.addLink(host, switch)

def program_switch():
    p4info_helper = P4InfoHelper("/home/ubuntu/simple.p4info.txtpb")

    try:
        s1 = SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=1,
            proto_dump_file='logs/p4runtime-requests.txt'
        )

        s1.MasterArbitrationUpdate()

        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                     bmv2_json_file_path="/home/ubuntu/simple.json")

        # Write forwarding rules
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ("10.0.1.1", 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": "00:00:00:00:01:01",
                "port": 1
            })
        s1.WriteTableEntry(table_entry)

        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ("10.0.2.2", 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": "00:00:00:00:02:02",
                "port": 2
            })
        s1.WriteTableEntry(table_entry)

        return s1

    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def main():
    setLogLevel('info')

    # Create network
    topo = SingleSwitchTopo()
    net = Mininet(topo)
    
    # Start network
    net.start()

    # Start P4 switch
    switch_cmd = [
        'simple_switch_grpc',
        '--no-p4',
        '--dump-packet-data',
        '/home/ubuntu/simple.json',
        '--device-id', '1',
        '--grpc-server-addr', '0.0.0.0:50051',
        '--log-console'
    ]
    
    # Give the switch time to start
    print("Waiting for switch to start...")
    time.sleep(2)

    # Program the switch
    print("Programming switch...")
    switch_connection = program_switch()
    if switch_connection is None:
        print("Failed to program switch")
        net.stop()
        return

    # Configure hosts
    h1, h2 = net.get('h1'), net.get('h2')
    h1.cmd('arp -s 10.0.2.2 00:00:00:00:02:02')
    h2.cmd('arp -s 10.0.1.1 00:00:00:00:01:01')

    print("Network is ready!")
    print("Try: h1 ping h2")
    
    CLI(net)
    
    # Clean up
    if switch_connection:
        ShutdownAllSwitchConnections()
    net.stop()

if __name__ == '__main__':
    main()