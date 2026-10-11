#!/bin/bash

# Disable network if script fails
teardown_all()
{
    echo "Teardown"
    kill $(ps -e | pgrep tcpdump) || true
    ./net/disable_net.sh || true
}

# Cleanup after previous test
./net/disable_net.sh > /dev/null 2>&1

set +e

# Enable netwok
sleep 0.1
./net/enable_net.sh
trap teardown_all INT
sleep 0.5

# Run tcpdump
ip netns exec DN_ns tcpdump -w dn.pcap &
ip netns exec gNB_ns tcpdump -w gnb.pcap &

sleep 0.1

# Start simulators
(ip netns exec gNB_ns python3 fakes/fake_ue.py) > ./ue.log &
(ip netns exec UPF_ns python3 fakes/fake_upf.py) > ./upf.log &
sleep 0.1
ip netns exec DN_ns ping 192.168.7.1 -I dn_veth
