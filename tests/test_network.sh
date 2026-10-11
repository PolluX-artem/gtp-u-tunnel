#!/bin/bash

teardown_all()
{
    echo "Teardown"
    kill $(ps -e | pgrep tcpdump) || true
    kill $(ps -e | pgrep ping) || true
    ../net/disable_net.sh || true
}

set +e
../net/disable_net.sh
sleep 1
../net/enable_net.sh
sleep 1
ip netns exec UPF_ns tcpdump -w test_dump.pcap &
trap teardown_all INT
sleep 0.5

set -e

echo "Check DN<->UPF connectivity"
ip netns exec DN_ns ping 192.168.7.1 -c 7 -I dn_veth > ping_dn_upf.log &
ip netns exec UPF_ns python3 upf_network_tester.py

echo "Check gNB<->UPF connectivity"
ip netns exec UPF_ns ping 192.168.9.2 -c 7 -I upf_an_veth > ping_upf_gnb.log

echo "Test completed"

set +e
teardown_all
