#!/bin/bash

echo "Create namespaces for DN, gNB, UPF"

ip netns add DN_ns
ip netns add gNB_ns
ip netns add UPF_ns

echo "Create interfaces between DN, UPF and gNB"
ip link add dn_veth type veth peer name upf_cn_veth # cn - Core network interface
ip link add gnb_veth type veth peer name upf_an_veth # an - Access network interface

echo "Set namespaces to interfaces"
ip link set dev dn_veth netns DN_ns
ip link set dev gnb_veth netns gNB_ns
ip link set dev upf_cn_veth netns UPF_ns
ip link set dev upf_an_veth netns UPF_ns

echo "Enable all interfaces"
ip netns exec DN_ns ip link set dn_veth up
ip netns exec gNB_ns ip link set gnb_veth up
ip netns exec UPF_ns ip link set upf_an_veth up
ip netns exec UPF_ns ip link set upf_cn_veth up

echo "Subnet UPF<->gNB 192.168.9.0/24 where 192.168.9.1 is UPF and 192.168.9.2 is gNB"
ip netns exec UPF_ns ip addr add 192.168.9.1/24 dev upf_an_veth
ip netns exec gNB_ns ip addr add 192.168.9.2/24 dev gnb_veth

echo "Subnet UPF<->DN where 192.168.5.1 is DN"
ip netns exec DN_ns ip addr add 192.168.5.1/24 dev dn_veth

echo "Configure subnet of UE's 192.168.7.0 via gateway 192.168.5.1 in DN namespace"
ip netns exec DN_ns ip route add 192.168.7.0/24 via 192.168.5.1 dev dn_veth
