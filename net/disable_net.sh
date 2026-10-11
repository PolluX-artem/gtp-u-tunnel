ip netns exec DN_ns ip link delete dn_veth || true
ip netns exec gNB_ns ip link delete gnb_veth || true

ip netns delete DN_ns || true
ip netns delete gNB_ns || true
ip netns delete UPF_ns || true