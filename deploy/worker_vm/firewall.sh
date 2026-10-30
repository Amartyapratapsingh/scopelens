#!/bin/sh
# Only the transport relay may cross the VM boundary, to the enforcing proxy.
set -eu
modprobe br_netfilter
sysctl -q -w net.bridge.bridge-nf-call-iptables=1
sysctl -q -w net.bridge.bridge-nf-call-ip6tables=1
iptables -N SL_WORKER_FORWARD 2>/dev/null || true
iptables -F SL_WORKER_FORWARD
iptables -A SL_WORKER_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A SL_WORKER_FORWARD -s 172.30.0.0/24 -d 172.30.0.2 -p tcp --dport 8080 -j ACCEPT
iptables -A SL_WORKER_FORWARD -s 172.30.1.2 -d 192.168.5.2 -p tcp --dport 8098 -j ACCEPT
iptables -A SL_WORKER_FORWARD -s 172.30.0.0/23 -j DROP
iptables -A SL_WORKER_FORWARD -j RETURN
iptables -C DOCKER-USER -j SL_WORKER_FORWARD 2>/dev/null || iptables -I DOCKER-USER 1 -j SL_WORKER_FORWARD
iptables -N SL_WORKER_INPUT 2>/dev/null || true
iptables -F SL_WORKER_INPUT
iptables -A SL_WORKER_INPUT -s 172.30.0.0/23 -j DROP
iptables -A SL_WORKER_INPUT -j RETURN
iptables -C INPUT -j SL_WORKER_INPUT 2>/dev/null || iptables -I INPUT 1 -j SL_WORKER_INPUT
iptables -N SL_WORKER_OUTPUT 2>/dev/null || true
iptables -F SL_WORKER_OUTPUT
iptables -A SL_WORKER_OUTPUT -o lo -j ACCEPT
iptables -A SL_WORKER_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A SL_WORKER_OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
iptables -A SL_WORKER_OUTPUT -d 192.168.5.2 -p tcp --dport 8098 -j ACCEPT
iptables -A SL_WORKER_OUTPUT -j DROP
iptables -C OUTPUT -j SL_WORKER_OUTPUT 2>/dev/null || iptables -I OUTPUT 1 -j SL_WORKER_OUTPUT
ip6tables -C FORWARD -i slworker -j DROP 2>/dev/null || ip6tables -I FORWARD 1 -i slworker -j DROP
ip6tables -N SL_WORKER_OUTPUT 2>/dev/null || true
ip6tables -F SL_WORKER_OUTPUT
ip6tables -A SL_WORKER_OUTPUT -o lo -j ACCEPT
ip6tables -A SL_WORKER_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A SL_WORKER_OUTPUT -j DROP
ip6tables -C OUTPUT -j SL_WORKER_OUTPUT 2>/dev/null || ip6tables -I OUTPUT 1 -j SL_WORKER_OUTPUT
