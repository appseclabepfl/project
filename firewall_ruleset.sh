#!/bin/bash

#### FRESH START ####
/sbin/iptables -t mangle -F
/sbin/iptables -F
/sbin/ip6tables -t mangle -F
/sbin/ip6tables -F


#### IPv4 ####
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD DROP

### Allow normal utilization traffic ###
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -p tcp -s 78.78.78.2 -d 10.10.20.2 --dport 5000 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s3 -p tcp -s 10.10.20.2 --sport 5000 -d 78.78.78.2 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 10.10.20.2 -d 10.10.10.2 --dport 3306 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 10.10.10.2 --sport 3306 -d 10.10.20.2 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 10.10.20.2 -d 10.10.10.3 --dport 6000 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 10.10.10.3 --sport 6000 -d 10.10.20.2 -j ACCEPT

### ssh access for admin ###
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -p tcp -s 78.78.78.2 -d 10.10.20.2 --dport ssh -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s3 -p tcp -s 10.10.20.2 --sport ssh -d 78.78.78.2 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s9 -p tcp -s 78.78.78.2 -d 10.10.10.0/24 --dport ssh -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s3 -p tcp -s 10.10.10.0/24 --sport ssh -d 78.78.78.2 -j ACCEPT
/sbin/iptables -A INPUT -i enp0s3 -p tcp -s 78.78.78.2 -d 78.78.78.1 --dport ssh -j ACCEPT


#### IPv6 ####
/sbin/ip6tables -t mangle -P PREROUTING DROP
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P FORWARD DROP
/sbin/ip6tables -P OUTPUT DROP

#### DDOS PROTECTION : https://javapipe.com/blog/iptables-ddos-protection/####

### 1: Drop invalid packets ### 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -m conntrack --ctstate INVALID -j DROP  

### 2: Drop TCP packets that are new and are not SYN ### 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 
 
### 3: Drop SYN packets with suspicious MSS value ### 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  

### 4: Block packets with bogus TCP flags ### 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags FIN,ACK FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ACK,URG URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ACK,FIN FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ACK,PSH PSH -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ALL ALL -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ALL NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  

### 5: Block spoofed packets ### 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 224.0.0.0/3 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 169.254.0.0/16 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 172.16.0.0/12 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 192.0.2.0/24 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 192.168.0.0/16 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 10.0.0.0/8 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 0.0.0.0/8 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 240.0.0.0/5 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

### 6: Drop ICMP (you usually dont need this protocol) ### 
/sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP  

### 7: Drop fragments in all chains ### 
/sbin/iptables -t mangle -A PREROUTING -f -j DROP  

### 8: Limit connections per source IP ### 
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

### 9: Limit RST packets ### 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  

### 10: Limit new TCP connections per second per source IP ### 
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

### DROP UDP ###
/sbin/iptables -t mangle -A PREROUTING -p udp -j DROP

### SSH brute-force protection ### 
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

### Protection against port scanning ### 
/sbin/iptables -N port-scanning 
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
/sbin/iptables -A port-scanning -j DROP

#### SAVE CONFIG ####
/sbin/iptables-save > /etc/iptables/rules.v4
/sbin/ip6tables-save > /etc/iptables/rules.v6
