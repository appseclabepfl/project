#!/bin/bash

#### FRESH START ####
#### IPv4 ####
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD DROP
#### IPv6 ####
/sbin/ip6tables -t mangle -P PREROUTING DROP
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P FORWARD DROP
/sbin/ip6tables -P OUTPUT DROP

/sbin/iptables -t mangle -F
/sbin/iptables -F
/sbin/ip6tables -t mangle -F
/sbin/ip6tables -F
/sbin/iptables -N INVALID_DROP 	#WALL
/sbin/iptables -N FILTER_DROP	#KNOCK1
/sbin/iptables -N RAW_DROP		#KNOCK3
/sbin/iptables -P FORWARD ACCEPT
/sbin/iptables -N MANGLE_DROP 	#PASSED
/sbin/iptables -N SECURITY_DROP 	#KNOCK2


### Allow normal utilization traffic ###
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -p tcp -d 10.10.20.2 --dport 5000 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s3 -p tcp -s 10.10.20.2 --sport 5000 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 10.10.20.2 -d 10.10.10.2 --dport 42069 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 10.10.10.2 --sport 42069 -d 10.10.20.2 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp -s 10.10.20.2 -d 10.10.10.3 --dport 6000 -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp -s 10.10.10.3 --sport 6000 -d 10.10.20.2 -j ACCEPT

### ssh access for admin ###
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -p tcp -d 10.10.20.2 --dport ssh -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s8 -o enp0s3 -p tcp -s 10.10.20.2 --sport ssh -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s9 -p tcp -d 10.10.10.0/24 --dport ssh -j ACCEPT
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s3 -p tcp -s 10.10.10.0/24 --sport ssh -j ACCEPT
/sbin/iptables -A INPUT -i enp0s3 -p tcp -d 78.78.78.1 --dport ssh -j ACCEPT
/sbin/iptables -A INPUT -i lo -j ACCEPT


## PORT KNOCKING
/sbin/iptables -A FORWARD -i enp0s9 -o enp0s3 -p tcp -s 10.10.10.3 --sport 6001 -j ACCEPT

/sbin/iptables -A FORWARD -j INVALID_DROP

/sbin/iptables -A FILTER_DROP -i enp0s3 -p tcp --dport 3306 -m recent --name drop1 --set -j DROP
/sbin/iptables -A FILTER_DROP -j DROP

/sbin/iptables -A SECURITY_DROP -m recent --name drop1 --remove
/sbin/iptables -A SECURITY_DROP -i enp0s3 -p tcp --dport 8000 -m recent --name drop2 --set -j DROP
/sbin/iptables -A SECURITY_DROP -j DROP

/sbin/iptables -A RAW_DROP -m recent --name drop2 --remove
/sbin/iptables -A RAW_DROP -i enp0s3 -p tcp --dport 6000 -m recent --name drop3 --set -j DROP
/sbin/iptables -A RAW_DROP -j DROP

#/sbin/iptables -A MANGLE_DROP -m recent --name drop3 --remove
/sbin/iptables -A MANGLE_DROP -i enp0s3 -p tcp --dport 6001 -j ACCEPT
/sbin/iptables -A MANGLE_DROP -j DROP

/sbin/iptables -A INVALID_DROP -m recent --rcheck --seconds 5 --name drop3 -j MANGLE_DROP
/sbin/iptables -A INVALID_DROP -m recent --rcheck --seconds 5 --name drop2 -j RAW_DROP
/sbin/iptables -A INVALID_DROP -m recent --rcheck --seconds 5 --name drop1 -j SECURITY_DROP
/sbin/iptables -A INVALID_DROP -j FILTER_DROP


#### DDOS PROTECTION ####

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
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 10.0.0.0/8 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -i enp0s3 -s 0.0.0.0/8 -j DROP
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
