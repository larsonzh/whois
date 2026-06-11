#!/bin/sh

echo
echo '# BEGIN'

echo
echo "ping -4 -c 3 www.qq.com"
ping -4 -c 3 www.qq.com

echo
echo "ping -6 -c 3 www.qq.com"
ping -6 -c 3 www.qq.com

echo
echo "traceroute -m 8 www.qq.com"
traceroute -m 8 www.qq.com

echo
echo "traceroute -6 -m 8 www.qq.com"
traceroute -6 -m 8 www.qq.com

echo
echo "sudo apt update"
sudo apt update

echo
echo "sudo apt full-upgrade -o APT::Get::Always-Include-Phased-Updates=true"
sudo apt full-upgrade -o APT::Get::Always-Include-Phased-Updates=true

echo
echo "whois -h whois.apnic.net 143.128.0.0/16"
whois -h whois.apnic.net 143.128.0.0/16

echo
echo "./whois-x86_64 -h apnic 143.128.0.0/16 --show-non-auth-body --show-post-marker-body"
./whois-x86_64 -h apnic 143.128.0.0/16 --show-non-auth-body --show-post-marker-body

echo
echo "./whois-x86_64 -h lacnic 143.128.0.0/16 --show-non-auth-body --show-post-marker-body"
./whois-x86_64 -h lacnic 143.128.0.0/16 --show-non-auth-body --show-post-marker-body

echo
echo '# END'
echo
