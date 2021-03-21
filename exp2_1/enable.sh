sudo sysctl -w net.ipv4.ip_forward=1;
sudo sysctl -p;
# 主机请求, 进来时在pre修改目的地址, 在post修改源地址

sudo iptables -t nat -I PREROUTING 1 -d 192.168.121.132 -p tcp --dport 80 -j DNAT --to-destination 192.168.121.142:8080;
sudo iptables -t nat -I POSTROUTING 1 -d 192.168.121.142 -p tcp --dport 8080 -j SNAT --to-source 192.168.121.132;

# 服务器出去, 进来时在pre修改目的地址, 在post修改源地址
# iptables -t nat -I PREROUTING 1 -d 192.168.121.132 -p tcp -j DNAT --to-destination 192.168.121.141;
# 如果使用上面的代码, 上面的命令优先级高于第一条命令因为用来头插法,导致客户端发出的141->132变为 141->141的包
sudo iptables -t nat -A PREROUTING -d 192.168.121.132 -p tcp -j DNAT --to-destination 192.168.121.141;
sudo iptables -t nat -A POSTROUTING -s 192.168.121.142 -p tcp -j SNAT --to-source 192.168.121.132:80;