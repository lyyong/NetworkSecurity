# 信息安全实验
以下实验均使用linux版本：ubuntu18.04，内核版本5.4
## 实验1
实验内容：ICMP重定向攻击

文件夹：exp1_1

主要原理：通过raw socket截取IP报文，获得报文中的原IP地址，然后伪造网关IP构造出ICMP重定向报文，发回原IP


## 实验2
### 任务1
实验内容：使用iptables命令完成nat功能

推荐文章：https://www.zsythink.net/archives/1199 学习iptables概念

文件夹：exp2_1

### 任务2
实验内容：使用内核代码实现自己的netfilter

文件夹：exp2_2

khello是用来熟悉内核编成的helloworld代码，nf是实验代码

主要原理：创建一个钩子函数然后注册到postrouting链中，得到出站的MAC帧，然后层层剥离得到TCP数据然后进行相应处理

使用到的命令：
- `make` 构建内核模块，构建完后会生成`.ko`文件
- `sudo insmod  ko文件` 将模块添加到内核中
- `sudo rmmod ko文件` 移除模块
- `dmesg | tail` 打印内核日志的末尾，也可以不用tail打印所有日志

## 实验3
实验内容：使用内核级rootkit隐藏某个端口

文件夹：exp3

主要原理：一定要在内核版本5.8之前，新内核不能使用函数`kallsyms_lookup_name` 获得系统内核数据，原理修改tcp4_seq_ops中的show函数。tcp4_seq_ops结构是处理tcp连接数据从内核区导出到/proc/net/tcp文件的函数。