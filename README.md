# 基于 netfilter 动态包过滤

### 实验环境: 
```
ubuntu18.04
```

### 编译: 
```
git clone https://github.com/qwganker/flowfirewall
cd ./dynamicfilter && make
```

### 运行:
- 加载内核模块
```
sudo insmod firewall.ko
```

- 运行控制器
```
cd ./uadmin
./a.out
```

### 使用说明
- 查看已添加规则
> ./a.out --action list

- 停止过滤
> ./a.out --action stop

- 启动过滤
> ./a.out --action start

- 添加过滤规则
> ./a.out --action add --sip [源ip] --sport [源端口] --tport [目的端口]

- 删除过滤规则
> ./a.out --action del --sip [源ip] --sport [源端口] --tport [目的端口]

