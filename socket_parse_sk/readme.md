#### Ethernet II 类型
```txt
目标Mac    源Mac     类型    数据               FCS
6byte       6byte   2byte    46-1500byte        4byte
```
&emsp; 在接下来数据段的两个字节标识所携带的上层数据类型, 0x0800 IP协议 0x809B 代表AppleTalk等

4字节FCS是对从目标mac到数据段的校验。

##### Ethernet 802.3raw
格式
```txt
目标Mac    源Mac   总长度    0xFFFF    数据               FCS
6byte       6byte   2byte      2byte   44-1498byte        4byte
```
> 0xFFFF 代表它是Novll 以太网类型


#### Ethernet 802.3 SAP格式
格式
```txt
目标MAC地址         源MAC地址    总长度        DSAP    SSAP    控制       数据       FCS
  6byte             6byte        2byte        1byte    1byte   1bye     43-1497byte  4byte 
```
&emsp;1个字节的控制字段构成802.2逻辑链路的控制首部(LLC)， LLC提供无连接(LLC1类型)和面向链接的(LLC2)的网络服务。LLC1 用于以太网中，LLC2用于IBM SNA网络环境里面。
&emsp;DSAP(源服务访问点)  SSAP(目标服务访问点) .他们用于表示以太网帧携带的上层数据类型, 0x06 代表IP协议数据， 0xE0 代表Novel类型， 0xF0 代表IBM NETBIOS类型



