# LFTP
LFTP是一个文件传输系统。程序分为客户端和和服务端。客户端可以从服务端下载文件，或上传文件到服务端。
## 使用
### 服务端
```bash
LFTP_server <path> <port>
```
path为文件接受或上传的路径，port为服务器监听的端口，默认为2121
### 客户端
上传文件：
```bash
LFTP lsend myserver mylargefile
```
下载文件
```bash
LFTP lget myserver mylargefile
```
参数含义：
- myserver: 服务器地址（域名或ip地址，带端口号，端口号默认为2121）
- mylargefile: 待上传或下载的文件名称

## 特性
- LFTP使用UDP作为传输层协议
- LFTP保证100%的传输可靠性
- LFTP实现了类似TCP的流控制
- LFTP实现了流水线式的报文传输
- LFTP实现了类似TCP的拥塞控制
- LFTP允许多个用户同时进行文件传输
- LFTP能够拒绝未建立连接的用户进行文件交换

# 文档
设计文档，测试文档见项目目录中的doc文件夹

# 性能测试
> 详细测试结果请查看doc文件夹下的测试文档
## 理想网络传输
![](https://github.com/MrFive5555/CN_LFTP/blob/master/doc/result_pic/ideal%20network.png?raw=true)  
在理想网络环境下传输时，文件几乎是匀速传输
## 模拟拥塞网络
![](https://github.com/MrFive5555/CN_LFTP/blob/master/doc/result_pic/simulated%20network.png?raw=true)  
在模拟的拥塞网络下，传输曲线表现出了更复杂的形状，在传输过程中会有速度的变化，但总体没有与理想情况下的直线形状偏差太多（因为模拟网络中的时延有一个固定的均值）。而当我们靠近一点看的时候，可以看见曲线上有一些不光滑的凹凸，这些是出现较大时延或丢包时出现时的波动。
## 多用户同时传输
![](https://github.com/MrFive5555/CN_LFTP/blob/master/doc/result_pic/multiClient.png?raw=true)  
这里我们让三个用户同时向服务器请求文件，可以看见，三者之间没有一个会全部占用网络带宽，服务器可以较公平地处理这三个连接的传输请求。