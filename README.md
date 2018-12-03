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