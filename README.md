# GmSSL 3.1.1-wl

## 编译与安装

GmSSL 3.0 采用了cmake构建系统。下载源代码后将其解压缩，进入源码目录，执行：

```bash
mkdir build
cd build
cmake ..
make
make test
sudo make install
```
在`make install`完成后，GmSSL会在默认安装目录中安装`gmssl`命令行工具，在头文件目录中创建`gmssl`目录，并且在库目录中安装`libgmssl.a`、`libgmssl.so`等库文件。

### Visual Studio环境编译

在Visual Studio命令提示符下执行：

```bash
mkdir wbuild
cd wbuild
cmake .. -G "NMake Makefiles"
nmake
```
如果需要重新编译可用
```
nmake clean
nmake all
```

## 主要功能

### 密码算法

* 分组密码：SM4 (CBC/CTR/GCM), AES (CBC/CTR/GCM)
* 序列密码：ZUC/ZUC-256, ChaCha20, RC4
* 哈希函数: SM3, SHA-224/256/384/512, SHA-1, MD5
* 公钥密码：SM2加密/签名, SM9加密/签名
* MAC算法：HMAC, GHASH
* 密钥导出函数：PBKDF2、HKDF
* 随机数生成器：Intel RDRAND, HASH_DRBG (NIST.SP.800-90A)

### 证书和数字信封

* 数字证书：X.509证书, CRL证书注销列表, CSR (PKCS #10) 证书签名请求
* 私钥加密：基于SM4/SM3口令加密的PEM格式私钥 (PKCS #8)
* 数字信封：SM2密码消息 (GM/T 0010-2012)

### SSL协议

* TLCP 1.1，支持密码套`TLS_ECC_SM4_CBC_SM3 {0xE0,0x13}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.2，支持密码套件`TLS_ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.3，支持密码套件`TLS_SM4_GCM_SM3 {0x00,0xC6}`  (RFC 8998)