#### 2018/07/16
* 选题 
   * 开发语言为Python3.6.3
   * 后端基于Django框架
   * 前端基于Bootstrap框架
   * 使用Apache服务器
   * 使用MySQL数据库
* 环境搭建
   * 搭建Linux环境（部分完成）
   * Windows环境搭建（基本完成）
     * Django 
     * pymysql
     * django-simple-captcha


#### 2018/07/17
* 搭建网站
  * 登录注册系统搭建完成（未加密）
  * 前端界面基本完成
  * 参考教程：https://blog.csdn.net/laikaikai/article/details/80563387



#### 2018/07/25
* 可以通过域名访问网站，域名绑定https（使用自签发证书）
* 登录注册系统
   * 用户密码哈希存储
   * 用户注册时分配公私钥并存储
   * 非对称密钥使用Cryptography模块中的RSA算法
   * 哈希算法使用passlib模块中的sha256算法
* 文件上传完成
   * 完成文件上传相关限制 
   * 文件分配对称密钥
   * 文件对称密钥加密并签名存储
   * 对称密钥用公钥加密存储
   * 对称密钥使用Cryptography模块中的Fernet算法
   * 非对称密钥使用Cryptography模块中的RSA算法


