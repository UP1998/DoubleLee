# Create your models here.
# login/models.py

from django.db import models


class User(models.Model):
    '''用户表'''

    gender = (
        ('male', '男'),
        ('female', '女'),
    )

    name = models.CharField(max_length=128, unique=True)
    password = models.CharField(max_length=256)
    email = models.EmailField(unique=True)
    sex = models.CharField(max_length=32, choices=gender, default='男')
    c_time = models.DateTimeField(auto_now_add=True)
    pubkey = models.CharField(max_length=2048, default=' ')  # 用户公钥
    privkey = models.CharField(max_length=2048, default=' ')  # 用户私钥

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['c_time']
        verbose_name = '用户'
        verbose_name_plural = '用户'


# 文件模型
class file(models.Model):
    '''文件'''
    username = models.CharField(max_length=128, unique=True)  # 上传用户名
    filename = models.FileField(upload_to = 'upload/%Y%m%d')  # 文件名
    size = models.IntegerField(default=0)    # 文件大小
    enckey = models.CharField(max_length=2048, default=' ')  # 用于加密的对称密钥，使用用户公钥加密存储
    sha256 = models.CharField(max_length=256, default=' ')  # 明文文件的sha256
    create_time = models.DateTimeField(auto_now_add=True)  # 上传时间

    def __unicode__(self):
        return self.username

# # 分享模型
# class share(models.Model):
#     '''分享'''
#     uid = models.IntegerField(max_length=11)
#     fid = models.IntegerField(max_length=11)
#     sharekey = models.CharField(max_length=60)  # 分享链接使用的解密口令，采用与登录口令相同的哈希
#     enckey = models.CharField(max_length=2048)  # 用于解密的对称密钥
#     filepath = models.CharField(max_length=255)  # 文件路径








