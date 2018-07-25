from django.shortcuts import render
# -*- coding: utf-8 -*-
# Create your views here.
# login/views.py
import os
from django.shortcuts import render, redirect
from . import models
from .forms import UserForm
from .forms import RegisterForm
from .forms import FileUploadForm
import re
from passlib.hash import sha256_crypt
from django.http import HttpResponse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes



def index(request):
    pass
    return render(request, 'login/index.html',locals())


def login(request):
    # 防止重复登录
    if request.session.get('is_login', None):
        return redirect('/index')

    if request.method == "POST":
        login_form = UserForm(request.POST)
        message = "请检查填写的内容！"
        if login_form.is_valid():
            username = login_form.cleaned_data['username']
            password = login_form.cleaned_data['password']
            try:
                user = models.User.objects.get(name=username)
                # 进行哈希值的比对
                if sha256_crypt.verify(password, user.password):
                    # 往session字典内写入用户状态和数据
                    request.session['is_login'] = True
                    request.session['user_id'] = user.id
                    request.session['user_name'] = user.name
                    return redirect('/index/')
                else:
                    message = "密码不正确！"
            except:
                message = "用户不存在！"
        return render(request, 'login/login.html', locals())

    login_form = UserForm()
    return render(request, 'login/login.html', locals())


def register(request):
    if request.session.get('is_login', None):
        # 登录状态不允许注册,可以修改这条原则！
        return redirect("/index/")
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():  # 获取数据
            username = register_form.cleaned_data['username']
            # 匹配数字、字母、中文和特殊字符
            p = re.compile(r'[0-9]*[a-z]*[A-Z]*[\-]*[\_]*[\.]*[\u4e00-\u9fa5]*')
            if '' in p.findall(username)[:-1]:
                message = '用户名不合法，请重新输入！\n' \
                          '请注意：用户名仅可包含中文、英文字母、数字、特殊字符(.、-、_)'
                return render(request, 'login/register.html', locals())
            password1 = register_form.cleaned_data['password1']
            password2 = register_form.cleaned_data['password2']
            email = register_form.cleaned_data['email']
            sex = register_form.cleaned_data['sex']
            pasw = re.compile(r'[0-9]+[a-z]+[A-Z]+')
            if len(password1) < 8:
                message = "密码过短，至少8位，至多36位！"
                return render(request, 'login/register.html', locals())
            elif password1 != password2:  # 判断两次密码是否相同
                message = "两次输入的密码不同！"
                return render(request, 'login/register.html', locals())
            elif pasw.findall(password1) == []:
                message = '密码强度低！请注意同时包含大、小写字母和数字。'
                return render(request, 'login/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:  # 用户名唯一
                    message = '用户已经存在，请重新选择用户名！'
                    return render(request, 'login/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:  # 邮箱地址唯一
                    message = '该邮箱地址已被注册，请使用别的邮箱！'
                    return render(request, 'login/register.html', locals())

                # 当一切都OK的情况下，创建新用户

                new_user = models.User.objects.create()
                new_user.name = username
                # 使用passlib中的SHA-256哈希存储
                new_user.password = sha256_crypt.encrypt(password1)
                new_user.email = email
                new_user.sex = sex
                # 生成公私钥对并存储
                # 生成用户私钥
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=1024,
                    backend=default_backend()
                )
                # 序列化私钥为pem格式
                prv_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    # 无密码
                    encryption_algorithm=serialization.NoEncryption()
                    # 也可以加入密码保护私钥:
                    # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
                )
                # 保存私钥序列
                new_user.privkey = str(prv_pem, encoding='utf-8')
                # 依据用户私钥生成公钥
                public_key = private_key.public_key()
                # 序列化公钥为pem格式
                pub_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # 保存公钥序列
                new_user.pubkey = str(pub_pem, encoding='utf-8')
                new_user.save()
                return redirect('/login/')  # 自动跳转到登录页面
    register_form = RegisterForm()
    return render(request, 'login/register.html', locals())


def logout(request):
    if not request.session.get('is_login', None):
        # 如果本来就未登录，不存在登出
        return redirect("/index/")
    request.session.flush()
    # flush()方法是比较安全的一种做法，
    # 而且一次性将session中的所有内容全部清空，
    # 确保不留后患。但也有不好的地方，
    # 那就是如果在session中夹带了一点‘私货’，
    # 会被一并删除。

    # 或者使用下面的方法
    # del request.session['is_login']
    # del request.session['user_id']
    # del request.session['user_name']
    return redirect("/index/")


# 提交文件并加密签名
def handle_upload_file(file, userfile):
    content = b''
    # 随机生成对称加密密钥
    userfile.enckey = Fernet.generate_key()
    key = Fernet(userfile.enckey)
    # 获取当前用户私钥进行加密后的签名
    uvk = serialization.load_pem_private_key(
        bytes(models.User.objects.get(name=userfile.username).privkey, encoding='utf-8'),
        # 读入私钥此处还有: password=b'xxxx',
        password=None,
        backend=default_backend()
    )
    signer = uvk.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # 分块加密并签名, 每个chunk默认2.5MB，可以修改
    with open("./static/files/%s" % file.name, 'wb+') as f:
        for chunk in file.chunks():
            content += chunk
            # 先使用对称密钥加密，然后使用用户私钥签名存储
            c = key.encrypt(chunk)
            signer.update(c)
            f.write(signer.finalize())
    # passlib中sha256输入最长为4096个字符，还没想到好的文件哈希方法，先前截取4096位
    userfile.sha256 = sha256_crypt.hash(str(content,'utf-8')[0:4096])  # str1.encode('utf-8')
    f.close()


def upload(request):
    if request.method == "POST":
        uf = FileUploadForm(request.POST, request.FILES)
        if uf.is_valid():
            if request.FILES['filename'].size > 10*1024*1024:
                return HttpResponse("文件过大! 请选择10MB以下的文件。")
                # return render(request, 'login/upload.html', {'uf': uf}, locals())
            # 取出文件后缀名，匹配文件类型；可以使用python自带的filetype判断文件类型，但是没有office的文件类型，没想到其他方法
            # 文件类型为常见的图片格式和office文件格式
            ftype = ['.jpg', '.png', '.jpeg', '.bmp', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
            if os.path.splitext(request.FILES['filename'].name)[1] not in ftype:
                return HttpResponse("不支持的文件类型，仅支持jpg/jpeg/png/bmp以及office文件。")
                # return render(request, 'login/upload.html', {'uf': uf}, locals())
            else:
                # 创建文件，写入数据库
                file = models.file.objects.create()
                file.username = request.session['user_name']
                file.filename = request.FILES['filename'].name
                file.size = request.FILES['filename'].size
                # 加密 enckey.encrypt(file)
                # 解密 enckey.decrypt(enc_file)
                # 加密存储
                handle_upload_file(request.FILES['filename'], file)
                # 加密对称密钥，使用用户公钥加密
                # 获取当前用户公钥
                upk = serialization.load_pem_public_key(
                    bytes(models.User.objects.get(name=file.username).pubkey, encoding='utf-8'),
                    backend=default_backend()
                )
                # 对称密钥用公钥加密并保存
                file.enckey = upk.encrypt(
                    file.enckey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                file.save()
                # message = "上传成功！"
                return HttpResponse('上传成功!')
    else:
        uf = FileUploadForm()
    return render(request, 'login/upload.html', {'uf': uf}, locals())


def download(request):
    pass
    return render(request, 'login/download.html')