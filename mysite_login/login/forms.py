from django import forms
from captcha.fields import CaptchaField
from passlib.hash import sha256_crypt


# 用户表单
class UserForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=128, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label="密码", max_length=36, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    captcha = CaptchaField(label='验证码')


# 注册表单
class RegisterForm(forms.Form):
    gender = (
        ('male', "男"),
        ('female', "女"),
    )
    username = forms.CharField(label="用户名", max_length=128, widget=forms.TextInput(attrs={'class': 'form-control'}))
    # 设置密码长度最大为36
    # password1和password2，用于输入两遍密码，并进行比较，防止误输密码；
    password1 = forms.CharField(label="密码", max_length=36, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    password2 = forms.CharField(label="确认密码", max_length=36, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    # email是一个邮箱输入框；
    email = forms.EmailField(label="邮箱地址", widget=forms.EmailInput(attrs={'class': 'form-control'}))
    # sex是一个select下拉框；
    sex = forms.ChoiceField(label='性别', choices=gender)
    # 验证码
    captcha = CaptchaField(label='验证码')