from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.


#定义用户信息  在系统的父类AbstractUser上进行扩展
class User(AbstractUser):
    #手机号
    mobile=models.CharField(max_length=11,unique=True,blank=False)#手机号不能为空
    #头像信息
    avatar=models.ImageField(upload_to='avatar/%Y%m%d',blank=True)#设置头像图片上传路径以及命名格式，且头像可为空
    #简介信息
    user_desc=models.TextField(max_length=500,blank=True)

    # 修改认证的字段
    USERNAME_FIELD = 'mobile'
    # 创建超级管理员的需要必须输入的字段
    REQUIRED_FIELDS = ['username', 'email']


#修改配置信息 如表名等
    class Meta:
        db_table='tb_users'#修改表名
        verbose_name='用户信息'#admin后台显示
        verbose_name_plural=verbose_name#admin后台显示

#为了方便调试
    def __str__(self):
        return self.mobile



