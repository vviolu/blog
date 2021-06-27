import logging
import re

import redis
from django.shortcuts import render, redirect

# Create your views here.

from django.http import HttpResponseBadRequest, HttpResponse
from django.views import View

from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

from django.views import View
from django.http.response import JsonResponse
from utils.response_code import RETCODE
import logging

logger = logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP
from users.models import User
from django.db import DatabaseError
from django.urls import reverse


class RegisterView(View):
    """用户注册"""
    def get(self, request):
        return render(request, 'register.html')
    def post(self, request):
        """
        1.接收数据
        2.验证数据
            2.1 参数是否齐全
            2.2 手机号的格式是否正确
            2.3 密码是否符合格式
            2.4 密码和确认密码要一致
            2.5 短信验证码是否和redis中的一致
        3.保存注册信息
        4.返回响应跳转到指定页面
        """
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1 参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要的参数')
        #     2.2 手机号的格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.3 密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')
        #     2.4 密码和确认密码要一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
        #     2.5 短信验证码是否和redis中的一致
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        # 3.保存注册信息
        # create_user 可以使用系统的方法来对密码进行加密
        try:
            user = User.objects.create_user(username=mobile,
                                            mobile=mobile,
                                            password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')

        from django.contrib.auth import login
        login(request, user)  # 调用login方法应该在页面跳转之前 ，注册成功之后
        # 4.返回响应跳转到指定页面
        # 暂时返回一个注册成功的信息，后期再实现跳转到指定页面

        # redirect 是进行重定向
        # reverse 是可以通过 namespace:name 来获取到视图所对应的路由
        response = redirect(reverse('home:index'))
        # return HttpResponse('注册成功，重定向到首页')

        # 设置cookie信息，以方便首页中 用户信息展示的判断和用户信息的展示
        response.set_cookie('is_login', True)
        response.set_cookie('username', user.username, max_age=7 * 24 * 3600)

        return response


class ImageCodeView(View):

    def get(self, request):
        # 1.获取前端传递过来的参数
        uuid = request.GET.get('uuid')
        # 2.判断参数是否为None,即uuid是否获取到了
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误')
        # 3.获取验证码内容和验证码图片二进制数据   通过调用captcha来生成图片验证码
        text, image = captcha.generate_captcha()
        # 4.将图片验内容保存到redis中，并设置过期时间
        # uuid作为一个key 图片内容作为一个value 同时设置过期时间作为实效
        redis_conn = get_redis_connection('default')
        # key设置为uuid
        # seconds 过期秒数 300秒 5分钟过期时间
        # value text
        redis_conn.setex('img:%s' % uuid, 300, text)  # 设置了一个前缀img:%s
        # 5.返回响应，将生成的图片以content_type为image/jpeg的形式返回给请求
        return HttpResponse(image, content_type='image/jpeg')


class SmsCodeView(View):
    # 1.接收参数（查询字符串的形式）
    # 2.参数的验证
    #   2.1验证参数是否齐全
    #   2.2图片验证码的验证
    #      连接redis  获取redis中的图片验证码
    #      判断图片验证码是否存在
    #      如果图片验证码未过期，我们获取到之后就可以删除图片验证码
    #       比对图片验证码（）不区分大小写
    # 3.生成短信验证码
    # 4.保存短信验证码到redis中 5.发送短信 6。返回响应
    def get(self, request):
        # 接收参数
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')

        # 校验参数
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要参数'})

        # 创建连接到redis的对象
        redis_conn = get_redis_connection('default')
        # 提取图形验证码
        redis_image_code = redis_conn.get('img:%s' % uuid)
        if redis_image_code is None:
            # 图形验证码过期或者不存在
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码已过期'})
        # 删除图形验证码，避免恶意测试图形验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        # 对比图形验证码 注意大小写的问题 redis的数据是bytes类型
        # image_code = image_code.decode()  # bytes转字符串
        if redis_image_code.decode().lower() != image_code.lower():  # 转小写后比较
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码有误'})

        # 生成短信验证码：生成6位数验证码
        sms_code = '%06d' % randint(0, 999999)  # 生成随机六位验证码
        # 为了后期比对方便 可将短信验证码记录到日志中
        logger.info(sms_code)
        # 保存短信验证码到redis中，并设置有效期
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 发送短信验证码
        # 参数1：测试手机号
        # 参数2（列表）：您的验证码是{1}，请于{2}分钟内正确输入
        #   {1}短信验证码   {2}短信有效期
        # 参数3：免费开发测试使用的模板id为1
        CCP().send_template_sms(mobile, [sms_code, 5], 1)

        # 响应结果
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '发送短信成功'})


class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    '''
            1.接收参数
            2.参数的验证
                2.1验证手机号是否符合规则
                2.2验证密码是否符合规则
            3.用户认证登录
            4.状态的保持
            5.根据用户的选择是否记住登录状态
            6.为了首页显示我们需要设置一些cookie信息
            7.返回响应

            :param request:
            :return:
            '''

    def post(self, request):
        # 接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')

        # 校验参数
        # 判断参数是否齐全
        if not all([mobile, password]):
            return HttpResponseBadRequest('缺少必传参数')

        # 判断手机号是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码最少8位，最长20位')

        # 认证登录用户,采用系统自带的认证方式进行认证
        # 如果用户名和密码正确，会返回user
        # 如果用户名和密码有一个不正确，会返回none
        # 认证字段已经在User模型中的USERNAME_FIELD = 'mobile'修改(当前的判断信息是手机号)
        #
        from django.contrib.auth import authenticate
        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        # 实现状态保持
        from django.contrib.auth import login
        login(request, user)

        # 根据next参数来进行页面的跳转

        # 响应登录结果
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))  # 跳转到首页

        # 设置状态保持的周期,根据用户选择的是否记住登录状态来判断
        if remember != 'on':
            # 没有记住用户：浏览器会话结束就过期
            # 浏览器关闭之后
            request.session.set_expiry(0)
            # 设置cookie
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:
            # 记住用户：None表示默认两周后过期
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        # 返回响应
        return response


from django.contrib.auth import logout


class LogoutView(View):
    def get(self, request):
        # 1.session数据清除
        logout(request)
        # 2。删除部分cookie数据
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')  # 清除登录状态
        # 3.跳转到首页
        return response


class ForgetPasswordView(View):

    def get(self, request):

        return render(request, 'forget_password.html')

    def post(self, request):
        """
        1.接收数据
        2.验证数据
            2.1 判断参数是否齐全
            2.2 手机号是否符合格则
            2.3 判断密码是否符合格则
            2.4 判断确认密码和密码是否一致
            2.5 判断短信验证码是否正确
        3.根据手机号进行用户信息的查询
        4.如果手机号查询出用户信息则进行用户密码的修改
        5.如果手机号没有查询出用户信息，则进行新用户的创建
        6.进行页面跳转，跳转到登录页面
        7.返回响应
        :param request:
        :return:
        """
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1 判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('参数不全')
        #     2.2 手机号是否符合格则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合格则')
        #     2.3 判断密码是否符合格则
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合格则')
        #     2.4 判断确认密码和密码是否一致
        if password2 != password:
            return HttpResponseBadRequest('密码不一致')
        #     2.5 判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息的查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5.如果手机号没有查询出用户信息，则进行新用户的创建
            try:
                User.objects.create_user(username=mobile,
                                         mobile=mobile,
                                         password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')

        else:
            # 修改用户密码
            user.set_password(password)
            user.save()

            # 跳转到登录页面
        response = redirect(reverse('users:login'))

        return response


from django.contrib.auth.mixins import LoginRequiredMixin


# LoginRequiredMixin
# 如果用户未登陆的话，会进行默认的跳转
# 默认的跳转连接accounts/login/?next=/***(next后就是要跳转的路由)
class UserCenterView(LoginRequiredMixin, View):

    def get(self, request):
        # 获取用户信息
        user = request.user

        # 组织模板渲染数据/组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,  # 头像可为空
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        # 1.接收参数
        # 2.将参数保存起来
        # 3.更新cookie中的username信息
        # 4.刷新当前页面（重定向操作）
        # 5.返回响应

        # 接收数据
        user = request.user
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)
        avatar = request.FILES.get('avatar')

        # 修改数据库数据
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        response = redirect(reverse('users:center'))
        # 更新cookie信息
        response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        return response

    from django.views import View


from django.views import View
from home.models import ArticleCategory, Article


class WriteBlogView(LoginRequiredMixin, View):

    def get(self, request):
        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }
        return render(request, 'write_blog.html', context=context)

    def post(self, request):


        # 接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user

        # 验证数据是否齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全')

        # 判断文章分类id数据是否正确
        try:
            article_category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类信息')

        # 保存到数据库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                category=article_category,
                tags=tags,
                title=title,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后再试')

        # 返回响应，跳转到文章详情页面
        # 暂时先跳转到首页
        return redirect(reverse('home:index'))
