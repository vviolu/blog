from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View

from home.models import ArticleCategory,Article
from django.http.response import HttpResponseNotFound
from home.models import Comment
class IndexView(View):
    def get(self, request):
        '''
        1.获取所有分类信息
        2.接收用户点击的分类id
        3.根据分类id进行分类的查询
        4.获取分页参数
        5.根据分类信息查询文章数据
        6.创建分页器（利用分页器帮助实现分页）
        7.进行分页处理
        8.组织数据传递给模板
        :param request:
        :return:
        '''
        """提供首页广告界面"""
        #?cat_id=xxx&page_num=xxx&page_size=xxx
        cat_id=request.GET.get('cat_id',1)
        page_num = request.GET.get('page_num', 1)
        page_size = request.GET.get('page_size', 10)

        #判断分类id
        try:
            category = ArticleCategory.objects.get(id=cat_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseNotFound('没有此分类')

        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        # 分页数据
        articles = Article.objects.filter(
            category=category
        )
        # 创建分页器：每页N条记录
        from django.core.paginator import Paginator,EmptyPage
        paginator = Paginator(articles, page_size)
        # 获取每页商品数据
        try:
            page_articles = paginator.page(page_num)
        except EmptyPage:
            # 如果没有分页数据，默认给用户404
            return HttpResponseNotFound('empty page')
        # 获取列表页总页数
        total_page = paginator.num_pages
        context = {
            'categories':categories,
            'category':category,
            'articles': page_articles,
            'page_size': page_size,
            'total_page': total_page,
            'page_num': page_num,
        }

        return render(request, 'index.html',context=context)

class DetailView(View):

    def get(self, request):
        '''
        1.接收文章id信息
        2.根据文章id进行文章数据的查询
        3.查询分类数据
        4.获取分页参数
        5.根据分类信息查询文章数据
        6.创建分页器（利用分页器帮助实现分页）
        7.进行分页处理
        8.组织模板数据
        :param request:
        :return:
        '''
        # detail/?id=xxx&page_num=xxx&page_size=xxx
        # 获取文档id
        id = request.GET.get('id')

        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        try:
            article = Article.objects.get(id=id)
        except Article.DoesNotExist:
            return render(request, '404.html')
        else:
            #让浏览量+1
            article.total_views+=1
            article.save()

        #查询分类数据
        categories=ArticleCategory.objects.all()

        #查询浏览量前10的文章数据
        hot_article=Article.objects.order_by('-total_views')[:9]
        #获取分页请求的参数
        page_size=request.GET.get('page_size',10)#未传递过来则每一页传递十条数据
        page_num=request.GET.get('page_num',1)

        #根据文章信息查询评论数据
        comments=Comment.objects.filter(article=article).order_by('-created')
        # 获取评论总数
        total_count = comments.count()
        #创建分页器
        from django.core.paginator import Paginator,EmptyPage
        paginator=Paginator(comments,page_size)
        #进行分页处理
        try:
            page_comment=paginator.page(page_num)
        except EmptyPage:
            return HttpResponseNotFound('empty page')
        #获取总页数
        total_page=paginator.num_pages



        context = {
            'categories': categories,#所有的分类信息
            'category': article.category,#当前的分类信息
            'article': article,#文章信息
            'hot_articles':hot_article,
            'total_count':total_count,
            'comments':page_comment,
            'page_size':page_size,
            'total_page':total_page,
            'page_num':page_num
        }

        return render(request, 'detail.html', context=context)

    def post(self, request):
        '''
        1.先接受用户信息
        2.判断用户是否登录
        3.登录用户则可以接收form数据
            3.1接收评论数据
            3.2验证文章是否存在
            3.2保存评论数据
            3.3修改文章的评论数量
        4.未登录用户则跳转到登录页面
        :param request:
        :return:
        '''

        # 获取用户信息
        user = request.user

        # 判断用户是否登录
        if user and user.is_authenticated:
            # 接收数据
            id = request.POST.get('id')
            content = request.POST.get('content')

            # 判断文章是否存在
            try:
                article = Article.objects.get(id=id)
            except Article.DoesNotExist:
                return HttpResponseNotFound('没有此文章')

            # 保存到数据
            Comment.objects.create(
                content=content,
                article=article,
                user=user
            )
            # 修改文章评论数量
            article.comments_count += 1
            article.save()
            # 拼接跳转路由  刷新当前页面（页面重定向）
            path = reverse('home:detail') + '?id={}'.format(article.id)
            return redirect(path)
        else:
            # 没有登录则跳转到登录页面
            return redirect(reverse('users:login'))