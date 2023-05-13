# whatweb-plus 

whatweb-plus 是基于国际通用的 Whatweb 优化改造的国内版Web指纹识别工具。

主体程序:
https://github.com/winezer0/whatweb-plus

插件存储:
https://github.com/winezer0/whatweb-plus-plugins

原始项目:
https://github.com/urbanadventurer/WhatWeb



为限制git文件夹大小,现已对项目文件夹结构进行清理。

后续windows可执行文件下载请访问 [Releases页面](https://github.com/winezer0/whatweb-plus/releases/)




# TODO

```
日常:
对指纹扫描插件 文件夹分类、风险级别分级、重复文件合并。
```

# 功能支持

```
1、多种插件分类和加载方案：
    1、支持多级目录插件分类和加载.[新增]
    2、支持按插件名称 指定加载、 [原生]
    3、支持按插件目录 指定加载、 [原生]
2、最小化重复目标请求.          [新增]
3、提供exe程序直接运行.         [新增]
4、优化插件加载目录设置：
  默认加载插件路径：
    1、当前命令行环境路径.      [新增]
    2、whatweb.exe及 whatweb.rb 路径. [新增]
    3、lib目录的相对路径的上一级.             [默认]
    4、Windows下的用户目录下的whatweb目录.    [新增]
    5、Linux下的用户目录下的whatweb目录.      [新增]
    6、linux自己安装的/opt/whatweb 目录.     [新增]
    7、Kali默认安装的/usr/share/whatweb     [默认]
  注意：默认加载插件路径下的plugins或my-plugins目录.   [优化]
  注意：建议同时只使用一种默认路径方式,以免插件重复.

5、支持对输入的域名,同时添加http和https协议头进行测试.   [优化]

6、支持按照插件的风险级别来调用插件,如只调用中高风险的插件(-r 3).    [新增]
```



# 最近更新

请查看更新记录: [更新记录](doc/更新记录.md) 

# 新增参数

请求限制相关参数

```
--add-path --ap
    新增，自动访问高频指纹路径，默认false
    自动访问常用路径访问如:/favicon.ico，/robots.txt

--min-urls --mu
    新增，最小化访问插件:url，默认false
    将匹配插件的每一个请求URL作为完整的新URL作为请求，以避免全局重复请求相同的URL. 缺点是会表现出一个站点的多个子请求，建议使用novafinger.py包装器的--log-csv参数进行结果输出，便于排序处理

--max-match --mm
    新增，忽略匹配:url要求，默认false
    精选匹配规则时，忽略需要:url相同的前提，形成更多的结果匹配，需要更多匹配时可以开启
```



请求设置参数

```
--update-cookies
  根据响应自动的更新cookie
```



插件过滤参数

```
--risk-level, -r=RISK 
  设置调用指定的风险级别的插件级。默认值: 1
  1. None 为每个目标调用无风险和更高级别的插件
  2. Low 为每个目标调用低风险和更高级别的插件
  3. Mid 为每个目标调用中等风险和更高级别的插件
  4. High 为每个目标调用高风险和更高级别的插件

--risk-exact, --re 
  仅调用指定等级的插件,不调用更高级别的插件。默认值:false

risk属性配置示例:
  Plugin.define do
  name "HTML5"
  authors [ "Andrew Horton", ]
  risk 2  # 加risk行即可配置
  version "0.2"
  ....
  end
 
注意事项： risk属性需要在插件内配置,没有配置就默认为None级别。
```



# 注意事项

```
1.关于运行环境
    使用ruby运行whatweb脚本，需要安装mmh3模块 [gem install mmh3]
    windows下有exe打包版本，其他系统未打包成功，需要安装ruby环境（kali ruby2.5-2.7 测试通过） 
    whatweb.exe为了缩小打包体积，仅包含简单的基础插件

2.关于WAF指纹识别
	支持WAf指纹，但没有添加会触发waf的请求,需要用户主动请求会触发waf的请求.
	如 whatweb http://www.baidu.com/index?/etc/passed
```

# 程序安装



Windows系统下可以直接使用release下的whatweb.exe文件，无需配置任何环境即可运行.

kali Linux及其他Linux操作系统请查看安装教程: [安装教程](doc/安装教程.md) 



# 使用说明

汉化版help说明请查看: 

请查看使用说明: [使用说明](doc/使用说明.md) 



# 其他参考

Whatweb 0.5.5.12 完善使用及插件文档【非常重要,记录各种功能更新及基本使用】

https://mp.weixin.qq.com/s/F9sXIhCfFCZ3WtMMltnP5Q

痛点重谈-Web指纹识别与解决方案-NOVASEC

https://mp.weixin.qq.com/s/lHIJmIWbm8ylK6yjjmmNkg

Whatweb特征修改、插件编写、EXE打包

https://mp.weixin.qq.com/s/TaYHrzw5Yb6jxj046nR_DA

NOVASEC 开源工具记录

https://mp.weixin.qq.com/s/h4rYBZ36xaEHF34vyW4WQg

里程碑思路: Go工具框架实现动态插件

https://mp.weixin.qq.com/s/ihNalwYQGNcWlG7TJ8yazw

whatweb增强版公开发布

https://mp.weixin.qq.com/s/njxWqxw-TJH2MKAvOvI-kg



# NEED STAR And ISSUE

```
1、右上角点击Star支持更新.
2、ISSUE或NOVASEC提更新需求
```

![NOVASEC](doc/NOVASEC.jpg)
