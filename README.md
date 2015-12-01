引子

由于我们部门web业务上线频繁，对外接口使用较多，为了保证基本安全，每次上线前都会进行一般安全测试规避风险。一般测试有SQL注入测试，XSS测试，CSRF测试等。涵盖OWASP top 10。

但是随着业务发展，接口越来越多，普通的手动安全测试越来越制约项目上线时间，如何做到能保存测试进展也是需要解决的问题。

因为几个问题越来越突出，我决定开发一套安全测试工具，保证我们所有安全测试过程和结果都能查询，且对QA同事是无感知的，故有了此文。


代理+DB+安全工具的模式

我设想是，安全工程师负责安全测试样例的输出，而正常请求记录最好交给QA同事在逻辑测试阶段，这样有两个好处：

1、保证研发所有上线的接口都能涵盖；

2、安全和QA可以并行测试互不影响，QA只需要做一遍逻辑测试流程即可，加快上线时间；

所以后面的事情也很顺理成章：

1、利用libmproxy开发一款代理工具，且能将HTTP请求记录到数据库；

2、有一个任务调度程序，能够识别下发的攻击类型，利用HTTP请求记录生成payload，并将结果反馈给数据库并记录；

3、有页面能够展示测试样例，测试结果，安全测试类型并对能选择测试安全项；

如图：
![alt tag](https://cloud.githubusercontent.com/assets/1246088/11491341/fc2da8ce-981b-11e5-920e-e03883c4b8d6.jpg)


工具实现

所以有了几个需求，那么可以开始编码了，先看一下完成图。

![alt tag](https://cloud.githubusercontent.com/assets/1246088/11491343/fe271ea8-981b-11e5-8e72-f031127c1122.jpg)

![alt tag](https://cloud.githubusercontent.com/assets/1246088/11491345/ff8608cc-981b-11e5-8e53-e6aaaa6f911b.jpg)

代理工具编写

这个项目其实是来源于我当时给某客户做安全测试的时候写的一个工具，即就是利用libmproxy作为代理，记录所有HTTP/HTTPS请求，并自动修改请求。

当时因为测试的是手机应用，在频繁点击手机交互UI的适合，还要兼顾每个http/https请求这要求测试人员要么是哪吒可以并行进行，要么有一款合适的工具能够记录HTTP/HTTPS请求并处理后进行测试。

刚开始我也是使用burpsuite来进行代理的测试，不想再造一个轮子了，但是到了项目中期，我发现使用burpsuite有几个问题：

1、需要手动指定payload位置；

2、所有攻击过程和结果不能记录；

3、太多接口很容易重复测试和漏测；

libmproxy环境搭建

参考了很多国内网大牛写的文档以后，我决定使用libmproxy来编写我自己的代理工具，并且要求运行在centOS系统上，因为libmproxy在centOS环境搭建不属于此文重点，有这个需求的同学请移步：

http://www.icsoft.ca/2014/11/install-mitmproxy-on-centos-6-x64.html

注意：最后一步pip install mitmproxy可能会出错，是由于版本不适配导致,解决办法：

git clone git://github.com/mitmproxy/mitmproxy.git

cd mitmproxy/

python setup.py install

如果在python 环境下import limproxy没有问题，则说明我们的环境已经搭建成功。

利用libmproxy库编写代理工具

可以说，这个代理工具是pitbull安全测试的核心，他要解决将代理来的HTTP/HTTPS请求修改后放入数据库的操作。如果有gzip压缩数据，还要将数据解压后放入数据库。

所需库：

pip install pymongo

pip install pymongo

pip install requests

pip install pyzmq

