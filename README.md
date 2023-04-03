# sniffer-UI-
用python的scapy库和socket编程模块做了一个带UI的嗅探器<br>
中国科学院大学《软件与系统安全》、《网络攻防基础》实验1<br>
我主要分为了两个模块：抓包个数模式、持续监听模式。累计抓包模式中，使用python第三方库scapy进行了开发，可以实现对所有网卡的抓包。持续监听模式，利用socket网络编程相关的库函数，对特定网卡进行了抓包，由于socket模块获取网卡信息需要使用管理员模式，我们可以用管理员命令行的形式运行源码的.py文件。本次实验采用tkinter模块进行了GUI的设计。  
## 启动方式
若使用sockt网络编程模块的持续监听模式，必须以管理员身份运行。管理员身份运行cmd，然后进入所在目录，运行catch.py即可
![execute](https://user-images.githubusercontent.com/115724910/225799596-08701049-0c33-46c1-b8fe-8b574cffbda3.png)
然后就可以看到启动界面了：
![first_display](https://user-images.githubusercontent.com/115724910/225799702-befa656a-2d59-4483-be2a-6aac1fcc3e6f.png)<br>
具体使用方式详见read_me.docx<br>
## scapymodel的启动
这个模块直接运行即可，无需管理员。在对应命令行输入scapymodel.py或在python解释器中run均可，效果如下：<br>
