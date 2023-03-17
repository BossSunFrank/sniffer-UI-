from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from io import StringIO
from contextlib import redirect_stdout
import socket
import os
import struct
from ctypes import *
import time
import datetime as dt

#捕获的数据包的结果会写在下面这个列表中
my_packages = []

def start():
    var1 = packageName.get()
    var2 = packageCnt.get()
    try:
        if type(eval(var2)) is not int:
            tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
            return
    except:
        tk.messagebox.showerror(title='错误', message='抓包数量必须为整数！')
        return
    try:
        packages = sniff(iface=var1, count=eval(var2))
    except:
        tk.messagebox.showerror(title='错误', message='网卡不存在')
        return
    for i in range(eval(var2)):
        t.insert("end", "序号：{}   {}\n".format(i+1,packages[i].summary()))
        my_packages.append(packages[i])


def showDetail():
    #获取想要具体查询的包序号
    var3 = packageNum.get()
    #创建第二个窗口
    detialWindow = tk.Tk()
    detialWindow.title("第{}个包的详细信息".format(var3))
    detialWindow.geometry('800x350')
    scrollbar = tk.Scrollbar(detialWindow)
    scrollbar.pack(side="right", fill="y")
    t1 = tk.Text(detialWindow, wrap="none", width=100, yscrollcommand=scrollbar.set)
    t1.pack(side='top')
    scrollbar.config(command=t1.yview)
    try:
        # 将my_packages[eval(var3)-1].show()重定向到变量packageDetail中
        output_str = StringIO()
        with redirect_stdout(output_str):
            my_packages[eval(var3)-1].show()
        packageDetail = output_str.getvalue()
        t1.insert("end",packageDetail)
    except:
        tk.messagebox.showerror(title='错误', message='包序号出错！')
    detialWindow.mainloop()

def showHelp():
    helpWindow = tk.Tk()
    helpWindow.title("帮助说明")
    helpWindow.geometry('800x350')
    helpText=["嗅探工具（抓包个数模式）使用说明：","1. 第一个输入框为网卡名称，默认为所有网卡",
              "2. 第二个输入框为拟抓包的数量，需要输入一个正整数，再点击'开始抓包'即可开始捕获数据包",
              "3. 第三个输入框为查看序号，在点击'开始抓包'后，输入想要具体查看的包序号，再点击'详细信息'",
              "   即可查看特定包序号的详细信息",
              "\n","嗅探工具（持续监听模式）使用说明：",
              "1. 点击按钮'持续监听'即可跳转至持续监听功能使用界面",
              "2. 使用'持续监听'功能必须使用管理员运行，否则无法抓包",
              "3. 输入网卡的ip后，点击'开始'，即可开始持续监听",
              "4. 点击'停止'，即可停止监听，抓包结束"]
    helpBox = tk.Text(helpWindow, wrap="none", width=100)
    helpBox.pack(side="top")
    for line in helpText:
        helpBox.insert("end",line)
        helpBox.insert("end", "\n")
    helpWindow.mainloop()


# IP头定义
class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_ulong),
        ('dst', c_ulong),
        ("src_port", c_ushort),
        ("dst_port", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)  # 实例化类

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}  # 创建一个字典，协议字段与协议名称对应
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        # inet_ntoa()函数将字节流转化为点分十进制的字符串，专用于IPv4地址转换
        # 将c_ulong类型的src(源地址)转为小端的long类型数据，返回源地址的字节流格式
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        # 协议判断
        try:
            self.protocol = self.protocol_map[self.protocol_num]  # 将协议号与协议名对应
        except:
            self.protocol = str(self.protocol_num)  # 若字典中没有，则直接输出协议号




def model2():
    #此函数为持续监听模式，点击持续监听即可跳转至此界面

    # Windows下嗅探所有数据包，Linux下嗅探ICMP数据包
    def start():
        var = e.get()
        if os.name == "nt":  # 判断系统是否为window
            socket_protocol = socket.IPPROTO_IP  # 设置协议为ip协议
        else:
            socket_protocol = socket.IPPROTO_ICMP
        global sniffer

        # 创建一个原始套接字
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        try:
            sniffer.bind((var, 0))  # 套接字绑定地址，0默认所有端口
        except:
            tk.messagebox.showerror(title='错误', message='socket连接错误')  # 若绑定失败则弹窗解释

        # 设置ip头部
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Windows下要打开混杂模式
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            # 设置开启混杂模式，socket.SIO_RCVALL默认接收所有数据，socket.RCVALL_ON开启
        show_th = threading.Thread(target=show)  # 创建一个线程，执行函数为show()
        show_th.setDaemon(True)
        show_th.start()

    def show():
        window2.title('正在抓包...')  # 更改界面标题
        while True:
            # 读取数据包
            raw_buffer = sniffer.recvfrom(65535)[0]  # 获取数据包，接收最大字节数为65565
            # 读取前20字节
            ip_header = IP(raw_buffer[0:24])
            # 输出协议和双方通信的IP地址
            now_time = dt.datetime.now().strftime('%T')  # 获取系统当前时间
            result = '协议: ' + str(ip_header.protocol) + ' ' + str(ip_header.src_address) + ' : ' + str(
                ip_header.src_port) + ' -> ' + str(ip_header.dst_address) + ' : ' + str(
                ip_header.dst_port) + '  size:' + str(ip_header.len) + ' 时间:' + str(now_time) + '\n'  # 设置输出的字符串
            t.insert('end', result)  # 将每条输出插入到界面
            time.sleep(0.1)

    def stop():
        window2.title('抓包已停止')
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # 关闭混杂模式，第一个参数是接收所有数据，第二个对应关闭
        sniffer.close()  # 关闭套接字
    #此处开始，相当于是持续监听模式的主函数
    window2 = tk.Tk()
    window2.title('老孙的嗅探工具（持续监听模式）')
    window2.geometry('800x600')
    # 本地监听
    l = tk.Label(window2, text='网卡ip：')
    l.place(x=150, y=65)
    e = tk.Entry(window2, show=None)
    e.place(x=250, y=65)
    var = tk.StringVar()  # 定义一个字符串变量
    b_1 = tk.Button(window2, text='开始抓包', width=15, height=2, command=start).place(x=450, y=20)
    b_2 = tk.Button(window2, text='停止抓包', width=15, height=2, command=stop).place(x=450, y=80)
    t = tk.Text(window2, width=100)
    t.place(x=50, y=200)
    window2.mainloop()



# 创建tkinter主窗口
window = tk.Tk()
window.title('老孙的嗅探工具（抓包个数模式）')
window.geometry('800x600')
window.iconbitmap('doghead.ico')
tip1 = tk.Label(window, text='网卡名称：')
tip1.place(x=100, y=30)
packageName = tk.Entry(window, show=None)
packageName.place(x=200, y=30)
var1 = tk.StringVar()

tip2 = tk.Label(window, text='抓包数量：')
tip2.place(x=100,y=70)
packageCnt = tk.Entry(window, show=None)

packageCnt.place(x=200, y=70)
var2 = tk.StringVar()
tip3 = tk.Label(window, text='查看序号：')
tip3.place(x=100,y=110)
packageNum = tk.Entry(window, show=None)

packageNum.place(x=200,y=110)
var3 = tk.StringVar()

b_1 = tk.Button(window, text='开始抓包', width=15, height=2,command=start).place(x=450, y=25)
b_2 = tk.Button(window, text='详细信息', width=15, height=2,command=showDetail).place(x=450,y=85)
b_3 = tk.Button(window, text='帮助说明', width=15, height=2,command=showHelp).place(x=580,y=24)
b_4 = tk.Button(window, text='持续监听', width=15, height=2,command=model2).place(x=580,y=84)
yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window,orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")
t = tk.Text(window, wrap="none",width=100, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
t.place(x=50, y=200)
yscrollbar.config(command=t.yview)
xscrollbar.config(command=t.xview)

window.mainloop()
