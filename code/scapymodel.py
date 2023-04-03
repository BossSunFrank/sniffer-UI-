from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from io import StringIO
from contextlib import redirect_stdout

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
# b_4 = tk.Button(window, text='持续监听', width=15, height=2,command=model2).place(x=580,y=84)
yscrollbar = tk.Scrollbar(window)
yscrollbar.pack(side="right", fill="y")
xscrollbar = tk.Scrollbar(window,orient="horizontal")
xscrollbar.pack(side="bottom", fill="x")
t = tk.Text(window, wrap="none",width=100, yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
t.place(x=50, y=200)
yscrollbar.config(command=t.yview)
xscrollbar.config(command=t.xview)

window.mainloop()
