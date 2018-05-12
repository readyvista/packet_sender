# coding=utf-8
import datetime
import tkinter

from tkinter import *
from tkinter import Button
from tkinter.constants import *
from tkinter.ttk import Treeview, Style

from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import *
from scapy.layers.l2 import *

tk = tkinter.Tk()
tk.title("协议编辑器")

tk.geometry("1000x700")
# 使窗体最大化
tk.state("zoomed")
# 左右分隔窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5)
# 协议编辑区窗体
protocol_editor_panedwindow = PanedWindow(orient=VERTICAL, sashrelief=RAISED, sashwidth=5)
# 协议导航树
protocols_tree = Treeview()
# 当前网卡的默认网关
default_gateway = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-3]
# 用来终止数据包发送线程的线程事件
stop_sending = threading.Event()


# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')





def create_IP_sender():
    # IP数据报编辑区
    IP_fields = '协议版本:','头部长度:','服务类型','总长度','标志','分片偏移','生存时间','协议','校验和','源IP地址','目的IP地址'
    entries = create_protocol_editor(protocol_editor_panedwindow,IP_fields)

    send_packet_button,reset_button,default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    tk.bind('<Return>',(lambda event:send_IP_packet(entries,send_packet_button)))
    send_packet_button.bind('<Button-1>',(lambda event:send_IP_packet(entries , send_packet_button)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_IP_packet(entries)))
    reset_button.bind('<Button-1>', (lambda event:clear_protocol_editor(entries)))

def create_TCP_sender():
    tcp_fields = '源端口号:' , '目的端口号','封包序号','确认序号','数据偏移','状态控制码','滑动窗口','TCP校验和','紧急指针','选项'
    entries = create_protocol_editor(protocol_editor_panedwindow,tcp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    tk.bind('<Return>', (lambda event: send_TCP_packet(entries, send_packet_button)))
    send_packet_button.bind('<Button-1>',(lambda event : send_TCP_packet(entries , send_packet_button)))
    default_packet_button.bind('<Button-1>',(lambda event:create_default_tcp_packet(entries)))
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))

def create_ICMP_sender():
    icmp_fields = '报文类型','代码','id','序号'
    entries = create_protocol_editor(protocol_editor_panedwindow,icmp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    default_packet_button.bind('<Button-1>', (lambda event: create_default_ICMP_packet(entries)))
    tk.bind('<Return>', (lambda event:send_ICMP_packet(entries,send_packet_button)))
    send_packet_button.bind('<Button-1>,',(lambda event:send_ICMP_packet(entries, send_packet_button)))
    reset_button.bind('<Button-1>',(lambda event:clear_protocol_editor(entries)))


def create_DNS_sender():
    dns_fields = '会话ID','查询/响应标志','查询/响应类型','授权回答','是否可截断','期望递归','可用递归'
    entries = create_protocol_editor(protocol_editor_panedwindow,dns_fields)
    send_packet_button,reset_button,default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    tk.bind('<Return>',(lambda event:send_DNS_packet(entries, send_packet_button)))
    send_packet_button.bind('<Button-1>',(lambda event: send_DNS_packet(entries,send_packet_button)))
    reset_button.bind('<Button-1>',(lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>',(lambda event: create_default_DNS_packet(entries)))


def create_arp_sender():
    """
    创建ARP包编辑器
    :return: None
    """
    # ARP包编辑区
    mac_fields = '硬件类型：', '协议类型：', '硬件地址长度：', '协议地址长度：', '操作码：', '源硬件地址：', \
                 '源逻辑地址：', '目标硬件地址：', '目标逻辑地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送ARP包
    tk.bind('<Return>', (lambda event: send_arp_packet(entries, send_packet_button)))
    # 为"发送"按钮的单击事件编写事件响应代码，发送ARP包
    send_packet_button.bind('<Button-1>', (
        lambda event: send_arp_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入ARP包字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_arp_packet(entries)))


def create_default_arp_packet(entries):   #entries就是字段的值
    """
    在协议字段编辑框中填入默认ARP包的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_arp_packet = ARP()
    entries[0].insert(0, default_arp_packet.hwtype)
    entries[1].insert(0, hex(default_arp_packet.ptype))
    entries[2].insert(0, default_arp_packet.hwlen)
    entries[3].insert(0, default_arp_packet.plen)
    entries[4].insert(0, default_arp_packet.op)
    entries[5].insert(0, default_arp_packet.hwsrc)
    entries[6].insert(0, default_arp_packet.psrc)
    entries[7].insert(0, default_arp_packet.hwdst)
    # 目标IP地址设成本地默认网关
    entries[8].insert(0, default_gateway)


def create_default_DNS_packet(entries):
    """
    在协议字段编辑框中填入默认DNS包的字段值
    :param entries:协议字段编辑列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_DNS_packet = DNS()
    entries[0].insert(0,default_DNS_packet.id)
    # id表示会话标识，通过它区分DNS应答报文是哪个请求的响应
    entries[1].insert(0,default_DNS_packet.qr)
    # QR，查询/响应标志，0是查询，1是相应
    entries[2].insert(0,default_DNS_packet.opcode)
    # opcode查询类型，0表示标准查询，1表示反响查询，2表示服务器状态请求
    entries[3].insert(0,default_DNS_packet.aa)
    # 表示授权回答
    entries[4].insert(0,default_DNS_packet.tc)
    # tc表示DNS报文是否可截断
    entries[5].insert(0,default_DNS_packet.rd)
    # rd表示DNS报文是否期望递归
    entries[6].insert(0,default_DNS_packet.ra)
    # ra表示DNS报文当前可用递归

def create_default_ICMP_packet(entries):
    """
    在协议字段编辑框中填入默认ICMP包的字段值
    :param entries: 协议字段编辑列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_ICMP_packet=ICMP()
    entries[0].insert(0,default_ICMP_packet.type)
    entries[1].insert(0,default_ICMP_packet.code)
    entries[2].insert(0,hex(default_ICMP_packet.id))
    entries[3].insert(0, hex(default_ICMP_packet.seq))

def send_ICMP_packet(entries,send_packet_button):
    """
    发送ICMP包
    :param entries: 协议字段编辑列表
    :param send_packet_button: 发送按钮
    :return: None
    """
    if send_packet_button['text'] == '发送':
        icmp_type=int(entries[0].get())
        icmp_code=int(entries[1].get())
        icmp_id = hex(entries[2].get())
        icmp_seq = hex(entries[3].get())
        packet_to_send = DNS(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def send_DNS_packet(entries, send_packet_button):
    """
    发送DNS包
    :param entries:协议字段编辑列表
    :param send_packet_button: send_packet_button：发送按钮
    :return: None
    """
    if send_packet_button['text'] == '发送':
        dns_id = int(entries[0].get())
        dns_qr = int(entries[1].get())
        dns_opcode = int(entries[2].get())
        dns_aa = int(entries[3].get())
        dns_tc = int(entries[4].get())
        dns_rd = int(entries[5].get())
        dns_ra = int(entries[6].get())
        packet_to_send = DNS(id=dns_id, qr=dns_qr, opcode=dns_opcode, aa=dns_aa, tc=dns_tc, rd=dns_rd, ra=dns_ra)
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def send_arp_packet(entries, send_packet_button):
    """
    发送ARP包
    :param send_packet_button: ARP包发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        arp_hwtype = int(entries[0].get())
        arp_ptype = int(entries[1].get(), 16)
        arp_hwlen = int(entries[2].get())
        arp_plen = int(entries[3].get())
        arp_op = int(entries[4].get())
        arp_hwsrc = entries[5].get()
        arp_psrc = entries[6].get()
        arp_hwdst = entries[7].get()
        arp_pdst = entries[8].get()
        packet_to_send = ARP(hwtype=arp_hwtype, ptype=arp_ptype, hwlen=arp_hwlen, plen=arp_plen,
                             op=arp_op, hwsrc=arp_hwsrc, psrc=arp_psrc, hwdst=arp_hwdst, pdst=arp_pdst)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def send_IP_packet(entries, send_packet_button):
    if send_packet_button['text'] == '发送':
        IP_version = int(entries[0].get())
        IP_src = entries[9].get()
        IP_dst = entries[10].get()
        packet_to_send = IP(src=IP_src , dst=IP_dst, )
        packet_to_send = IP(raw(packet_to_send))
        IP_chksum = packet_to_send.chksum
        entries[8].insert(0, IP_chksum)
        t=threading.Thread(target=send_packet , args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def send_TCP_packet(entries,send_packet_button):
    if send_packet_button['text'] == '发送':
        tcp_sport=int(entries[0].get())
        tcp_dport=int(entries[1].get())
        tcp_seq=int(entries[2].get())
        tcp_ack=int(entries[3].get())
        tcp_flags=entries[5].get()
        tcp_window=int(entries[6].get())
        tcp_urgptr=int(entries[8].get())

        packet_to_send = IP()/TCP(sport=tcp_sport, dport=tcp_dport, seq=tcp_seq, ack=tcp_ack,
                             flags=tcp_flags, window=tcp_window, urgptr=tcp_urgptr)
        packet = IP(raw(packet_to_send))
        entries[7].insert(0,packet.chksum)
        t=threading.Thread(target=send_packet , args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        toggle_protocols_tree_state()
        send_packet_button['text']='停止'
    else:
        stop_sending.set()
        toggle_protocols_tree_state()
        send_packet_button['text']='发送'


def create_default_IP_packet(entries):
    """

    """
    clear_protocol_editor(entries)
    default_IP_packet = IP()
    entries[0].insert(0 , default_IP_packet.version)
    entries[1].insert(0 , '')
    entries[2].insert(0 , hex(default_IP_packet.tos))

    entries[3].insert(0,'')
    entries[4].insert(0,default_IP_packet.id)
    entries[5].insert(0,default_IP_packet.frag)
    entries[6].insert(0,default_IP_packet.ttl)
    entries[7].insert(0,default_IP_packet.proto)
    entries[8].insert(0,'')
    entries[9].insert(0, default_IP_packet.src)
    entries[10].insert(0, default_IP_packet.dst)


def create_default_tcp_packet(entries):
    """
    在协议字段编辑框中填入默认tcp包的字段值
    :param entries: 协议字段编辑框列表
    :return: none
    """
    clear_protocol_editor(entries)
    default_tcp_packet=TCP()
    entries[0].insert(0,default_tcp_packet.sport)
    entries[1].insert(0,default_tcp_packet.dport)
    entries[2].insert(0,default_tcp_packet.seq)
    entries[3].insert(0,default_tcp_packet.ack)
    entries[4].insert(0,"")  # 此处为数据偏移字段，默认为none
    entries[5].insert(0,default_tcp_packet.flags)
    entries[6].insert(0,default_tcp_packet.window)
    entries[7].insert(0,"")  # 此处为校验和字段，默认为none
    entries[8].insert(0,default_tcp_packet.urgptr)
    entries[9].insert(0,default_tcp_packet.options)


def create_protocols_tree():
    """
    创建协议导航树
    :return: 协议导航树
    """
    protocols_tree.heading('#0', text='选择网络协议', anchor='w')
    # 参数:parent, index, iid=None, **kw (父节点，插入的位置，id，显示出的文本)
    # 应用层
    applicatoin_layer_tree_entry = protocols_tree.insert("", 0, "应用层", text="应用层")  # ""表示父节点是根
    http_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "HTTP包", text="HTTP包")
    dns_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "DNS包", text="DNS包")
    # 传输层
    transfer_layer_tree_entry = protocols_tree.insert("", 1, "传输层", text="传输层")
    tcp_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 0, "TCP包", text="TCP包")
    upd_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 1, "UDP包", text="UDP包")
    # 网络层
    ip_layer_tree_entry = protocols_tree.insert("", 2, "网络层", text="网络层")
    ip_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 0, "IP包", text="IP包")
    icmp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 1, "ICMP包", text="ICMP包")
    arp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 2, "ARP包", text="ARP包")
    # 网络接入层
    ether_layer_tree_entry = protocols_tree.insert("", 3, "网络接入层", text="网络接入层")
    mac_frame_tree_entry = protocols_tree.insert(ether_layer_tree_entry, 1, "MAC帧", text="MAC帧")
    protocols_tree.bind('<<TreeviewSelect>>', on_click_protocols_tree)  #绑定事件
    style = Style(tk)
    # get disabled entry colors
    disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
    style.map("Treeview",
              fieldbackground=[("disabled", disabled_bg)],
              foreground=[("disabled", "gray")],
              background=[("disabled", disabled_bg)])
    protocols_tree.pack()
    return protocols_tree


def toggle_protocols_tree_state():
    """
    使protocols_tree失效
    :rtype: None
    """
    if "disabled" in protocols_tree.state():
        protocols_tree.state(("!disabled",))
        # re-enable item opening on click
        protocols_tree.unbind('<Button-1>')
    else:
        protocols_tree.state(("disabled",))
        # disable item opening on click
        protocols_tree.bind('<Button-1>', lambda event: 'break')


def on_click_protocols_tree(event):
    """
    协议导航树单击事件响应函数
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空protocol_editor_panedwindow上现有的控件
    for widget in protocol_editor_panedwindow.winfo_children():
        widget.destroy()
    # 设置状态栏
    status_bar.set("%s", selected_item[0])

    if selected_item[0] == "MAC帧":
        create_mac_sender()
    elif selected_item[0] == "ARP包":
        create_arp_sender()
        # create_arp_sender()
    elif selected_item[0] == "IP包":
        create_IP_sender()
    elif selected_item[0] == "TCP包":
        create_TCP_sender()
    elif selected_item[0] == "UDP包":
        pass
        # create_udp_sender()
    elif selected_item[0] == "HTTP包":
        pass
        # create_http_sender()
    elif selected_item[0] == "ICMP包":
        create_ICMP_sender()
    elif selected_item[0] == "DNS包":
        create_DNS_sender()

def create_protocol_editor(root, field_names):
    """
    创建协议字段编辑区
    :param root: 协议编辑区
    :param field_names: 协议字段名列表
    :return: 协议字段编辑框列表
    """
    entries = []
    for field in field_names:
        row = Frame(root)
        label = Label(row, width=15, text=field, anchor='e')
        entry = Entry(row, font=('Courier', '12', 'bold'), state='normal')  # 设置编辑框为等宽字体
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
        entries.append(entry)
    return entries


def clear_protocol_editor(entries):
    """
    清空协议编辑器的当前值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    for entry in entries:
        # 如果有只读Entry，也要清空它的当前值
        state = entry['state']
        entry['state'] = 'normal'
        entry.delete(0, END)
        entry['state'] = state


def create_bottom_buttons(root):
    """
    创建发送按钮和重置按钮
    :param root: 编辑编辑区
    :return: 发送按钮和清空按钮
    """
    bottom_buttons = Frame(root)
    send_packet_button = Button(bottom_buttons, width=20, text="发送")
    default_packet_button = Button(bottom_buttons, width=20, text="默认值")
    reset_button = Button(bottom_buttons, width=20, text="重置")
    bottom_buttons.pack(side=BOTTOM, fill=X, padx=5, pady=5)
    send_packet_button.grid(row=0, column=0, padx=5, pady=5)
    default_packet_button.grid(row=0, column=1, padx=2, pady=5)
    reset_button.grid(row=0, column=2, padx=5, pady=5)
    bottom_buttons.columnconfigure(0, weight=1)
    bottom_buttons.columnconfigure(1, weight=1)
    bottom_buttons.columnconfigure(2, weight=1)
    return send_packet_button, reset_button, default_packet_button


    


def create_mac_sender():
    """
    创建MAC帧编辑器
    :return: None
    """
    # MAC帧编辑区
    mac_fields = '源MAC地址：', '目标MAC地址：', '协议类型：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)  #能够实现组件画图
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送MAC帧
    tk.bind('<Return>', (lambda event: send_mac_frame(entries, send_packet_button)))  # <Return>代表回车键，lambda表达式格式：lambda 参数:对应函数
    # 为"发送"按钮的单击事件编写事件响应代码，发送MAC帧
    send_packet_button.bind('<Button-1>', (
        lambda event: send_mac_frame(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入MAC帧字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_mac_frame(entries)))


def create_default_mac_frame(entries):
    """
    在协议字段编辑框中填入默认MAC帧的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_mac_frame = Ether()
    entries[0].insert(0, default_mac_frame.src)
    entries[1].insert(0, default_mac_frame.dst)
    entries[2].insert(0, hex(default_mac_frame.type))


def send_mac_frame(entries, send_packet_button):
    """
    发送MAC帧
    :param send_packet_button: MAC帧发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        mac_src = entries[0].get()
        mac_dst = entries[1].get()
        mac_type = int(entries[2].get(), 16)
        packet_to_send = Ether(src=mac_src, dst=mac_dst, type=mac_type)
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))  #target属性就是你要执行的函数，args是元祖（参数），即使只有一个也要加入圆括号内，并且加逗号，逗号不能省
        t.setDaemon(True)  #设为守护线程（如果把前台关了这个守护线程也会自动关，否则会一直运行）
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def send_packet(packet_to_send):
    """
    用于发送数据包的线程函数，持续发送数据包
    :type packet_to_send: 待发送的数据包
    """
    # print(packet.show(dump=True))
    # 对发送的数据包次数进行计数，用于计算发送速度
    n = 0
    stop_sending.clear()
    # 待发送数据包的长度（用于计算发送速度）
    packet_size = len(packet_to_send)
    # 推导数据包的协议类型
    proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'Unknown']
    packet_proto = ''
    for pn in proto_names:
        if pn in packet_to_send:
            packet_proto = pn
            break
    # 开始发送时间点
    begin_time = datetime.now()
    while not stop_sending.is_set():
        if isinstance(packet_to_send, Ether):
            sendp(packet_to_send, verbose=0)  # verbose=0,不在控制回显'Sent 1 packets'.
        else:
            send(packet_to_send, verbose=0)
        n += 1
        end_time = datetime.now()
        total_bytes = packet_size * n
        bytes_per_second = total_bytes / ((end_time - begin_time).total_seconds()) / 1024
        status_bar.set('已经发送了%d个%s数据包, 已经发送了%d个字节，发送速率: %0.2fk字节/秒',
                       n, packet_proto, total_bytes, bytes_per_second)


def create_welcome_page(root):
    welcome_string = '\n协议编辑器\n'
    Label(root, justify=CENTER, padx=10, pady=150, text=welcome_string,
          font=('隶书', '30', 'bold')).pack()


if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建欢迎界面
    create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)
    # 启动消息处理
    tk.mainloop()



