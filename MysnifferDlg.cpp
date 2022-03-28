
// MysnifferDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Mysniffer.h"
#include "MysnifferDlg.h"
#include "afxdialogex.h"

#include <vector>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define LINE_LEN 16
#define MAXSIZE 5000
int number = 0;
CMysnifferDlg *dlg;//用 于访问CMySnifferDIg中的成员的指针
CString pack_str[MAXSIZE];
static bool STATE;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMysnifferDlg 对话框



CMysnifferDlg::CMysnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_Mysniffer_DIALOG, pParent)
	, m_info(_T(""))
	, m_select(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMysnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comboBoxRule);
	DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	//  DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	DDX_Text(pDX, IDC_EDIT_SELECT_DEVICE, m_select);
	DDX_Control(pDX, IDC_LIST_DEVICE, m_device);
	DDX_Control(pDX, IDC_LIST_PACK, m_pack);
}

BEGIN_MESSAGE_MAP(CMysnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_DEVICE, &CMysnifferDlg::OnLvnItemchangedListDevice)
	ON_BN_CLICKED(IDC_BUTTON_GET_DEVICE, &CMysnifferDlg::OnClickedButtonGetDevice)
	ON_NOTIFY(NM_CLICK, IDC_LIST_PACK, &CMysnifferDlg::OnClickListPack)
	ON_BN_CLICKED(IDC_BUTTON_START, &CMysnifferDlg::OnClickedButtonStart)
	ON_EN_CHANGE(IDC_EDIT_DATA_INFOACTION, &CMysnifferDlg::OnEnChangeEditDataInfoaction)
	ON_BN_CLICKED(IDC_BUTTON_STOP, &CMysnifferDlg::OnClickedButtonStop)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CMysnifferDlg::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()


// CMysnifferDlg 消息处理程序

BOOL CMysnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	//SetIcon(m_hIcon, TRUE);			// 设置大图标
	//SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	STATE = FALSE;
	AfxGetMainWnd()->SetWindowText("Mysniffer");
	dlg = this;
	number = 0;
	devnum = 0;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	DWORD dwStyle1 = m_device.GetExtendedStyle();
	dwStyle1 |= LVS_EX_FULLROWSELECT;
	dwStyle1 |= LVS_EX_GRIDLINES;
	m_device.SetExtendedStyle(dwStyle1);
	m_device.InsertColumn(0, "NO", LVCFMT_LEFT, 100);
	m_device.InsertColumn(1, "网络设备", LVCFMT_LEFT, 400);
	m_device.InsertColumn(2, "网络适配器 名称",LVCFMT_LEFT,500);
	//设置列表m_ pack格式
	DWORD dwStyle = m_pack.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;
	m_pack.SetExtendedStyle(dwStyle);
	//添加m_ pack的列标题
	
	m_pack.InsertColumn(0,"序号", LVCFMT_LEFT, 60);
	m_pack.InsertColumn(1,"IP协议版本", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(2,"协议", LVCFMT_LEFT, 80);
	m_pack.InsertColumn(3,"源IP地址", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(4,"目的IP地址", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(5,"源MAC地址", LVCFMT_LEFT, 140);
	m_pack.InsertColumn(6,"目的MAC地址", LVCFMT_LEFT, 140);
	m_pack.InsertColumn(7,"数据包发送时间", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(8,"数据包大小", LVCFMT_LEFT, 100);

	m_comboBoxRule.AddString(_T("选择过滤规则"));
	/*初始化过滤规则列表*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));
	//m_comboBoxRule.AddString(_T("tls"));
	m_comboBoxRule.SetCurSel(0);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMysnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMysnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		//dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMysnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMysnifferDlg::OnNMCustomdrawProgress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}

void CMysnifferDlg::OnLvnItemchangedListDevice(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CMysnifferDlg::OnLvnItemchangedListDevice1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CMysnifferDlg::OnEnChangeEditDataaction1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CMysnifferDlg::OnClickListDevice1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CMysnifferDlg::OnClickedButtonGetDevice()
{
	// TODO: 在此添加控件通知处理程序代码
	this->getAllDevs();
	

}


void CMysnifferDlg::OnClickListPack(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	POSITION Pos = m_pack.GetFirstSelectedItemPosition();
	int num = (int)Pos;
	
	GetDlgItem(IDC_EDIT_DATA_INFOACTION)->SetWindowText(pack_str[num]);
	*pResult = 0;
}


void CMysnifferDlg::OnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(TRUE);
	if (STATE == FALSE) {
		this->m_pack.DeleteAllItems();
	}
	STATE = TRUE;
	this->startCap();
	

}

void CMysnifferDlg::getAllDevs()
{
	pcap_if_t *d;
	int i = 0;
	/* 获取本地机器设备列表 */
	//if (this->alldevs != NULL) return this->alldevs;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
	{
		exit(1);
	}

	/* 打印列表 */
	for (d = this->alldevs; d != NULL; d = d->next)
	{
		str.Format("%d", i + 1);
		m_device.InsertItem(i, str);
		str = d->name;
		m_device.SetItemText(i, 1, str);
		if (d->description) {
			str = d->description;
			m_device.SetItemText(i, 2, str);
		}
		else
		{
			str = "无法获取设备详情";
			m_device.SetItemText(i, 2, str);
		}
		i++;
	}
	devnum = i;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
	return;
}

static UINT WINAPI ThreadFunc()
{
	int res = 10;
	int cot = 0;
	if ((dlg->dumpfp = pcap_dump_open(dlg->adhandle, "data.pcap")) == NULL) 
	{
		exit(-1);
	}
	//u_char *oldtime;
	while ((res = pcap_next_ex(dlg->adhandle, &dlg->header, &dlg->pkt_data)) >= 0)
	{
		if(STATE == FALSE){
			return 0;
		}
		pcap_t *adhandle = dlg->adhandle;
		pcap_pkthdr *header = dlg->header;
		const u_char *pkt_data = dlg->pkt_data;
		if (number == MAXSIZE) break;
		if (res == 0) continue;
		int counter, counter2;
		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		if (number != 0)
		{
			// =(u_char) local_tv_sec;
			//dlg->analyse(oldtime);
		}
		
		pcap_dump((u_char *)dlg->dumpfp,(const pcap_pkthdr *)dlg->header,(const u_char *)dlg->pkt_data);
		
		number++;
		dlg->str.Format("%d", number);//打印包的序号
		dlg->m_pack.InsertItem(number - 1, dlg->str);//打印包的时间
		local_tv_sec = header->ts.tv_sec;//将时间戳转换成可识别的格式
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		dlg->str = timestr;
		dlg->m_pack.SetItemText(number - 1, 7, dlg->str);
		dlg->str.Format("%d", header->len);//打印包的长度
		dlg->m_pack.SetItemText(number - 1, 8, dlg->str);
		dlg->an_ethernet();
		if(number == 1)
			dlg->file = fopen("data.pcap", "rb+");
		dlg->getoffset(dlg->file);
	}
	pcap_dump_close(dlg->dumpfp);
	return 0;
}

void CMysnifferDlg::startCap()
{
	int filter_index;
	pcap_if_t *d;
	int inum = 0;
	int i = this->devnum;
	int res;
	u_int netmask;
	CString message;
	CString select;
	GetDlgItemText(IDC_EDIT_SELECT_DEVICE, str);
	
	struct bpf_program fcode;
	filter_index = this->m_comboBoxRule.GetCurSel();
	if (CB_ERR == filter_index)
	{
		MessageBox(_T("过滤器选择错误"));
		return ;
	}

	POSITION Pos = m_device.GetFirstSelectedItemPosition();
	if(Pos == NULL && str == "") {
		message = "您还未选择网卡！";
		MessageBox(message, "INFO");
		return;
	}
	int pos = (int)Pos;
	CString d1, d2;

	//GetDlgItemText(IDC_EDIT_SELECT_DEVICE,str);

	inum = atoi((char *)(LPSTR)(LPCTSTR)str);
	if(inum != pos && Pos != NULL && str != ""){
		message = "您选择的设备和输入的设备不相同，请重新输入";
		MessageBox(message, "INFO");
		this->m_device.DeleteAllItems();
		return;
	}
	if (str == "") {
		inum = pos;
		str.Format("%d", pos);
	}
	
	if (inum < 1 || inum > i)
	{
		message = "设备序号超出范围.";
		MessageBox(message, "ERROR");
		pcap_freealldevs(alldevs);
		return;
	}

	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 要捕捉的数据包的部分 
						  // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		message = "无法打开适配器.";
		MessageBox(message, "error");
		pcap_freealldevs(alldevs);
		return;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	//pcap_freealldevs(alldevs);

	//编译过滤器
	if (0 == filter_index)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldevs);
			return ;
		}
	}
	else {
		CString str;
		char *filter;
		int len, x;
		this->m_comboBoxRule.GetLBText(filter_index, str);
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (x = 0; x < len; x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldevs);
			return ;
		}
	}


	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldevs);
		return ;
	}

	this->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadFunc , NULL, 0, &ThreadID);

	return;
}


void CMysnifferDlg::an_ethernet()
{
	u_short ethernet_type;
	ether_header *ethernet;
	u_char *macaddr;
	ethernet = (ether_header *)this->pkt_data;
	static int ethernet_number = 1;
	ethernet_type = ntohs(ethernet->ether_type);
	macaddr = ethernet->smac;
	str.Format("%.2x", macaddr[0]);
	dlg->m_str2 = str;
	for (int cc = 1; cc < 6; cc++)
	{
		str.Format(":%.2x", macaddr[cc]);
		dlg->m_str2 += str;
	}
	dlg->m_pack.SetItemText(number - 1, 5, m_str2);
	/* 获得源以太网地址 */
	macaddr = ethernet->dmac;
	m_str2.Format("%.2x", macaddr[0]);
	dlg->str = m_str2;
	for(int cc = 1;cc < 6; cc ++)
	{
		m_str2.Format(":%.2x", macaddr[cc]);
		dlg->str += m_str2;
	}
	dlg->m_pack.SetItemText(number - 1, 6, str);

	/* 获得目的以太网地址 */
	int counter=0, counter2=0;
	dlg->str.Format("%08x ", counter + 16);
	for (counter = 1; (counter < (header->caplen + 1)); counter++)
	{
		dlg->m_str2.Format("%.2x ", pkt_data[counter - 1]);
		dlg->str += dlg->m_str2;
		if ((counter % LINE_LEN) == 0)
		{
			dlg->str += " ";
			for (counter2 = 0; counter2 < LINE_LEN; counter2++)
			{
				if ((pkt_data[counter + counter2 - LINE_LEN - 1] >= 32) && (pkt_data[counter + counter2 - LINE_LEN - 1] <= 126)) 
				{
					
					dlg->str += pkt_data[counter + counter2 - LINE_LEN - 1];
				}
				else dlg->str += ".";
			}
			dlg->str += "\r\n"; 
			dlg->m_str2.Format("%08x ", counter + 16);
			dlg->str += dlg->m_str2;
		}
	}
	dlg->str += "\r\n--------- 以太网 ---------\r\n";
	CString temp;
	temp.Format("%02x:%02x:%02x:%02x:%02X:%02X", *ethernet->smac, *(ethernet->smac + 1), *(ethernet->smac + 2), *(ethernet->smac + 3), *(ethernet->smac + 4), *(ethernet->smac + 5));
	dlg->str += "源端口：" + temp+"\r\n";
	temp.Format("%02x:%02x:%02x:%02x:%02X:%02X", *ethernet->dmac, *(ethernet->dmac + 1), *(ethernet->dmac + 2), *(ethernet->dmac + 3), *(ethernet->dmac + 4), *(ethernet->dmac + 5));
	dlg->str += "目的端口：" + temp+"\r\n";
	dlg->str += "Type: ";
	switch (ethernet_type)
	{
	case 0x86dd:
		dlg->str+="IPV6\r\n";
		this->m_pack.SetItemText(number - 1, 1, "IPV6");
		dlg->str += "\r\n-----------IPV6-----------\r\n";
		break;
	case 0x0806:
		dlg->str += "ARP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "ARP");
		//dlg->str += "\r-----------ARP------------\r\n";
		dlg->str += this->_arp();
		break;
	case 0x0800:
		this->str += "IP\r\n";

		//->str += "\r\n-----------IPV4-----------\r\n";
		dlg->str += this->_ip();
		break;
	default:
		break;
	}

	pack_str[number] = dlg->str;


}

CString CMysnifferDlg::_arp()
{
	ARP_header *arp;
	u_short version;
	u_short hardware_type;
	u_short operation_code;
	u_char *macaddr;
	u_short hardware_length;
	u_short protocol_length;
	CString s ,r, temp;
	arp = (ARP_header *)((u_char *)pkt_data + 14);
	hardware_type = ntohs(arp->HardwareType);
	version = ntohs(arp->ProtocolType);
	operation_code = ntohs(arp->OperationField);
	hardware_length = arp->HardwareAddLen;
	protocol_length = arp->ProtocolAddLen;
	if (version == 0x0800) this->m_pack.SetItemText(number - 1, 1, "IPV4");
	if (version == 0x86dd) this->m_pack.SetItemText(number - 1, 1, "IPV6");

	s = "";
	m_str2.Format("%d", arp->SourceIpAdd.byte1);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte2);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte3);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 3, s);

	s = "";
	m_str2.Format("%d", arp->DestIpAdd.byte1);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte2);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte3);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 4, s);
	r += "----------- ARP协议 -----------\r\n";
	temp.Format("%d", hardware_type);
	r += "硬件类型：" + temp + "\r\n";
	temp.Format("%d", version);
	r += "协议类型：0x%02x" + temp + "\r\n";
	temp.Format("%d", hardware_length);
	r += "硬件地址长度：" + temp + "\r\n";
	temp.Format("%d", protocol_length);
	r += "协议地址长度：" + temp + "\r\n";
	temp.Format("%d", operation_code);
	r += "操作码：" + temp + "\r\n";
	macaddr = arp->SourceMacAdd;
	r += "源以太网地址:";
	temp.Format("%02x:%02x:%02x:%02x:%02x:%02x", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	r += temp + "\r\n";
	macaddr = arp->DestMacAdd;
	r += "目的以太网地址:";
	temp.Format("%02x:%02x:%02x:%02x:%02x:%02x", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	r += temp + "\r\n";
	temp.Format("%d.%d.%d.%d", arp->SourceIpAdd.byte1, arp->SourceIpAdd.byte2, arp->SourceIpAdd.byte3, arp->SourceIpAdd.byte4);
	r += "源IP地址:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", arp->DestIpAdd.byte1, arp->DestIpAdd.byte2, arp->DestIpAdd.byte3, arp->DestIpAdd.byte4);
	r += "目的IP地址:" + temp + "\r\n";

	return r;
}

CString CMysnifferDlg::_ip()
{
	ip_header *ip;
	u_short version;
	u_short header_lenth;
	u_int offset;
	u_char tos;
	u_short id;
	u_char flag;
	u_int16_t checksum;
	CString s;
	ip = (ip_header*)(pkt_data + 14);
	version = ((ip->ver_ihl & 0xf0) >> 4);
	header_lenth = (ip->ver_ihl & 0xf) * 4;
	tos = ip->tos;
	id = ntohs(ip->identification);
	flag = (ip->identification >> 13);
	offset = ntohs((ip->flags & 0x1fff));
	checksum = ntohs(ip->checknum);

	if (version == 4) this->m_pack.SetItemText(number - 1, 1, "IPV4");
	if (version == 6) this->m_pack.SetItemText(number - 1, 1, "IPV6");

	s = "";
	m_str2.Format("%d", ip->saddr.byte1);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte2);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte3);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 3, s);

	s = "";
	m_str2.Format("%d", ip->daddr.byte1);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte2);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte3);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 4, s);
	CString r, temp;
	r += "----------- IP协议 -----------\r\n";
	temp.Format("%d", version);
	r += "版本号:" + temp + "\r\n";
	temp.Format("%d", header_lenth);
	r += "首部长度:" + temp + "\r\n";
	temp.Format("%d", tos);
	r += "服务质量:" + temp + "\r\n";
	temp.Format("%d", ntohs(ip->tlen));
	r += "总长度:" + temp + "\r\n";
	temp.Format("%d", ntohs(ip->identification));
	r += "标识:" + temp + "\r\n";
	temp.Format("%d", offset);
	r += "偏移:" + temp + "\r\n";
	temp.Format("%d", ip->ttl);
	r += "生存时间:" + temp + "\r\n";
	temp.Format("%d", checksum);
	r += "校验和:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
	r += "源IP地址:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
	r += "目的IP地址:" + temp + "\r\n";
	r += "协议：";
	switch (ip->protocol)
	{
	case 6:
		r += "TCP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "TCP");
		r += this->_tcp();
		
		break;
	case 17:
		r += "UDP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "UDP");
		r += this->_udp();
		break;
	case 1:
		r += "ICMP";
		this->m_pack.SetItemText(number - 1, 2, "ICMP");
		r += this->_icmp();
		break;
	default:
		break;
	}
	return r;

}

// 显示HTTP协议的详细信息
CString CMysnifferDlg::_http()
{
	CString r, temp;
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ver_ihl;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->tcp_offset * 4;


	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tlen) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	//http_packet * http_pktHdr = new http_packet ;// HTTP packet's  struct
	vector<CString> strVecRequestHttp; // 定义请求头容器
	vector<CString> strVecRespondHttp; // 定义响应头容器
	CString chrVecTmp = NULL; // 声明存入容器的临时字符
	CString strVecTmp = NULL; // 声明存入容器的临时字符串

	u_char * pchrHttpAllData = NULL; //定义HTTP协议包的起始位置，包括请求头或响应头都可
	u_char * pchrHttpRequestPos = NULL; //定义HTTP协议包的请求头的起始位置
	u_char * pchrHttpRespondPos = NULL; //定义HTTP协议包的响应头的起始位置
	pchrHttpAllData = http_pkt; //赋值得到HTTP协议包的开始位置

	CString strHttpALLData = NULL;//定义HTTP协议包的数据包,包括请求头或响应头都可
	CString strHttpRequestData = NULL;//定义HTTP协议包的请求头的数据
	CString strHttpRespondData = NULL;//定义HTTP协议包的响应头的数据

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;
	r += "----------- HTTP协议 -----------\r\n";
	if (IsHTTP(pkt_data)) // check is http
	{

		if (*pkt_data == 'H') // 如果第一个字符为H，即可能以HTTP开头的，则为响应头，否则应为请求头
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				//chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				//strHttpRespondData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}
			r += "响应头:\r\n";
			for (u_short irespond = 0; irespond < strVecRespondHttp.size(); irespond++) {
				temp.Format("%d", strVecRespondHttp[irespond]);
				r += temp + "\r\n";
			}

		}
		else
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				//chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				//strHttpRequestData += chrVecTmp;//记录完整的HTTP请求头的数据

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRequestHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}
			r += "请求头:\r\n";
			for (u_short irequest = 0; irequest < strVecRequestHttp.size(); irequest++) {
				temp.Format("%d", strVecRequestHttp[irequest]);
				r += temp + "\r\n";
			}

		}
	}
	return r;

}
// 判断该协议是否为HTTP协议
bool CMysnifferDlg::IsHTTP(const u_char *pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ver_ihl;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->tcp_offset * 4;

	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tlen) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	CString chrTmp = NULL;
	CString strTmp = NULL;
	CString strHttp = NULL;

	int httpPos = 0;

	if (ip_hdr->protocol == 6)
	{
		for (int i = 0; i < http_pktLen; i++) // 仅提取第一行是否含有HTTP字符串
		{
			chrTmp.Format(TEXT("%c"), http_pkt[i]);
			strTmp += chrTmp;
			if (i > 2 && http_pkt[i - 1] == 13 && http_pkt[i] == 10)
				break;
		}
		//AfxMessageBox(strTmp);
		httpPos = strTmp.Find(TEXT("HTTP"), 0);

		if (httpPos != -1 && httpPos != 65535) // 如果第一行含有字符串HTTP，则为HTTP协议
		{
			return true;
		}
			return false;

	}
	return false;
}

CString CMysnifferDlg::_tcp()
{
	tcp_header* tcp;/* TCP协议变量 */
	u_char flags;/* 标记 */
	int header_length;/* 长度 */
	u_short source_port;/* 源端口 */
	u_short destination_port;/* 目的端口 */
	u_short windows;/* 窗口大小 */
	u_short urgent_pointer;/* 紧急指针 */
	u_int sequence;/* 序列号 */
	u_int acknowledgement;/* 确认号 */
	u_int16_t checksum;/* 校验和 */
	CString r, temp;
	tcp = (tcp_header*)((u_char *)pkt_data + 14 + iplen);/* 获得TCP协议内容 */
	source_port = ntohs(tcp->tcp_source_port);/* 获得源端口 */
	destination_port = ntohs(tcp->tcp_destination_port);/* 获得目的端口 */
	header_length = tcp->tcp_offset * 4;/* 长度 */
	sequence = ntohl(tcp->tcp_sequence_lliiuuwweennttaaoo);/* 序列码 */
	acknowledgement = ntohl(tcp->tcp_acknowledgement);/* 确认序列码 */
	windows = ntohs(tcp->tcp_windows);/* 窗口大小 */
	urgent_pointer = ntohs(tcp->tcp_urgent_pointer);/* 紧急指针 */
	flags = tcp->tcp_flags;/* 标识 */
	checksum = ntohs(tcp->tcp_checksum);/* 校验和 */
	r += "----------- TCP协议 -----------\r\n";
	temp.Format("%d", source_port);
	r += "源端口号:" + temp + "\r\n";
	temp.Format("%d", destination_port);
	r += "目的端口号:" + temp + "\r\n";
	temp.Format("%u",sequence);
	r += "序列码:" + temp + "\r\n";
	temp.Format("%u", acknowledgement);
	r += "确认号:" + temp + "\r\n";
	temp.Format("%d", header_length);
	r += "首部长度:" + temp + "\r\n";
	temp.Format("%d", tcp->tcp_reserved);
	r += "保留:" + temp + "\r\n";
	r += "标记:\r\n";
	r += "PSH = ";
	if (flags & 0x08)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "ACK = ";
	if (flags & 0x10)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "SYN = ";
	if (flags & 0x02)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "URG = ";
	if (flags & 0x20)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "FIN = ";
	if (flags & 0x01)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "RST = ";
	if (flags & 0x04)
		r += "1";
	else r += "0";
	r += "\r\n";
	temp.Format("%d", windows);
	r += "窗口大小:" + temp + "\r\n";
	temp.Format("%d", checksum);
	r += "校验和:" + temp + "\r\n";
	temp.Format("%d", urgent_pointer);
	r += "紧急指针:" + temp + "\r\n";
	if (IsHTTP(pkt_data)) {
		r += "协议:HTTP\r\n";
		r += this->_http();
		this->m_pack.SetItemText(number - 1, 2, "HTTP");
	}
	return r;
}

CString CMysnifferDlg::_udp()
{
	udp_header *udp;
	CString r, temp;
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
	//ip = (ip_header *)((u_char *)pkt_data + 14);
	udp = (udp_header *)((u_char *)pkt_data + 14 + iplen);

	sport = ntohs(udp->sport);
	dport = ntohs(udp->dport);
	len = udp->len;
	crc = ntohs(udp->crc);
	r += "----------- UDP协议 -----------\r\n";
	temp.Format("%d", sport);
	r += "源端口号:" + temp + "\r\n";
	temp.Format("%d", dport);
	r += "目的端口号:" + temp + "\r\n";
	temp.Format("%u", len);
	r += "长度:" + temp + "\r\n";
	temp.Format("%u", crc);
	r += "校验和:" + temp + "\r\n";

	return r;
}

CString CMysnifferDlg::_icmp()
{
	struct icmp_header* icmp;
	/* ICMP协议变量 */
	icmp = (struct icmp_header*)((u_char *)pkt_data + 14 + iplen);
	/* 获得ICMP协议内容 */
	CString r, temp;
	r += "----------- ICMP协议 -----------\r\n";
	temp.Format("%d", icmp->icmp_type);
	r += "ICMP类型:" + temp + "\r\n";
	/* 获得ICMP类型 */
	switch (icmp->icmp_type)
	{
	case 8:
		r += "  ICMP回显请求协议\r\n";
		temp.Format("%u", icmp->icmp_code);
		r += "ICMP代码:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_id);
		r += "标识符:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_sequence);
		r += "序列码:" + temp + "\r\n";
		break;
	case 0:
		r += "  ICMP回显应答协议\r\n";
		temp.Format("%u", icmp->icmp_code);
		r += "ICMP代码:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_id);
		r += "标识符:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_sequence);
		r += "序列码:" + temp + "\r\n";
		break;
	default:
		break;
	}
	temp.Format("%u", ntohs(icmp->icmp_checksum));
	r += "ICMP校验和:" + temp + "\r\n";
	/* 获得ICMP校验和 */
	return r;
}

void CMysnifferDlg::getoffset(FILE *fp)
{
	if (fp == NULL) {
		printf("getoffset error\n%s\n", strerror(ferror(fp)));
		return;
	}
	long len = sizeof(pcap_file_header);
	fseek(fp, len, SEEK_SET);

	pcap_pkthdr pkt;
	u_int pkt_len = 0;
	int cot = 1;
	while (!feof(fp) && cot <= MAXSIZE)
	{
		memset(&pkt, 0, sizeof(pcap_pkthdr));
		if (fread(&pkt, sizeof(pcap_pkthdr), 1, fp) == -1)
		{
			printf("get header error\n");
			break;
		}
		pkgoffset[cot] = ftell(fp);
		pkt_len = pkt.caplen;
		if (fseek(fp, (long)pkt_len, SEEK_CUR))
		{
			printf("\n%s\n", strerror(ferror(fp)));
			return;
		}
		cot++;
		printf("%d : %d  %d\n", cot - 1, pkgoffset[cot - 1], sizeof(pcap_pkthdr));
	}

	pkgoffset[0] = cot - 1;
}

int CMysnifferDlg::getpkg(FILE * fp, int id, pcap_pkthdr * header, const u_char * data)
{
	if (id <= 0) {
		printf("the id is error");
		return -1;
	}
	else if (id > pkgoffset[0]) {
		printf("the id is out of range\n");
		return -1;
	}
	if (pkgoffset[id] - sizeof(pcap_pkthdr) < 0)
	{
		printf("get pkg error\n");
		return -1;
	}
	fseek(fp, pkgoffset[id] - sizeof(pcap_pkthdr), SEEK_SET);

	if (fread((void *)header, sizeof(pcap_pkthdr), 1, fp) != 1)
	{
		printf("fread error1\n");
		return -1;
	}
	if (fread((void *)data, sizeof(char), header->caplen, fp) != header->caplen)
	{
		printf("fread error2: %d\n ", header->caplen);
		return -1;
	}
	fseek(fp, 0 - (header)->caplen, SEEK_CUR);
	return 1;
}

void CMysnifferDlg::OnStnClickedStaticSip()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CMysnifferDlg::OnEnChangeEditDmac()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

void CMysnifferDlg::OnEnChangeEditDataInfoaction()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

void CMysnifferDlg::OnClickedButtonStop()
{
	// TODO: 在此添加控件通知处理程序代码
	STATE = FALSE;
	pcap_freealldevs(this->alldevs);
	this->file = NULL;
	number = 0;
	devnum = 0;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	this->m_device.DeleteAllItems();

}

void CMysnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
}