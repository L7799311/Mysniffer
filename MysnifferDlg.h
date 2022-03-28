
// MysnifferDlg.h : 头文件
//
#pragma once

#include "afxcmn.h"

#include "pcap.h"
#include <stdlib.h>
#include "afxwin.h"

struct ether_header
{
	u_char smac[6];
	/* 目的以太网地址 */
	u_char dmac[6];
	/* 源以太网地址 */
	u_short ether_type;
	/* 以太网类型 */
};

typedef struct IPv4
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_addr;

typedef struct IP_Header
{
	u_char ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)  
	u_char  tos;            // 服务类型(Type of service)   
	u_short tlen;           // 总长(Total length)   
	u_short identification; // 标识(Identification)  
	u_short flags;			// 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)  
	u_char  ttl;            // 存活时间(Time to live) 
	u_char  protocol;       // 协议(Protocol)  
	u_short checknum;       // 首部校验和(Header checksum)  
	ip_addr  saddr;			// 源地址(Source address)  
	ip_addr  daddr;			// 目的地址(Destination address)  
	u_int   op_pad;         // 选项与填充(Option + Padding)  
}ip_header;

struct icmp_header
{
	u_int8_t icmp_type;/* ICMP类型 */
	u_int8_t icmp_code;/* ICMP代码 */
	u_int16_t icmp_checksum;/* 校验和 */
	u_int16_t icmp_id;/* 标识符 */
	u_int16_t icmp_sequence;/* 序列码 */
};

struct ARP_header
{
	u_short HardwareType;	 //硬件类型
	u_short ProtocolType;	 //协议类型
	u_short HardwareAddLen;	 //硬件地址长度
	u_short ProtocolAddLen;	 //协议地址长度
	u_short OperationField;  //操作字段
	u_char SourceMacAdd[6];  //源mac地址
	ip_addr SourceIpAdd;	 //源ip地址
	u_char DestMacAdd[6];	 //目的mac地址
	ip_addr DestIpAdd;		 //目的ip地址
};

typedef struct UDP_Header
{
	u_short sport;          // 源端口(Source port)  
	u_short dport;          // 目的端口(Destination port)  
	u_short len;            // UDP数据包长度(Datagram length)  
	u_short crc;            // 校验和(Checksum)  
}udp_header;

typedef struct TCP_Header
{
	u_int16_t tcp_source_port;/* 源端口号 */
	u_int16_t tcp_destination_port;/* 目的端口号 */
	u_int32_t tcp_sequence_lliiuuwweennttaaoo;/* 序列号 */
	u_int32_t tcp_acknowledgement;/* 确认序列号 */
#ifdef WORDS_BIGENDIAN   
	u_int8_t tcp_offset : 4,
		/* 偏移 */
		tcp_reserved : 4;
	/* 未用 */
#else   
	u_int8_t tcp_reserved : 4,/* 未用 */
		tcp_offset : 4;/* 偏移 */
#endif   
	u_int8_t tcp_flags;/* 标记 */
	u_int16_t tcp_windows;/* 窗口大小 */
	u_int16_t tcp_checksum;/* 校验和 */
	u_int16_t tcp_urgent_pointer;/* 紧急指针 */
}tcp_header;
// CMysnifferDlg 对话框
class CMysnifferDlg : public CDialogEx
{
// 构造
public:
	CMysnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_Mysniffer_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
	

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnNMCustomdrawProgress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemchangedListDevice(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemchangedListDevice1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnEnChangeEditDataaction1();
	afx_msg void OnClickListDevice1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClickedButtonGetDevice();
	afx_msg void OnClickListPack(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClickedButtonStart();

	afx_msg
		void getoffset(FILE * fp);
	int getpkg(FILE * fp, int id, pcap_pkthdr * header, const u_char * data);
	afx_msg void OnStnClickedStaticSip();
	//afx_msg void OnClickedButtonSend();

	void getAllDevs();
	void startCap();

	// 显示HTTP协议的详细信息
	//void GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data);
	// 判断该协议是否为HTTP协议
	bool IsHTTP(const u_char *pkt_data);
	CString _arp();
	CString _ip();
	CString _tcp();
	CString _udp();
	CString _icmp();
	CString _http();

	void an_ethernet();
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	int iplen;


	pcap_t *adhandle;
	const u_char *pkt_data;
	pcap_pkthdr *header;
	pcap_dumper_t *dumpfp;

	FILE *file;
	
	pcap_t *fp;
	long pkgoffset[500 + 20000];
	pcap_pkthdr *head;
	const u_char *pdata;
	

	HANDLE hThread;
	DWORD ThreadID;

	int devnum;

	CString m_info;
	CString m_select;
	CListCtrl m_device;
	CListCtrl m_pack;
	CString str;
	CString m_str2;
	CComboBox m_comboBoxRule;
	
	afx_msg void OnEnChangeEditDmac();
	afx_msg void OnEnChangeEditDataInfoaction();
	
	afx_msg void OnClickedButtonStop();
	afx_msg void OnCbnSelchangeCombo1();
};
