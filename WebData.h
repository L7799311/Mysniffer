#pragma once

#include <list>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include "pcap.h"
#include <conio.h>
#include <assert.h>
#include "WireDlg.h"

#pragma comment(lib,"wpcap.lib")  

#pragma comment(lib,"packet.lib")  

#pragma comment(lib,"ws2_32.lib")  
using namespace std;

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
	in_addr SourceIpAdd;	 //源ip地址
	u_char DestMacAdd[6];	 //目的mac地址
	in_addr DestIpAdd;		 //目的ip地址
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

struct Data{
	int id;
	pcap_pkthdr *header;
	u_char *data;
	Data() {
		header = (pcap_pkthdr *)malloc(sizeof(pcap_pkthdr));
		data = NULL;
		return;
	}
	int set()
	{
		if (header == NULL) {
			printf("malloc error\n"); return -1;
		} else {
			if((data = (u_char *)malloc(sizeof(u_char) * header->caplen))==NULL)
			{
				printf("data malloc error");
				return -1;
			}
		}
		return 0;
	}
};

typedef list<Data>::iterator dat;

class WebData
{
private:
	static WebData *instance;
	int MAX_DUMP = 10;
	u_int iplen;//ip报文长度
	u_int netmask;
	long pkgoffset[50000 + 2];

	CString m_str;
	CString m_str2;

	FILE *file;
	list <Data> data;

	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_pkthdr *header;
	pcap_t *adhandle;
	pcap_t *fp;
	const u_char *pkt_data;

	pcap_pkthdr *head;
	const u_char *pdata;

	bpf_program fcode;
	pcap_dumper_t *dumpfp;

	tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	char filename[1000];
	void WebData::getoffset(FILE *fp);
	int WebData::getpkg(FILE *fp,int id,pcap_pkthdr *header,const u_char *data);

	void WebData::an_ethernet();
	void WebData::an_ip();
	void WebData::an_udp(int iplen);
	void WebData::an_tcp(int iplen);
	void WebData::an_arp();
	void WebData::an_icmp(int iplen);

	
	int WebData::editpkg();

	int WebData::editmac();
	int WebData::setmac(u_char *);

	int WebData::editip();
	int WebData::setip(ip_header*);
	int WebData::setip(ip_addr*,char []);

	int WebData::editport();
	int WebData::setport(tcp_header *);
	int WebData::setport(udp_header *);

	int WebData::sendPacket(const u_char*, int);
	
	int WebData::getData();
	int WebData::getData(char name[]);
	int WebData::getData1(char name[]);
	
	void WebData::setData();
	void WebData::setData1();
	pcap_t *WebData::getFile();
	void WebData::inputfile();
	void WebData::sendQueue();
public:
	WebData(void);
	~WebData(void);
	pcap_if_t *WebData::getAllDevs();
	pcap_if_t *WebData::getAllDevs(CString str1,CListCtrl device);

	void WebData::freeAllDevs();
	int WebData::getDevsNum();

	
	void begin();
};

