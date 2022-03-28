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
	/* Ŀ����̫����ַ */
	u_char dmac[6];
	/* Դ��̫����ַ */
	u_short ether_type;
	/* ��̫������ */
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
	u_char ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)  
	u_char  tos;            // ��������(Type of service)   
	u_short tlen;           // �ܳ�(Total length)   
	u_short identification; // ��ʶ(Identification)  
	u_short flags;			// ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)  
	u_char  ttl;            // ���ʱ��(Time to live) 
	u_char  protocol;       // Э��(Protocol)  
	u_short checknum;       // �ײ�У���(Header checksum)  
	ip_addr  saddr;			// Դ��ַ(Source address)  
	ip_addr  daddr;			// Ŀ�ĵ�ַ(Destination address)  
	u_int   op_pad;         // ѡ�������(Option + Padding)  
}ip_header;

struct icmp_header
{
	u_int8_t icmp_type;/* ICMP���� */
	u_int8_t icmp_code;/* ICMP���� */
	u_int16_t icmp_checksum;/* У��� */
	u_int16_t icmp_id;/* ��ʶ�� */
	u_int16_t icmp_sequence;/* ������ */
};

struct ARP_header
{
	u_short HardwareType;	 //Ӳ������
	u_short ProtocolType;	 //Э������
	u_short HardwareAddLen;	 //Ӳ����ַ����
	u_short ProtocolAddLen;	 //Э���ַ����
	u_short OperationField;  //�����ֶ�
	u_char SourceMacAdd[6];  //Դmac��ַ
	in_addr SourceIpAdd;	 //Դip��ַ
	u_char DestMacAdd[6];	 //Ŀ��mac��ַ
	in_addr DestIpAdd;		 //Ŀ��ip��ַ
};

typedef struct UDP_Header
{
	u_short sport;          // Դ�˿�(Source port)  
	u_short dport;          // Ŀ�Ķ˿�(Destination port)  
	u_short len;            // UDP���ݰ�����(Datagram length)  
	u_short crc;            // У���(Checksum)  
}udp_header;

typedef struct TCP_Header
{
	u_int16_t tcp_source_port;/* Դ�˿ں� */
	u_int16_t tcp_destination_port;/* Ŀ�Ķ˿ں� */
	u_int32_t tcp_sequence_lliiuuwweennttaaoo;/* ���к� */
	u_int32_t tcp_acknowledgement;/* ȷ�����к� */
#ifdef WORDS_BIGENDIAN   
	u_int8_t tcp_offset : 4,
		/* ƫ�� */
		tcp_reserved : 4;
	/* δ�� */
#else   
	u_int8_t tcp_reserved : 4,/* δ�� */
		tcp_offset : 4;/* ƫ�� */
#endif   
	u_int8_t tcp_flags;/* ��� */
	u_int16_t tcp_windows;/* ���ڴ�С */
	u_int16_t tcp_checksum;/* У��� */
	u_int16_t tcp_urgent_pointer;/* ����ָ�� */
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
	u_int iplen;//ip���ĳ���
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

