#include "stdafx.h"
#include "WebData.h"
#include "afxcmn.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4477)
WebData* WebData::instance;
WebData::WebData(void)
{
	this->alldevs = NULL;
	this->fp =NULL;
	
	return;
}

WebData::~WebData(void)
{
}

pcap_if_t *WebData::getAllDevs()
{
    pcap_if_t *d;
    int i=0;
    
    /* ��ȡ���ػ����豸�б� */
	if(this->alldevs != NULL) return this->alldevs;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
    {
        this->alldevs = NULL;
		return NULL;
    }
    
    /* ��ӡ�б� */
    for(d= this->alldevs; d != NULL; d= d->next)
	{
		m_str.Format("%d", i + 1);
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (�޷���ȡ�豸����)\n");
    }
    
    if (i == 0)
    {
        printf("\nû�з����豸! Make sure WinPcap is installed.\n");
		this->alldevs = NULL;
        return NULL;
    }
    return this->alldevs;
}

pcap_if_t * WebData::getAllDevs(CString str1, CListCtrl device)
{
	pcap_if_t *d;
	int i = 0;

	/* ��ȡ���ػ����豸�б� */
	if (this->alldevs != NULL) return this->alldevs;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
	{
		this->alldevs = NULL;
		return NULL;
	}

	/* ��ӡ�б� */
	for (d = this->alldevs; d != NULL; d = d->next)
	{
		str1.Format("%d", i + 1);
		device.InsertItem(i, str1);
		str1 = d->name;
		device.SetItemText(i, 1, str1);
		if (d->description){
			str1 = d->description;
			device.SetItemText(i, 2, str1);
		}
		else
		{
			str1 = "�޷���ȡ�豸����";
			device.SetItemText(i, 2, str1);
		}
		i++;
	}

	if (i == 0)
	{
		printf("\nû�з����豸! Make sure WinPcap is installed.\n");
		this->alldevs = NULL;
		return NULL;
	}
	return this->alldevs;
	return nullptr;
}

void WebData::freeAllDevs(){
	if(this->alldevs != NULL){
		pcap_freealldevs(this->alldevs);
		this->alldevs = NULL;
	}
	return ;
}

int WebData::getDevsNum()
{
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if((this->getAllDevs()) == NULL)
	{
		fprintf(stderr,"Error in pcap_findalldevs : %s\n",errbuf);
		exit(1);
	}

	for(d = alldevs;d != NULL; d = d->next){
		i++;
	}
	return i;
}

int WebData::editpkg()
{
	if(this->pkt_data == NULL)
	{
		printf("[WARN] No package\n");
		return -1;
	}
	ether_header* ether = (ether_header *)pdata;
	int pkg_type = ntohs(ether->ether_type);
	if (pkg_type != 0x0800)
	{
		printf("[WARN] The Package type is not support\n");
		return -1;
	}
	cout << "[INFO] ��ѡ������Ҫ���ĵİ������ݣ�" << endl;
	cout << "1������Mac��ַ" << endl;
	cout << "2������IP��ַ" << endl;
	cout << "3�����Ķ˿ڵ�ַ" << endl;
	//cout << "4������Mac��ַ" << endl;
	int sec;
	scanf("%d", &sec);
	getchar();
	switch(sec)
	{
	case 1:
		this->editmac();
		break;
	case 2:
		this->editip();
		break;
	case 3:
		this->editport();
		break;
	default:
		break;
	}
	/*char cmd;
	do {
		printf("[INFO] Send the Package ?(y/n)");
		cin >> cmd;
		getchar();
	} while (cmd != 'y' || cmd != 'n');
	if (tolower(cmd) == 'y')
	{*/
		if (this->sendPacket(pdata, head->caplen))printf("[INFO] Send Success\n");
		else printf("Send unSuccess\n");
	//}
	return 0;
}

int WebData::editmac()
{
	ether_header *ethernet;
	cout << "��������Ҫ�޸ĵ�mac��ַ�� 1��Դmac��ַ  2��Ŀ��mac��ַ  3��ͬʱ�޸�" << endl;
	int i;
	cin >> i;
	getchar();
	u_char *smac;
	smac = (u_char *)malloc(sizeof(char) * 12);
	u_char *dmac;
	dmac = (u_char *)malloc(sizeof(char) * 12);
	ethernet = (ether_header *) pdata;
	int cot = 0;
	switch(i)
	{
		case 1:
			cout << "�������޸ĵ�mac��ַ��(no ':')" << endl;
			
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0],(int)&smac[1], 
					(int)&smac[2],(int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "�������mac��ַ��������������" << endl;
				else break;
				//else cout << "�������mac��ַ��������������" << endl;
			} while (1);
			for (int j = 0; j < 6; j++) ethernet->smac[j] = smac[j];
			break;
		case 2:
			cout << "�������޸ĵ�mac��ַ��(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "�������mac��ַ��������������" << endl;
				else break;
			} while (1);
			for (int j = 6; j < 12; j++) ethernet->dmac[j] = smac[j-6];
			break;
		case 3:
			cout << "�������޸ĵ�Դmac��ַ��(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "�������mac��ַ��������������" << endl;
				else break;
			} while (1);
			for (int j = 0; j < 6; j++) ethernet->smac[j] = smac[j];
			cout << "�������޸ĵ�Ŀ��mac��ַ��(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(dmac) == -1)
					cout << "�������mac��ַ��������������" << endl;
				else break;
			} while (1);
			for (int j = 6; j < 12; j++) ethernet->dmac[j] = smac[j-6];
			break;
	}
	return 0;
}

int WebData::setmac(u_char *mac)
{
	int num[18] = { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8 ,0x9 ,0xa
		,0xb ,0xc,0xd,0xe,0xf };
	for(int i = 0;i <6;i ++)
	{
		if (mac[i] < 0x0 || mac[i] > 0xff) return -1;
	}
	return 1;
}

int WebData::editip()
{
	ip_header *ip;
	ip = (ip_header *)(pdata + 14);
	if(this->setip(ip) == -1)
	{
		printf("[ERROR] Set ip error\n");
		return -1;
	}
	return 1;
}

int WebData::setip(ip_header *ip)
{
	char newip[200];
	ip_addr *ip4;
	int i;
	printf("��������Ҫ���ĵ�ip��1��ԴIP��2��Ŀ��IP\n");
	scanf("%d", &i);
	getchar();
	printf("�������޸ĵ���IP :(���� q �˳�����)");
	cin >> newip;
	getchar();


	if(newip[0] == 'q')
	{
		printf("[INFO] Exit \n");
		return 0;
	}
	else if (i == 1) {
		ip4 = &ip->saddr;
	} else if(i == 2){
		ip4 = &ip->daddr;
	}
	if (this->setip(ip4,newip))
	{
		printf("[ERROR] Set ip error\n");
		return -1;
	}
	return 1;
}

int WebData::setip(ip_addr *ipaddr,char ip[])
{
	char *endptr;
	u_char a, b, c, d, t;

	a = 127;
	t = 0;
	t = strtol(ip, &endptr, 10);
	if (endptr == ip || *endptr != '.' || endptr > ip + 3 || t > 255)
	{
		fprintf(stderr, "1\na|%d|%c|%c|%s|%s|\n", t, *endptr, *ip, ip, endptr);
		return 1;
	}
	a = t;

	b = 0;
	t = 0;
	ip = endptr + 1;
	t = strtol(ip, &endptr, 10);
	if (endptr == ip || *endptr != '.' || endptr > ip + 3 || t > 255)
	{
		fprintf(stderr, "2\nb|%d|%c|%c|%s|%s|\n", t, *endptr, *ip, ip, endptr);
		return 2;
	}
	b = t;

	c = 0;
	t = 0;
	ip = endptr + 1;
	t = strtol(ip, &endptr, 10);
	if (endptr == ip || *endptr != '.' || endptr > ip + 3 || t > 255)
	{
		fprintf(stderr, "3\nc|%d|%c|%c|%s|%s|\n", t, *endptr, *ip, ip, endptr);
		return 3;
	}
	c = t;

	d = 1;
	t = 0;
	ip = endptr + 1;
	t = strtol(ip, &endptr, 10);
	if (endptr == ip || endptr > ip + 3 || t > 255)
	{
		fprintf(stderr, "4\nd|%d|%c|%c|%s|%s|\n", t, *endptr, *ip, ip, endptr);
		return 4;
	}
	d = t;

	printf("[INFO] will set %d.%d.%d.%d as dest ip\n", a, b, c, d);
	ipaddr->byte1 = (u_char)a;
	ipaddr->byte2 = (u_char)b;
	ipaddr->byte3 = (u_char)c;
	ipaddr->byte4 = (u_char)d;

	return 0;
}

int WebData::editport()
{
	ip_header *ip;
	ip = (ip_header *)(pdata + 14);
	int i = ip->protocol;
	switch (i)
	{
	case 6:
		this->setport((tcp_header *)(pdata + 14 + (ip->ver_ihl & 0xf) * 4));
		break;
	case 17:
		this->setport((udp_header *)(pdata + 14 + (ip->ver_ihl & 0xf) * 4));
		break;
	default:
		break;
	}
	return 0;
}

int WebData::setport(tcp_header *tcp)
{
	cout << "����������Ҫ���ĵĶ˿ڣ�1��Դ�˿�  2��Ŀ�Ķ˿�" << endl;
	int i;
	cin >> i;
	getchar();
	u_short port;
	do {
		cout << "������˿ںţ�(1-65534)" << endl;
		cin >> port;
		getchar();
	} while (port < 0 && port >= 65535);
	port = (u_short)port;
	switch (i)
	{
	case 1:
		tcp->tcp_source_port = htons(port);
	case 2:
		tcp->tcp_source_port = htons(port);
	default:
		break;
	}

	return 1;
}

int WebData::setport(udp_header *udp) {
	cout << "����������Ҫ���ĵĶ˿ڣ�1��Դ�˿�  2��Ŀ�Ķ˿�" << endl;
	int i;
	cin >> i;
	getchar();
	u_short port;
	do {
		cout << "������˿ںţ�(1-65534)" << endl;
		cin >> port;
		getchar();
	} while (port < 0 && port >= 65535);
	port = (u_short)port;
	switch (i)
	{
	case 1:
		udp->sport = htons(port);
	case 2:
		udp->dport = htons(port);
	default:
		break;
	}

	return 1;
}

int WebData::getData()
{
	pcap_if_t *d;
	int inum;
	int i=0;
	int res;
    /* ��ȡ�����豸�б� */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"��ȡ�豸����: %s\n", errbuf);
        exit(1);
	}

	if(( i = this->getDevsNum() )< 1)
	{
		printf("���豸\n");
		return 0;
	}

    printf("��������Ҫ�������豸��� (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n�豸��ų�����Χ.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    if ( (adhandle= pcap_open(d->name,          // �豸��
                              65536,            // Ҫ��׽�����ݰ��Ĳ��� 
                                                // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                              ) ) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
    
    printf("\n���ڲ�׽ %s...\n", d->description);
    

    if (d->addresses != NULL)
	{ 
		netmask =((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
    else
	{netmask=0xffffff;} 

	
	//compile the filter*
    if (pcap_compile(adhandle, &fcode, "ip and icmp", 1, netmask) < 0)
    {
        fprintf(stderr,"\n�޷������������. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
	//set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n���������ô���.\n");
		this->freeAllDevs();
        return -1;
    }
	
	this->freeAllDevs();

    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
	{
        if(res == 0)
            continue;
		this->an_ethernet();
		//this->anpacket();
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
    return 0;
}

int WebData::getData(char name[])
{
	pcap_if_t *d;
	int inum;
	int i=0;
	int res;
    
    /* ��ȡ�����豸�б� */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"��ȡ�豸����: %s\n", errbuf);
        exit(1);
	}

	if(( i = this->getDevsNum()) < 1)
	{
		printf("���豸\n");
		return 0;
	}

    printf("��������Ҫ�������豸��� (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n�豸��ų�����Χ.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    if ( (adhandle= pcap_open(d->name,          // �豸��
                              65536,            // Ҫ��׽�����ݰ��Ĳ��� 
                                                // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                              ) ) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
    
    printf("\n���ڲ�׽ %s...\n", d->description);
    

    if (d->addresses != NULL)
	{ 
		netmask =((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
    else
	{netmask=0xffffff;} 


	/*compile the filter*/
    if (pcap_compile(adhandle, &fcode, name, 1, netmask) < 0)
    {
        fprintf(stderr,"\n�޷������������. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
	/*set the filter*/
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n���������ô���.\n");
		this->freeAllDevs();
        return -1;
    }

	this->freeAllDevs();

    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
	{
        if(res == 0)
            continue;
		//this->anpacket();
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
    return 0;
}

int WebData::getData1(char name[])
{
	int res = 0;
    netmask=0xffffff; 
	pcap_t *file = this->getFile();

    if (pcap_compile(file, &fcode,"tcp and ip", 1, netmask) < 0)
    {
        fprintf(stderr,"\n�޷������������. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
    if (pcap_setfilter(file, &fcode) < 0)
    {
        fprintf(stderr,"\n���������ô���.\n");
		this->freeAllDevs();
        return -1;
    }

	this->freeAllDevs();

    while((res = pcap_next_ex(file, &header, &pkt_data)) >= 0)
	{
        if(res == 0)
            continue;
		this->an_ethernet();
//		this->anpacket();
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
	return 1;
}

void WebData::begin()
{
	int i = 0;
	while (1)
	{
		cout << "��ѡ��" << endl;
		cout << "1����ʼ��׽" << endl;
		cout << "2�����ù�����Ϣ" << endl;
		cout << "3����ʾ������Ϣ" << endl;
		cin >> i;
		getchar();
		switch (i)
		{
		case 1:
			this->setData();
			break;
		case 2:
			this->inputfile();
		}
	}
}

void WebData::setData()
{
	pcap_if_t *d;
	int inum;
	int i=0;
	int res;
	u_int netmask;

	if(this->getAllDevs() == NULL){
		fprintf(stderr,"��ȡ�豸����: %s\n", errbuf);
        exit(1);
	}
	if(( i = this->getDevsNum() )< 1){
		printf("���豸\n");
		return;
	}

    printf("��������Ҫ�������豸��� (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n�豸��ų�����Χ.\n");
		this->freeAllDevs();
		
        return ;
    }

    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    if ((adhandle= pcap_open(d->name,          // �豸��
                              65536,            // Ҫ��׽�����ݰ��Ĳ��� 
                                                // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                              ) ) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return;
    }
    
    printf("\n���ڲ�׽ %s...\n", d->description);

	if (d->addresses != NULL)
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask=0xffffff; 


    if (pcap_compile(adhandle, &fcode, "ip and tcp", 1, netmask) < 0)
    {
        fprintf(stderr,"\n�޷������������. Check the syntax.\n");
		this->freeAllDevs();
        return;
    }
    
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n���������ô���.\n");
		this->freeAllDevs();
        return;
    }
	
    if((dumpfp = pcap_dump_open(this->adhandle,"data.pcap")) == NULL) {
		printf("������ļ�����\n");
		exit(-1);
	}
	
	this->freeAllDevs();
	int cot = 0;
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
		if (cot == MAX_DUMP) break;
        if(res == 0) continue;
		printf("id2:%d , len:%d", cot, header->caplen);
		printf("\r");
		pcap_dump((u_char *) dumpfp,
			(const pcap_pkthdr *)this->header,
			(const u_char *)this->pkt_data);
		cot++;

		this->an_ethernet();
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return;
    }
	pcap_dump_close(dumpfp);
    return ;
}

void WebData::setData1()
{
	pcap_if_t *d;
	int inum;
	int i = 0;
	int res;
	u_int netmask;

	if (this->getAllDevs() == NULL) {
		fprintf(stderr, "��ȡ�豸����: %s\n", errbuf);
		exit(1);
	}
	if ((i = this->getDevsNum())< 1) {
		printf("���豸\n");
		return;
	}

	printf("��������Ҫ�������豸��� (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\n�豸��ų�����Χ.\n");
		this->freeAllDevs();

		return;
	}

	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // Ҫ��׽�����ݰ��Ĳ��� 
						  // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\n�޷���������. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
		return;
	}

	printf("\n���ڲ�׽ %s...\n", d->description);

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	if (pcap_compile(adhandle, &fcode, "ip and tcp", 1, netmask) < 0)
	{
		fprintf(stderr, "\n�޷������������. Check the syntax.\n");
		this->freeAllDevs();
		return;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n���������ô���.\n");
		this->freeAllDevs();
		return;
	}
	FILE *fp;
	if ((fp = fopen("data.pcap", "wb")) == NULL)
	{
		printf("open file error\n");
		exit(1);
	}
	this->freeAllDevs();
	int cot = 0;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (cot == 10) break;
		cot++;
		if (res == 0) continue;
		Data *temp = new Data();
		temp->header = header;
		if (temp->set() == -1) {
			printf("temp set error\n");
			exit(1);
		}
		temp->data = (u_char *)pkt_data;
		fwrite(temp, sizeof(Data), 1, fp);
		//fwrite(pkt_data, sizeof(u_char)*header->caplen, 1, fp);
		assert(fwrite != NULL);
		//this->anpacket();
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return;
	}
	fclose(fp);
	//pcap_dump_close(dumpfp);
	return;
}

pcap_t *WebData::getFile()
{
	if(fp != NULL) 
		return fp; 
	/*printf("�������ȡ���ļ���:");
	scanf("%s",filename);
	int len = strlen(filename);
	filename[len++] = '.';
	filename[len++] = 'p';
	filename[len++] = 'c';
	filename[len++] = 'a';
	filename[len++] = 'p';
	filename[len] = '\0';*/
	if((fp = pcap_open_offline("pp.pcap",errbuf)) == NULL)
	{
		fprintf(stderr,"���ļ�����");
		fp = NULL;
		exit(1);
	}
	
	//printf("%s .success",filename);
	return fp;
}

void WebData::an_udp(int iplen) 
{
	udp_header *udp;

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
	printf("----------  UDPЭ��    ----------\n");
	printf("Դ�˿ں�:%d\n", sport);
	printf("Ŀ�Ķ˿ں�:%d\n", dport);
	switch (dport)
	{
	case 138:
		printf("�ϲ�Э��ΪNETBIOS���ݱ�����\n");
		break;
	case 137:
		printf("�ϲ�Э��ΪNETBIOS���ַ���\n");
		break;
	case 139:
		printf("�ϲ�Э��ΪNETBIOS�Ự����n");
		break;
	case 53:
		printf("�ϲ�Э��ΪDNS��������\n");
		break;
	default:
		break;
	}
	printf("����:%d\n", len);
	printf("У���:%d\n",crc);
}

void WebData::an_arp()
{
	ARP_header *arp;
	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char *macaddr;

	u_short hardware_length;
	u_short protocol_length;

	printf("--------   ARPЭ��    --------\n");
	arp = (ARP_header *)((u_char *)pkt_data + 14);
	hardware_type = ntohs(arp->HardwareType);
	protocol_type = ntohs(arp->ProtocolType);
	operation_code = ntohs(arp->OperationField);
	hardware_length = arp->HardwareAddLen;
	protocol_length = arp->ProtocolAddLen;
	printf("Ӳ������:%d\n", hardware_type);
	printf("Э������ Protocol Type:%d\n", protocol_type);
	printf("Ӳ����ַ����:%d\n", hardware_length);
	printf("Э���ַ����:%d\n", protocol_length);
	printf("ARP Operation:%d\n", operation_code);
	switch (operation_code)
	{
	case 1:
		printf("ARP����Э��\n");
		break;
	case 2:
		printf("ARPӦ��Э��\n");
		break;
	case 3:
		printf("RARP����Э��\n");
		break;
	case 4:
		printf("RARPӦ��Э��\n");
		break;
	default:
		break;
	}
	printf("Դ��̫����ַ: \n");
	macaddr = arp->SourceMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	
	/* ���Դ��̫����ַ */
	printf("Ŀ����̫����ַ: \n");
	macaddr = arp->DestMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, 
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));

	/* ���Ŀ����̫����ַ */
	/*mac_string = arp->SourceMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	memcpy((void*)& sip, (void*)& arp->SourceIpAdd, sizeof(struct in_addr));
	printf("ԴIP��ַ:%s\n", inet_ntop( sip);
	printf("Ŀ����̫����ַ: \n");
	mac_string = arp->DestMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	memcpy((void*)& dip, (void*)& arp->DestIpAdd, sizeof(struct in_addr));
	printf("Ŀ��IP��ַ:%s\n", inet_ntoa(dip));*/

	return;
}

void WebData::an_icmp(int iplen)
{
	struct icmp_header* icmp;
	/* ICMPЭ����� */
	icmp = (struct icmp_header*)((u_char *)pkt_data + 14 + iplen);
	/* ���ICMPЭ������ */
	printf("----------  ICMPЭ��    ----------\n");
	printf("ICMP����:%d\n", icmp->icmp_type);
	/* ���ICMP���� */
	switch (icmp->icmp_type)
	{
	case 8:
		printf("ICMP��������Э��\n");
		printf("ICMP����:%d\n", icmp->icmp_code);
		printf("��ʶ��:%d\n", icmp->icmp_id);
		printf("������:%d\n", icmp->icmp_sequence);
		break;
	case 0:
		printf("ICMP����Ӧ��Э��\n");
		printf("ICMP����:%d\n", icmp->icmp_code);
		printf("��ʶ��:%d\n", icmp->icmp_id);
		printf("������:%d\n", icmp->icmp_sequence);
		break;
	default:
		break;
	}
	printf("ICMPУ���:%d\n", ntohs(icmp->icmp_checksum));
	/* ���ICMPУ��� */
	return;

}

void WebData::an_ip()
{
	ip_header *ip;
	u_short version;
	u_short header_lenth;
	u_int offset;
	u_char tos;
	u_short id;
	u_char flag;
	u_int16_t checksum;
	
	ip = (ip_header*)(pkt_data + 14);
	version = ((ip->ver_ihl & 0xf0) >> 4);
	header_lenth = (ip->ver_ihl & 0xf) * 4;
	tos = ip->tos;
	id = ntohs(ip->identification);
	flag = (ip->identification >> 13);
	offset = ntohs((ip->flags & 0x1fff));
	checksum = ntohs(ip->checknum);
	
	printf("----------- IPЭ��    -----------\n");
	printf("�汾��:%d\n",version);
	printf("�ײ�����:%d\n", header_lenth);
	printf("��������:%d\n", tos);
	printf("�ܳ���:%d\n", ntohs(ip->tlen));
	printf("��ʶ:%d\n", ntohs(ip->identification));
	printf("ƫ��:%d\n", offset);
	printf("����ʱ��:%d\n", ip->ttl);
	printf("Э������:%d\n", ip->protocol);
	printf("У���:%d\n", checksum);
	printf("ԴIP��ַ:%d.%d.%d.%d\n", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);

	printf("Ŀ��IP��ַ:%d.%d.%d.%d\n",ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
	switch (ip->protocol)
	{
	case 6:
		printf("�ϲ�Э��ΪTCPЭ��\n");
		this->an_tcp(header_lenth);
		break;
	case 17:
		printf("�ϲ�Э��ΪUDPЭ��\n");
		this->an_udp(header_lenth);
		break;
	case 1:
		printf("�ϲ�Э��ΪICMPЭ��ICMP\n");
		this->an_icmp(header_lenth);
		break;
	default:
		break;
	}
	return;

}

void WebData::an_tcp(int iplen)
{
	tcp_header* tcp;/* TCPЭ����� */

	u_char flags;/* ��� */
	int header_length;/* ���� */
	u_short source_port;/* Դ�˿� */
	u_short destination_port;/* Ŀ�Ķ˿� */
	u_short windows;/* ���ڴ�С */
	u_short urgent_pointer;/* ����ָ�� */
	u_int sequence;/* ���к� */
	u_int acknowledgement;/* ȷ�Ϻ� */
	u_int16_t checksum;/* У��� */
	
	tcp = (tcp_header*)((u_char *)pkt_data + 14 + iplen);/* ���TCPЭ������ */
	source_port = ntohs(tcp->tcp_source_port);/* ���Դ�˿� */
	destination_port = ntohs(tcp->tcp_destination_port);/* ���Ŀ�Ķ˿� */
	header_length = tcp->tcp_offset * 4;/* ���� */
	sequence = ntohl(tcp->tcp_sequence_lliiuuwweennttaaoo);/* ������ */
	acknowledgement = ntohl(tcp->tcp_acknowledgement);/* ȷ�������� */
	windows = ntohs(tcp->tcp_windows);/* ���ڴ�С */
	urgent_pointer = ntohs(tcp->tcp_urgent_pointer);/* ����ָ�� */
	flags = tcp->tcp_flags;/* ��ʶ */
	checksum = ntohs(tcp->tcp_checksum);/* У��� */
	printf("-------  TCPЭ��   -------\n");
	printf("Դ�˿ں�:%d\n", source_port);
	printf("Ŀ�Ķ˿ں�:%d\n", destination_port);
	switch (destination_port)
	{
	case 80:
		printf("�ϲ�Э��ΪHTTPЭ��\n");
		break;
	case 21:
		printf("�ϲ�Э��ΪFTPЭ��\n");
		break;
	case 23:
		printf("�ϲ�Э��ΪTELNETЭ��\n");
		break;
	case 25:
		printf("�ϲ�Э��ΪSMTPЭ��\n");
		break;
	case 110:
		printf("�ϲ�Э��POP3Э��\n");
		break;
	default:
		break;
	}
	printf("������:%u\n", sequence);
	printf("ȷ�Ϻ�:%u\n", acknowledgement);
	printf("�ײ�����:%d\n", header_length);
	printf("����:%d\n", tcp->tcp_reserved);
	printf("���:");
	if (flags & 0x08)
		printf("PSH ");
	if (flags & 0x10)
		printf("ACK ");
	if (flags & 0x02)
		printf("SYN ");
	if (flags & 0x20)
		printf("URG ");
	if (flags & 0x01)
		printf("FIN ");
	if (flags & 0x04)
		printf("RST ");
	printf("\n");
	printf("���ڴ�С:%d\n", windows);
	printf("У���:%d\n", checksum);
	printf("����ָ��:%d\n", urgent_pointer);


}

void WebData::an_ethernet()
{
	u_short ethernet_type;
	ether_header *ethernet;
	u_char *macaddr;
	ethernet = (ether_header *)pkt_data;
	static int ethernet_number = 1;
	ethernet_type = ntohs(ethernet->ether_type);
	printf("��̫������:");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type) /* ������̫�������ж� */
	{
		case 0x0800:
			printf("�ϲ�Э��ΪIPЭ��\n");
			break;
		case 0x0806:
			printf("�ϲ�Э��ΪARPЭ��\n");
			break;
		case 0x8035:
			printf("�ϲ�Э��ΪRARPЭ��\n");
			break;
		default:
			break;
	}
	printf("Դ��̫����ַ: \n");
	macaddr = ethernet->smac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, *(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	/* ���Դ��̫����ַ */
	printf("Ŀ����̫����ַ: \n");
	macaddr = ethernet->dmac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, *(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));

	/* ���Ŀ����̫����ַ */
	switch (ethernet_type)
	{
	case 0x0806:
		this->an_arp();
		break;
		/* �ϲ�Э��ΪARPЭ�飬���÷���ARPЭ��ĺ�����ע������Ĵ��� */
	case 0x0800:
		this->an_ip();
		break;
		/* �ϲ�Э��ΪIPЭ�飬���÷���IPЭ��ĺ�����ע������Ĵ��� */
	default:
		break;
	}
	printf("**************************************************\n");
	ethernet_number++;

}

int WebData::sendPacket(const u_char* data, int len)
{
	pcap_if_t *d;
	int inum;
	int i=0;
	int res;
    /* ��ȡ�����豸�б� */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"��ȡ�豸����: %s\n", errbuf);
        exit(1);
	}
	if(( i = this->getDevsNum()) < 1)
	{
		printf("���豸\n");
		return -1;
	}
    printf("��ѡ���豸���з��� (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n�豸��ų�����Χ.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    if ( (adhandle= pcap_open(d->name,          // �豸��
                              65535,            // Ҫ��׽�����ݰ��Ĳ��� 
                                                // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                              ) ) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
	cout << "y" << endl;
    /* �������ݰ� */
    if (pcap_sendpacket(adhandle,data,len/* size */) != 0)
    {
        fprintf(stderr,"\n[WARN]Error sending the packet: \n");
        return -1;
    }
    return 1;
}

void WebData::getoffset(FILE *fp)
{
	if(fp == NULL){
		printf("getoffset error\n%s\n",	strerror(ferror(fp)));
		return;
	}
	long len = sizeof(pcap_file_header);
	fseek(fp, len, SEEK_SET);
	
	pcap_pkthdr pkt;
	u_int pkt_len = 0;
	int cot = 1;
	while(!feof(fp) && cot <= MAX_DUMP)
	{
		memset(&pkt, 0, sizeof(pcap_pkthdr));
		if(fread(&pkt,sizeof(pcap_pkthdr),1,fp) == -1)
		{
			printf("get header error\n");
			break;
		}
		pkgoffset[cot] = ftell(fp);
		pkt_len = pkt.caplen;
		if(fseek(fp,(long)pkt_len, SEEK_CUR))
		{
			printf("\n%s\n", strerror(ferror(fp)));
			return;
		}
		cot++;
		printf("%d : %d  %d\n", cot - 1, pkgoffset[cot - 1] ,sizeof(pcap_pkthdr));
	}

	pkgoffset[0] = cot - 1;
}

int WebData::getpkg(FILE * fp, int id, pcap_pkthdr * header, const u_char * data)
{
	if (id <= 0) {
		printf("the id is error");
			return -1;
	}
	else if (id > pkgoffset[0]) {
		printf("the id is out of range\n");
		return -1;
	}
	if(pkgoffset[id] - sizeof(pcap_pkthdr) < 0)
	{
			printf("get pkg error\n");
			return -1;
	}
	fseek(fp, pkgoffset[id] - sizeof(pcap_pkthdr), SEEK_SET);

	if(fread((void *)header,sizeof(pcap_pkthdr),1,fp) != 1)
	{
		printf("fread error1\n");
		return -1;
	}
	if (fread((void *)data,sizeof(char),header->caplen, fp) != header->caplen)
	{
		printf("fread error2: %d\n ",header->caplen);
		return -1;
	}
	fseek(fp, 0 - (header)->caplen, SEEK_CUR);	
	return 1;
}

void show(int id, const u_char *dat)
{
	ip_header *ih;
	ih = (ip_header*)(dat + 14);
	printf("%d:%d.%d.%d.%d -> %d.%d.%d.%d\n", id,
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
}

void WebData::inputfile()
{
	if((file = fopen("data.pcap", "rb+")) == NULL)
	{
		printf("[WARN]open file error\n");
		return;
	}
	this->getoffset(file);
	cout << "here" << endl;
	fseek(file, 0, SEEK_SET);
	char cmd[5];
	memset(cmd, 0, sizeof(cmd));
	head = NULL;
	head = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	pdata = NULL;
	pdata = (u_char *)malloc(sizeof(u_char) * 65535);
	int id = 0,cot= 0,res = 0,ret = 0,sel = 0;
	while(1)
	{
		cout << "here" << endl;
		memset((void *) head,0,sizeof(pcap_pkthdr));
		memset((void *)pdata, 0, sizeof(u_char) * 65535);
		id = 0;
		cot = 0;
		printf("pkg : %d\n", pkgoffset[0]);
		while(!feof(file) &&(res = this->getpkg(file,cot+1,head,pdata)) > 0)
		{
			cot++;
			cout << "here" << endl;
			//printf("%d(%d). %ld:%ld (%ld) ", id, cot, head->ts.tv_sec, head->ts.tv_usec, head->len);
			show(cot, pdata);
			if (cot != pkgoffset[0])
				continue;
			else printf("[INFO] please select the packeage you want to edit(between 1 to %d)", cot);
			cin >> cmd;
			getchar();
			
			if (cmd[0] == 'q')
			{
				printf("[INFO] exit edit\n");
				ret = 0;
				goto exit;
			}
			sel = 0;
			sel = atoi(cmd);
			if (!isdigit(cmd[0]) || sel <= 0 || sel > cot)
			{
				printf("[INFO] continue\n");
				continue;
			}
			else
			{
				printf("[INFO] NO.%d package selected.\n", sel);
				break;
			}
			if (res == -1)
			{
				//printf("Error reading the packets: %s\n", pcap_geterr(dev));
				printf("Error reading the packets");
				ret = -1;
				goto exit;
			}
			else if (res == -2)
			{
				printf("\n[INFO] no more package.\n");
				ret = 0;
				break;
			}

			printf("\n\n");
			

			printf("\n\n");
		}
		printf("sel : %d\n", sel);
		this->getpkg(file,sel, head, pdata);

		this->editpkg();

		//getchar();
	}

exit:
	fclose(file);
	//pcap_close(dev);
	return ;
}

