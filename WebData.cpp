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
    
    /* 获取本地机器设备列表 */
	if(this->alldevs != NULL) return this->alldevs;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
    {
        this->alldevs = NULL;
		return NULL;
    }
    
    /* 打印列表 */
    for(d= this->alldevs; d != NULL; d= d->next)
	{
		m_str.Format("%d", i + 1);
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (无法获取设备详情)\n");
    }
    
    if (i == 0)
    {
        printf("\n没有发现设备! Make sure WinPcap is installed.\n");
		this->alldevs = NULL;
        return NULL;
    }
    return this->alldevs;
}

pcap_if_t * WebData::getAllDevs(CString str1, CListCtrl device)
{
	pcap_if_t *d;
	int i = 0;

	/* 获取本地机器设备列表 */
	if (this->alldevs != NULL) return this->alldevs;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
	{
		this->alldevs = NULL;
		return NULL;
	}

	/* 打印列表 */
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
			str1 = "无法获取设备详情";
			device.SetItemText(i, 2, str1);
		}
		i++;
	}

	if (i == 0)
	{
		printf("\n没有发现设备! Make sure WinPcap is installed.\n");
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
	cout << "[INFO] 请选择您需要更改的包的内容：" << endl;
	cout << "1、更改Mac地址" << endl;
	cout << "2、更改IP地址" << endl;
	cout << "3、更改端口地址" << endl;
	//cout << "4、更改Mac地址" << endl;
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
	cout << "请输入需要修改的mac地址： 1、源mac地址  2、目的mac地址  3、同时修改" << endl;
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
			cout << "请输入修改的mac地址：(no ':')" << endl;
			
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0],(int)&smac[1], 
					(int)&smac[2],(int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "您输入的mac地址有误，请重新输入" << endl;
				else break;
				//else cout << "您输入的mac地址有误，请重新输入" << endl;
			} while (1);
			for (int j = 0; j < 6; j++) ethernet->smac[j] = smac[j];
			break;
		case 2:
			cout << "请输入修改的mac地址：(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "您输入的mac地址有误，请重新输入" << endl;
				else break;
			} while (1);
			for (int j = 6; j < 12; j++) ethernet->dmac[j] = smac[j-6];
			break;
		case 3:
			cout << "请输入修改的源mac地址：(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int)&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(smac) == -1)
					cout << "您输入的mac地址有误，请重新输入" << endl;
				else break;
			} while (1);
			for (int j = 0; j < 6; j++) ethernet->smac[j] = smac[j];
			cout << "请输入修改的目的mac地址：(no ':')" << endl;
			do {
				scanf("%x %x %x %x %x %x", (int&smac[0], (int)&smac[1],
					(int)&smac[2], (int)&smac[3], (int)&smac[4], (int)&smac[5]);
				getchar();
				if (this->setmac(dmac) == -1)
					cout << "您输入的mac地址有误，请重新输入" << endl;
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
	printf("请输入需要更改的ip：1、源IP；2、目的IP\n");
	scanf("%d", &i);
	getchar();
	printf("请输入修改的新IP :(输入 q 退出程序)");
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
	cout << "请输入您需要更改的端口：1、源端口  2、目的端口" << endl;
	int i;
	cin >> i;
	getchar();
	u_short port;
	do {
		cout << "请输入端口号：(1-65534)" << endl;
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
	cout << "请输入您需要更改的端口：1、源端口  2、目的端口" << endl;
	int i;
	cin >> i;
	getchar();
	u_short port;
	do {
		cout << "请输入端口号：(1-65534)" << endl;
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
    /* 获取本机设备列表 */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"获取设备错误: %s\n", errbuf);
        exit(1);
	}

	if(( i = this->getDevsNum() )< 1)
	{
		printf("无设备\n");
		return 0;
	}

    printf("请输入需要监听的设备序号 (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n设备序号超出范围.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分 
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        fprintf(stderr,"\n无法打开适配器. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
    
    printf("\n正在捕捉 %s...\n", d->description);
    

    if (d->addresses != NULL)
	{ 
		netmask =((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
    else
	{netmask=0xffffff;} 

	
	//compile the filter*
    if (pcap_compile(adhandle, &fcode, "ip and icmp", 1, netmask) < 0)
    {
        fprintf(stderr,"\n无法编译包过滤器. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
	//set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n过滤器设置错误.\n");
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
    
    /* 获取本机设备列表 */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"获取设备错误: %s\n", errbuf);
        exit(1);
	}

	if(( i = this->getDevsNum()) < 1)
	{
		printf("无设备\n");
		return 0;
	}

    printf("请输入需要监听的设备序号 (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n设备序号超出范围.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分 
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        fprintf(stderr,"\n无法打开适配器. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
    
    printf("\n正在捕捉 %s...\n", d->description);
    

    if (d->addresses != NULL)
	{ 
		netmask =((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
    else
	{netmask=0xffffff;} 


	/*compile the filter*/
    if (pcap_compile(adhandle, &fcode, name, 1, netmask) < 0)
    {
        fprintf(stderr,"\n无法编译包过滤器. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
	/*set the filter*/
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n过滤器设置错误.\n");
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
        fprintf(stderr,"\n无法编译包过滤器. Check the syntax.\n");
		this->freeAllDevs();
        return -1;
    }
    
    if (pcap_setfilter(file, &fcode) < 0)
    {
        fprintf(stderr,"\n过滤器设置错误.\n");
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
		cout << "请选择：" << endl;
		cout << "1、开始捕捉" << endl;
		cout << "2、设置过滤信息" << endl;
		cout << "3、显示所有信息" << endl;
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
		fprintf(stderr,"获取设备错误: %s\n", errbuf);
        exit(1);
	}
	if(( i = this->getDevsNum() )< 1){
		printf("无设备\n");
		return;
	}

    printf("请输入需要监听的设备序号 (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n设备序号超出范围.\n");
		this->freeAllDevs();
		
        return ;
    }

    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    if ((adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分 
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        fprintf(stderr,"\n无法打开适配器. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return;
    }
    
    printf("\n正在捕捉 %s...\n", d->description);

	if (d->addresses != NULL)
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask=0xffffff; 


    if (pcap_compile(adhandle, &fcode, "ip and tcp", 1, netmask) < 0)
    {
        fprintf(stderr,"\n无法编译包过滤器. Check the syntax.\n");
		this->freeAllDevs();
        return;
    }
    
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\n过滤器设置错误.\n");
		this->freeAllDevs();
        return;
    }
	
    if((dumpfp = pcap_dump_open(this->adhandle,"data.pcap")) == NULL) {
		printf("打开输出文件错误\n");
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
		fprintf(stderr, "获取设备错误: %s\n", errbuf);
		exit(1);
	}
	if ((i = this->getDevsNum())< 1) {
		printf("无设备\n");
		return;
	}

	printf("请输入需要监听的设备序号 (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\n设备序号超出范围.\n");
		this->freeAllDevs();

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
		fprintf(stderr, "\n无法打开适配器. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
		return;
	}

	printf("\n正在捕捉 %s...\n", d->description);

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	if (pcap_compile(adhandle, &fcode, "ip and tcp", 1, netmask) < 0)
	{
		fprintf(stderr, "\n无法编译包过滤器. Check the syntax.\n");
		this->freeAllDevs();
		return;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n过滤器设置错误.\n");
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
	/*printf("请输入读取的文件名:");
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
		fprintf(stderr,"打开文件错误");
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
	printf("----------  UDP协议    ----------\n");
	printf("源端口号:%d\n", sport);
	printf("目的端口号:%d\n", dport);
	switch (dport)
	{
	case 138:
		printf("上层协议为NETBIOS数据报服务\n");
		break;
	case 137:
		printf("上层协议为NETBIOS名字服务\n");
		break;
	case 139:
		printf("上层协议为NETBIOS会话服务n");
		break;
	case 53:
		printf("上层协议为DNS域名服务\n");
		break;
	default:
		break;
	}
	printf("长度:%d\n", len);
	printf("校验和:%d\n",crc);
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

	printf("--------   ARP协议    --------\n");
	arp = (ARP_header *)((u_char *)pkt_data + 14);
	hardware_type = ntohs(arp->HardwareType);
	protocol_type = ntohs(arp->ProtocolType);
	operation_code = ntohs(arp->OperationField);
	hardware_length = arp->HardwareAddLen;
	protocol_length = arp->ProtocolAddLen;
	printf("硬件类型:%d\n", hardware_type);
	printf("协议类型 Protocol Type:%d\n", protocol_type);
	printf("硬件地址长度:%d\n", hardware_length);
	printf("协议地址长度:%d\n", protocol_length);
	printf("ARP Operation:%d\n", operation_code);
	switch (operation_code)
	{
	case 1:
		printf("ARP请求协议\n");
		break;
	case 2:
		printf("ARP应答协议\n");
		break;
	case 3:
		printf("RARP请求协议\n");
		break;
	case 4:
		printf("RARP应答协议\n");
		break;
	default:
		break;
	}
	printf("源以太网地址: \n");
	macaddr = arp->SourceMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	
	/* 获得源以太网地址 */
	printf("目的以太网地址: \n");
	macaddr = arp->DestMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, 
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));

	/* 获得目的以太网地址 */
	/*mac_string = arp->SourceMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	memcpy((void*)& sip, (void*)& arp->SourceIpAdd, sizeof(struct in_addr));
	printf("源IP地址:%s\n", inet_ntop( sip);
	printf("目的以太网地址: \n");
	mac_string = arp->DestMacAdd;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	memcpy((void*)& dip, (void*)& arp->DestIpAdd, sizeof(struct in_addr));
	printf("目的IP地址:%s\n", inet_ntoa(dip));*/

	return;
}

void WebData::an_icmp(int iplen)
{
	struct icmp_header* icmp;
	/* ICMP协议变量 */
	icmp = (struct icmp_header*)((u_char *)pkt_data + 14 + iplen);
	/* 获得ICMP协议内容 */
	printf("----------  ICMP协议    ----------\n");
	printf("ICMP类型:%d\n", icmp->icmp_type);
	/* 获得ICMP类型 */
	switch (icmp->icmp_type)
	{
	case 8:
		printf("ICMP回显请求协议\n");
		printf("ICMP代码:%d\n", icmp->icmp_code);
		printf("标识符:%d\n", icmp->icmp_id);
		printf("序列码:%d\n", icmp->icmp_sequence);
		break;
	case 0:
		printf("ICMP回显应答协议\n");
		printf("ICMP代码:%d\n", icmp->icmp_code);
		printf("标识符:%d\n", icmp->icmp_id);
		printf("序列码:%d\n", icmp->icmp_sequence);
		break;
	default:
		break;
	}
	printf("ICMP校验和:%d\n", ntohs(icmp->icmp_checksum));
	/* 获得ICMP校验和 */
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
	
	printf("----------- IP协议    -----------\n");
	printf("版本号:%d\n",version);
	printf("首部长度:%d\n", header_lenth);
	printf("服务质量:%d\n", tos);
	printf("总长度:%d\n", ntohs(ip->tlen));
	printf("标识:%d\n", ntohs(ip->identification));
	printf("偏移:%d\n", offset);
	printf("生存时间:%d\n", ip->ttl);
	printf("协议类型:%d\n", ip->protocol);
	printf("校验和:%d\n", checksum);
	printf("源IP地址:%d.%d.%d.%d\n", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);

	printf("目的IP地址:%d.%d.%d.%d\n",ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
	switch (ip->protocol)
	{
	case 6:
		printf("上层协议为TCP协议\n");
		this->an_tcp(header_lenth);
		break;
	case 17:
		printf("上层协议为UDP协议\n");
		this->an_udp(header_lenth);
		break;
	case 1:
		printf("上层协议为ICMP协议ICMP\n");
		this->an_icmp(header_lenth);
		break;
	default:
		break;
	}
	return;

}

void WebData::an_tcp(int iplen)
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
	printf("-------  TCP协议   -------\n");
	printf("源端口号:%d\n", source_port);
	printf("目的端口号:%d\n", destination_port);
	switch (destination_port)
	{
	case 80:
		printf("上层协议为HTTP协议\n");
		break;
	case 21:
		printf("上层协议为FTP协议\n");
		break;
	case 23:
		printf("上层协议为TELNET协议\n");
		break;
	case 25:
		printf("上层协议为SMTP协议\n");
		break;
	case 110:
		printf("上层协议POP3协议\n");
		break;
	default:
		break;
	}
	printf("序列码:%u\n", sequence);
	printf("确认号:%u\n", acknowledgement);
	printf("首部长度:%d\n", header_length);
	printf("保留:%d\n", tcp->tcp_reserved);
	printf("标记:");
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
	printf("窗口大小:%d\n", windows);
	printf("校验和:%d\n", checksum);
	printf("紧急指针:%d\n", urgent_pointer);


}

void WebData::an_ethernet()
{
	u_short ethernet_type;
	ether_header *ethernet;
	u_char *macaddr;
	ethernet = (ether_header *)pkt_data;
	static int ethernet_number = 1;
	ethernet_type = ntohs(ethernet->ether_type);
	printf("以太网类型:");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type) /* 根据以太网类型判断 */
	{
		case 0x0800:
			printf("上层协议为IP协议\n");
			break;
		case 0x0806:
			printf("上层协议为ARP协议\n");
			break;
		case 0x8035:
			printf("上层协议为RARP协议\n");
			break;
		default:
			break;
	}
	printf("源以太网地址: \n");
	macaddr = ethernet->smac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, *(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	/* 获得源以太网地址 */
	printf("目的以太网地址: \n");
	macaddr = ethernet->dmac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *macaddr, *(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));

	/* 获得目的以太网地址 */
	switch (ethernet_type)
	{
	case 0x0806:
		this->an_arp();
		break;
		/* 上层协议为ARP协议，调用分析ARP协议的函数，注意参数的传递 */
	case 0x0800:
		this->an_ip();
		break;
		/* 上层协议为IP协议，调用分析IP协议的函数，注意参数的传递 */
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
    /* 获取本机设备列表 */
	if(this->getAllDevs() == NULL){
		fprintf(stderr,"获取设备错误: %s\n", errbuf);
        exit(1);
	}
	if(( i = this->getDevsNum()) < 1)
	{
		printf("无设备\n");
		return -1;
	}
    printf("请选择设备进行发送 (1-%d):",i);
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\n设备序号超出范围.\n");
		this->freeAllDevs();
        return -1;
    }
    
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65535,            // 要捕捉的数据包的部分 
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        fprintf(stderr,"\n无法打开适配器. %s is not supported by WinPcap\n", d->name);
		this->freeAllDevs();
        return -1;
    }
	cout << "y" << endl;
    /* 发送数据包 */
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

