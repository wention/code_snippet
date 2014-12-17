//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Modified by wention
//Dated : 20/11/2014
 
//Header Files
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid
#include<errno.h>
#include <getopt.h>  // getopt
#include <idna.h> // idna_to_ascii_8z
#include <pthread.h>

#define CRT_DNS_SRV  2

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
FILE *pFile=NULL;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
//Types of DNS resource records :)
 
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define MAX_THREADS  50
//Function Prototypes
int  ngethostbyname (unsigned char* ,int,char *,int,int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();
 
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

unsigned char hostname[100];

int getjob(char * job)
{
    char *p, *rc;
    if (!pFile)
        return -1;
    if ((rc = fgets (job , 210 , pFile)) <= 0)
        return -1;
    if ((p = strchr(job,'\n')))
        *p = '\0';
    return 0;
}

void * workitem(void *args)
{
    for(;;)
    {
        if(pthread_mutex_lock(&mutex)==0)
        {
            char job[220]={0}, record[256]={0};
            if (getjob(job) < 0) {
                pthread_mutex_unlock(&mutex);
                pthread_exit(0);
            }
            if (pthread_mutex_unlock(&mutex) == 0)
            if (ngethostbyname(job, T_A, record, 256, CRT_DNS_SRV) == 0 ) {
                printf("%s\n", record);
            } 
            
        }
    }
}

int main( int argc , char *argv[])
{
    int opt, i;
    pthread_t ptid[MAX_THREADS];
    pthread_mutex_init(&mutex,NULL);
    //Get the DNS servers from the resolv.conf file
    get_dns_servers();
     

    while ( (opt = getopt(argc, argv, "f:")) != -1)
    {
        switch (opt)
        {
            case 'f':
                pFile = fopen ( optarg, "r");
                
                for (i=0;i<MAX_THREADS;i++)
                    pthread_create( &(ptid[i]), NULL, &workitem, NULL);
                for (i=0;i<MAX_THREADS;i++)
                    pthread_join( ptid[i],NULL);
                fclose (pFile);
            break;
            default:

            break;
        }
    }
    
            if (argc == 2)
            {
                char record[256]={0};
                    if (ngethostbyname(argv[1], T_A, record, 256, CRT_DNS_SRV) == 0 ) {
                        printf("%s\n", record);
                    }
            }
/*
    char record[1024];
    ngethostbyname(argv[1], T_A, record, 1024);
    printf("%s\n",record);
*/
    return 0;
}
 
/*
 * Perform a DNS query by sending a packet
 * */
int  ngethostbyname(unsigned char *host , int query_type, char *record,int recdlen, int crt_dns_srv)
{
    unsigned char buf[65536],*qname,*reader,*idna_host,  hostname[100],host_tmp[220];
    int i , rc, j , stop , s , is_cn, sock_timeout=30000;
 
    struct sockaddr_in a;
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;


    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    //for output layout
    memset(record, 0, recdlen);   // make sure that for good layout
    memset(hostname, 0 , 100);
    memset(hostname, ' ', 26);
    memcpy(hostname, host, strlen(host));

    snprintf(record, recdlen, "%s ", hostname);
    
    // for ....recures
    strcpy ( host_tmp, host);

    // idna 
    for (i = 0;i<strlen(host);i++)
    {
        if ( host[i] > 128)
        {
            is_cn++;
            break;
        }
    }
    if (is_cn)
    {
        rc = idna_to_ascii_8z(host,(char **)&idna_host,0);
        strcpy (host , idna_host);
    }
    //printf("Resolving %s" , host);

    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
    if (!s)
    {
        perror("socket");

    }

    if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        //error("setsockopt failed\n");

    if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        //error("setsockopt failed\n");
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[crt_dns_srv]); //dns servers
 
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname, host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
 
    //printf("\nSending Packet...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    //printf("Done");
     
    //Receive the answer
    i = sizeof dest;
    //printf("\nReceiving answer...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {

        if ( errno == EAGAIN) {
        perror("recvfrom failed");
        // close the current socket file descriptor
        close(s);

        // 轮回切换dns server 以防出现死循环
        if (crt_dns_srv >0)
            crt_dns_srv--;
        else
            crt_dns_srv=2;
            
        if (ngethostbyname( host_tmp, T_A, record, recdlen, crt_dns_srv)==0)
            return 0;
        } else {
            perror("recvfrom failed");
        }

    }
    //printf("Done");
 
    dns = (struct DNS_HEADER*) buf;
 
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    //printf("\nThe response contains : ");
    //printf("\n %d Questions.",ntohs(dns->q_count));
    //printf("\n %d Answers.",ntohs(dns->ans_count));
    //printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    //printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
 
    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
 /*
    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
 */
    //print answers
    //printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    //

    if (dns->ans_count < 1)
      {
         snprintf(record+strlen(record), recdlen, " null");
        // try another dns server
        if (crt_dns_srv > 0) {
            crt_dns_srv--;

            //close current socket file descriptor
            close(s);
            if (ngethostbyname( host_tmp, T_A, record, recdlen, crt_dns_srv)==0)
                return 0;

        }
      }
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        //printf("%s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            snprintf(record+strlen(record), recdlen, " %s ",inet_ntoa(a.sin_addr));

        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            snprintf(record+strlen(record), recdlen, " %s ", answers[i].rdata);
        }
 
        //printf("\n");
    }
        //printf("%s\n", record);
 /*
    //print authorities
    printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
         
        printf("Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            printf("has nameserver : %s",auth[i].rdata);
        }
        printf("\n");
    }
 
    //print additional resource records
    printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        printf("Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }

*/  
    close(s);
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        if (answers[i].name)
            free(answers[i].name);
        if (answers[i].rdata)
            free(answers[i].rdata);
    }
    if (is_cn)
    free (idna_host);
    return 0;
}
 
/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
 
/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers()
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Failed opening /etc/resolv.conf file \n");
    }
     
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
             
            //p now is the dns ip :)
            //????
        }
    }
    

    strcpy(dns_servers[0] , "199.7.83.42");
    strcpy(dns_servers[1] , "8.8.8.8");
    strcpy(dns_servers[2] , "114.114.114.114");
    //strcpy(dns_servers[2] , "127.0.1.1");

}
 
/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}
