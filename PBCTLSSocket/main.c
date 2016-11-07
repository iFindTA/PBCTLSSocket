//
//  main.c
//  PBCTLSSocket
//
//  Created by nanhu on 16/11/5.
//  Copyright © 2016年 nanhu. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;
    
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information！\n");
}

#define HOST "182.92.194.20"
#define PAGE "/"
#define PORT 443
#define USERAGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.114 Safari/537.36"
#define ACCEPTLANGUAGE "zh-CN,zh;q=0.8,en;q=0.6,en-US;q=0.4,en-GB;q=0.2"
#define ACCEPTENCODING "gzip,deflate,sdch"

char *build_get_query(char *host,char *page){
    char *query;
    char *getpage=page;
    char *tpl="GET %s HTTP/1.1\r\nHost:%s\r\nAccept: */*\r\nUser-Agent:%s\r\nAccept-Language:%s\r\n\r\n";//Accept-Encoding:%s\r\n
    query=(char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)+strlen(ACCEPTLANGUAGE)-5);//+strlen(ACCEPTENCODING)
    sprintf(query,tpl,getpage,host,USERAGENT,ACCEPTLANGUAGE);//ACCEPTENCODING
    return query;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) < 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
#define MAX_BUF_LEN             2048
#define MAX_DOMAIN_LEN          80
#define MAX_ORGANIZATION_ID_LEN 128
#define MAX_MEMBER_ID_LEN       128
#define MAX_TOKEN_LEN           256
#define MAX_STATUS_LINE_LEN     64
#define MAX_HEADER_LEN          128
#define CURRENT_SDK_VERSION     "1.0.0"
#define CURRENT_API_VERSION     "1"
typedef struct {
    char            domain[MAX_DOMAIN_LEN + 1];
    char            org_id[MAX_ORGANIZATION_ID_LEN + 1];
    char            mem_id[MAX_MEMBER_ID_LEN + 1];
    char            token[MAX_TOKEN_LEN + 1];
} cde_identity;

static cde_identity *cde_id = NULL;

int read_line(SSL *ssl, char *header, int max_header_len) {
    int index = 0;
    memset(header, '\0', max_header_len + 1);
    index = 0;
    int got;
    char ch, tail = '\0';
    while (1) {
        got = SSL_read(ssl, &ch, 1);
        if (got <= 0) {
            printf("read header failed.\n");
            return 1;
        }
        
        if (tail == '\r' && ch == '\n') {
            header[index - 1] = '\0';
            break;
        }
        
        if (ch == '\r') {
            tail = ch;
        } else {
            tail = '\0';
        }
        
        header[index++] = ch;
        if (index >= max_header_len) {
            printf("header too long: %s.", header);
            return 2;
        }
    }
    
    return 0;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    int i,j,sockfd, len, fd, size;
    char fileName[50],sendFN[20];
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;
    
    if (argc != 3)
    {
        printf("Parameter format error! Correct usage is as follows：\n\t\t%s IP Port\n\tSuch as:\t%s 127.0.0.1 80\n", argv[0], argv[0]); exit(0);
    }
    
    /* SSL 库初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    
    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");
    
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n\n");
    
    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    
    
    //get method example
    char msg[1024];
    cde_id = malloc(sizeof(cde_identity));
    const char * domain = "sdk.flkjiami.com";
    const char * org_id = "123456";
    const char * mem_id = "123456";
    const char * token = "123456";
    memcpy(cde_id->domain, domain, strlen(domain) + 1);
    memcpy(cde_id->org_id, org_id, strlen(org_id) + 1);
    memcpy(cde_id->mem_id, mem_id, strlen(mem_id) + 1);
    memcpy(cde_id->token, token, strlen(token) + 1);
    printf("locate here \n");
    long url_len = strlen(CURRENT_API_VERSION) + strlen(cde_id->org_id) + strlen(cde_id->mem_id) + strlen(cde_id->token) + strlen(CURRENT_SDK_VERSION) + strlen("//secrets?o=&m=&t=&v=") + 1;
    char * URL = malloc(sizeof(char) * (url_len + 1));
    sprintf(URL, "/%s/secrets?o=%s&m=%s&t=%s&v=%s", CURRENT_API_VERSION, cde_id->org_id, cde_id->mem_id, cde_id->token, CURRENT_SDK_VERSION);
    URL[url_len] = '\0';
    printf("request url: %s \n", URL);
    memset(msg, '\0', 1024);
    //compose http request line
    sprintf(msg, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", URL, HOST);
    int sendSz = (int)strlen(msg);
    if (SSL_write(ssl, msg, sendSz) != sendSz) {
        printf("send request failed.\n");
        
    }
    /*
    while(sent<strlen(get)){
        //tmpres=send(sock,get+sent,strlen(get)-sent,0);
        tmpres = SSL_write(ssl, buf, sizeof(buf)-1);
        if(tmpres==-1){
            perror("Can't send query!");
            exit(1);
        }
        sent+=tmpres;
    }
    //*/
    
    /*
    int status_code = 0;
    //read status line
    char status_line[MAX_STATUS_LINE_LEN + 1];
    int ret = read_line(ssl, status_line, MAX_STATUS_LINE_LEN);
    if (ret != 0) {
        printf("reader status line failed: %d.\n", ret);
    }
    printf("got response: %s.\n", status_line);
    //*/
    char buf[1024];
    memset(buf,0,sizeof(buf));
    SSL_read(ssl, buf, sizeof(buf));
    printf("Message form server: %s\n", buf);
    
    
    /*
    while((tmpres=recv(sock,buf,BUFSIZ,0))>0){
        
        printf(buf);
        
        if(htmlstart==0){
            htmlcontent=strstr(buf,"\r\n\r\n");
            if(htmlcontent!=NULL){
                htmlstart=1;
                htmlcontent+=4;
            }
        }else{
            htmlcontent=buf;
        }
        if(htmlstart){
            fprintf(stdout,htmlcontent);
        }
        memset(buf,0,tmpres);
        
        fprintf(stdout,"\n\n\ntmpres Value:%d\n",tmpres);
    }
         //*/
    fprintf(stdout,"receive data over!\n");
    
    
    
    /* 关闭连接 */  
    close(fd);  
    SSL_shutdown(ssl);  
    SSL_free(ssl);  
    close(sockfd);  
    SSL_CTX_free(ctx);  
    return 0;
}
