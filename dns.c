#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h>

#define SERVER "127.0.1.1"
#define PORT 53
#define ANSWER 1048576
#define TYPE_A 1
#define TYPE_SOA 6
#define TYPE_MX 15
#define TYPE_AAAA 28


//Converts google.com to 6google3com
void hostConvert(unsigned char **host, unsigned char *aux)
{
  int i, j, size;
  unsigned char *label = NULL;

  size = strlen(aux);
  for(i=0, j=0; i<size; i++,j++){

    if(j%10==0){
      if(j==0)
        label = malloc(sizeof(char)*(10+1));
      else{
        label = realloc(label,sizeof(char)*(10+1)+strlen(label));
      }
    }

    if(aux[i] == '.'){
      if((*host) == NULL)
        (*host) = malloc(sizeof(char)*(strlen(label)+2+1));
      else
        (*host) = realloc((*host),sizeof(char)*(strlen((*host))+strlen(label)+2+1));
      strcat((*host),(unsigned char *) &j);
      strcat((*host),label);
      free(label);
      label = NULL;
      j=-1;
    }
    else{
      label[j] = aux[i];
      label[j+1] = '\0';
    }
  }

  (*host) = realloc((*host),sizeof(char)*(strlen((*host))+1));
  strcat((*host),(unsigned char *) &j);

}

//Reads the input
void readInput(int argc, char **argv, unsigned char **host, unsigned char **hostDNS, unsigned char **server)
{
  unsigned char *aux = NULL;

  if(argc < 2){
    printf("ERRO - ./dns <host> <server>(opt)\n");
    exit(1);
  }

  if(argv[1][strlen(argv[1])-1]=='.'){
    aux = malloc(sizeof(char)*(strlen(argv[1])+1));
    strncpy(aux,argv[1],strlen(argv[1]));
  }
  else{
    aux = malloc(sizeof(char)*(strlen(argv[1])+2));
    strcpy(aux,argv[1]);
    strcat(aux,".");
  }
  (*host) = malloc(strlen(aux)+1);
  strncpy(*host,aux,strlen(aux)-1);
  hostConvert(hostDNS,aux);
  free(aux);

  if(argc == 3){
    (*server) = malloc(sizeof(char)*(strlen(argv[2])+1));
    strcpy((*server),argv[2]);
  }
  else{
    (*server) = malloc(sizeof(char)*(strlen(SERVER)+1));
    strcpy((*server),SERVER);
  }

}

//Sets flags for the requisition
void setFlags(unsigned short *flags, int response, int opcode, int authoritativeAnswer, int truncation, int recursionDesired,
              int recursionAvailable, int reserved, int answerAuthenticated, int nonAuthenticatedData, int returnCode)
{
  (*flags) = recursionAvailable;
  (*flags) = ((*flags) << 1) | reserved;
  (*flags) = ((*flags) << 1) | answerAuthenticated;
  (*flags) = ((*flags) << 1) | nonAuthenticatedData;
  (*flags) = ((*flags) << 1) | returnCode;
  (*flags) = ((*flags) << 1) | response;
  (*flags) = ((*flags) << 4) | opcode;
  (*flags) = ((*flags) << 1) | authoritativeAnswer;
  (*flags) = ((*flags) << 1) | truncation;
  (*flags) = ((*flags) << 1) | recursionDesired;
}

//Reads flags of the answer
void readFlags(unsigned short flags, int *response, int *opcode, int *authoritativeAnswer, int *truncation, int *recursionDesired,
              int *recursionAvailable, int *reserved, int *answerAuthenticated, int *nonAuthenticatedData, int *returnCode)
{
  (*response) = (flags >> 15) & 0x1;
  (*opcode) = (flags >> 11) & 0x7;
  (*authoritativeAnswer) = (flags >> 10) & 0x1;
  (*truncation) = (flags >> 9) & 0x1;
  (*recursionDesired) = (flags >> 8) & 0x1;
  (*recursionAvailable) = (flags >> 7) & 0x1;
  (*reserved) = (flags >> 6) & 0x1;
  (*answerAuthenticated) = (flags >> 5) & 0x1;
  (*nonAuthenticatedData) = (flags >> 4) & 0x1;
  (*returnCode) = flags & 0xF;
}

//Reads the domain of the answer
unsigned char* readName(unsigned char *reader, int *size, unsigned char *message)
{
    unsigned char *aux = NULL;
    unsigned char *name = NULL;
    unsigned short num, compressed = 0;
    int i;

    num = (unsigned short) *reader;

    while(num!=0){
        while(num >= 192){
          if(!compressed)
            (*size)++;
          compressed = (unsigned short) ((((*reader) << 8) + (*(reader+1))) & (~0xC000));
          reader = message+compressed;
          num = (unsigned short) *(message+compressed);
        }
        reader+=1;
        for(i=1;i<=num;i++){
            if((i-1)%10 == 0){
              if(i==1)
                aux = malloc(sizeof(unsigned char)*(10+1));
              else
                aux = realloc(aux,sizeof(unsigned char)*(10+1)+strlen(aux));
            }
            aux[i-1]=*reader;
            aux[i]='\0';
            reader+=1;
        }
        if(name == NULL){
          name = malloc(strlen(aux)+strlen(".")+1);
          name[0] = '\0';
        }
        else{
          name = realloc(name,strlen(name)+strlen(aux)+strlen(".")+1);
        }
        strcat(name,aux);
        strcat(name,".");
        strcat(name,"\0");
        free(aux);
        if(!compressed)
          (*size)+=num+1;
        num = (unsigned short) *reader;
    }
    name[strlen(name)-1]='\0';
    (*size)++;
    return name;
}

//Reads the data received by the type A and AAAA
unsigned char* readData(unsigned char *data, unsigned int size)
{
  unsigned char *copy = NULL;
  int i;

  copy = malloc(sizeof(unsigned char)*size+1);
  for(i=0;i<size;i++){
    copy[i] = *(data+i);
  }
  copy[strlen(copy)] = '\0';
  return copy;
}

//Prints the error of requisition
void dnsError(int error)
{
  if(error == 1)
    printf("ERROR: FORMERR\n");
  else if(error == 2)
    printf("ERROR: SERVFAIL\n");
  else if(error == 3)
    printf("ERROR: NXDOMAIN\n");
  else if(error == 4)
    printf("ERROR: NOTIMP\n");
  else if(error == 5)
    printf("ERROR: RECUSADA\n");
  else if(error == 6)
    printf("ERROR: YXDOMAIN\n");
  else if(error == 7)
    printf("ERROR: YXRRSET\n");
  else if(error == 8)
    printf("ERROR: NXRRSET\n");
  else if(error == 9)
    printf("ERROR: NOTAUTH\n");
  else if(error == 10)
    printf("ERROR: NOTZONE\n");
  else 
    printf("ERROR\n");
}

//Creates socket, sends the requisition and receive and read the answer
void dns(unsigned char *host, int type, unsigned char *server)
{
  int i, destinySize;
  int sock;
  struct sockaddr_in destiny;
  unsigned char message[sizeof(unsigned short)*8+strlen(host)+2];
  unsigned char answer[ANSWER];
  unsigned char *questionName = NULL, *name = NULL, *namePrimaryNameServer = NULL, *nameResponsabileAuthorotysMailbox = NULL;
  unsigned char *nameMailExchange = NULL, *data = NULL, *nameAuthoritative = NULL, *nameAnswer = NULL;
  unsigned short *id = NULL;
  unsigned short flags;
  unsigned short *flagsp = NULL;
  unsigned short *questionCount = NULL;
  unsigned short *answerCount = NULL;
  unsigned short *authorityCount = NULL;
  unsigned short *additionalCount = NULL;
  unsigned short *questionType = NULL;
  unsigned short *questionClass = NULL;
  unsigned char* answerName = NULL;
  unsigned short* answerType = NULL;
  unsigned short* answerClass = NULL;
  unsigned int * answerTTL = NULL;
  unsigned short* answerDataLength = NULL;
  unsigned short* answerPreference = NULL;
  unsigned char* answerMailExchange = NULL;
  unsigned char* answerData = NULL;
  unsigned char* authoritativeName = NULL;
  unsigned short* authoritativeType = NULL;
  unsigned short* authoritativeClass = NULL;
  unsigned int * authoritativeTTL = NULL;
  unsigned short* authoritativeDataLength = NULL;
  unsigned char* authoritativePrimaryNameServer = NULL;
  unsigned char* authoritativeResponsibleAuthorotysMailbox = NULL;
  unsigned int* authoritativeSerialNumber = NULL;
  unsigned int* authoritativeRefreshInterval = NULL;
  unsigned int* authoritativeRetryInterval = NULL;
  unsigned int* authoritativeExpireLimit = NULL;
  unsigned int* authoritativeMinimumTTL = NULL;
  int answers, dataLength, nameSize, authorities, size;
  int flagResponse, flagOpcode, flagAuthoritativeAnswer, flagTrucation, flagRecursionDesired, flagRecusionAvailable;
  int flagReserved, flagAnswerAuthenticated, flagNonAuthenticatedData, flagReturnCode;
  long *p;
  char ipv6[INET6_ADDRSTRLEN];
  struct timeval tv;
  
  if(type == TYPE_A)
    printf("A\t");
  else if(type == TYPE_AAAA)
    printf("AAAA\t");
  else if(type == TYPE_MX)
    printf("MX\t");

  destiny.sin_family = AF_INET;
  destiny.sin_port = htons(PORT);
  if(!inet_aton(server,&(destiny.sin_addr))){
    printf("INVALID SERVER %s\n", server);
    exit(1);
  }
  memset(destiny.sin_zero,0x00,8);
  destinySize = sizeof(destiny);

  sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if(sock == -1){
    perror("ERROR socket ");
    return;
  }
  tv.tv_sec = 5;
  tv.tv_usec= 0;
  setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(struct timeval*)&tv,sizeof(struct timeval));
  
  memset(message,0,sizeof(message));
  id = (unsigned short *) &message;
  *id = (unsigned short) htons(getpid());
  flagResponse = 0;
  flagOpcode = 0;
  flagAuthoritativeAnswer = 0;
  flagTrucation = 0;
  flagRecursionDesired = 1;
  flagRecusionAvailable = 0;
  flagReserved = 0;
  flagAnswerAuthenticated = 0;
  flagNonAuthenticatedData = 0;
  flagReturnCode = 0;
  setFlags(&flags,flagResponse,flagOpcode,flagAuthoritativeAnswer,flagTrucation,flagRecursionDesired,
            flagRecusionAvailable,flagReserved,flagAnswerAuthenticated,flagNonAuthenticatedData,flagReturnCode);
  flagsp = (unsigned short *) &message[sizeof(unsigned short)];
  *flagsp = (unsigned short) flags;
  questionCount = (unsigned short *) &message[sizeof(unsigned short)*2];
  *questionCount = htons(1);
  answerCount = (unsigned short *) &message[sizeof(unsigned short)*3];
  *answerCount = htons(0);
  authorityCount = (unsigned short *) &message[sizeof(unsigned short)*4];
  *authorityCount = htons(0);
  additionalCount = (unsigned short *) &message[sizeof(unsigned short)*5];
  *additionalCount = htons(0);
  questionName =(unsigned char*)&message[sizeof(unsigned short)*6];
  strcat(questionName,host);
  questionType =(unsigned short *)&message[sizeof(unsigned short)*6+strlen(host)+1];
  *questionType = htons(type);
  questionClass =(unsigned short *)&message[sizeof(unsigned short)*7+strlen(host)+1];
  *questionClass = htons(1);

  if(sendto(sock,(char*)message,sizeof(message),0,(struct sockaddr*)&destiny,destinySize) < 0)
  {
    perror("ERROR sendto ");
  }

  if((recvfrom(sock,(char*)(answer) ,sizeof((answer)),0,(struct sockaddr*)&destiny,(socklen_t*)&destinySize) < 0))
  {
    perror("ERROR DNS");
    return;
  }

  dataLength = 0;
  nameSize = 0;
  id = (unsigned short*) (answer);
  flagsp = (unsigned short*) &(answer)[sizeof(unsigned short)*1];
  readFlags(ntohs(*flagsp),&flagResponse,&flagOpcode,&flagAuthoritativeAnswer,&flagTrucation,&flagRecursionDesired,
                          &flagRecusionAvailable,&flagReserved,&flagAnswerAuthenticated,&flagNonAuthenticatedData,&flagReturnCode);

  if(flagReturnCode != 0){
    dnsError(flagReturnCode);
    return;
  }
  questionCount = (unsigned short*) &(answer)[sizeof(unsigned short)*2];
  answerCount = (unsigned short*) &(answer)[sizeof(unsigned short)*3];
  authorityCount = (unsigned short*) &(answer)[sizeof(unsigned short)*4];
  additionalCount = (unsigned short*) &(answer)[sizeof(unsigned short)*5];
  questionName = &(answer)[sizeof(unsigned short)*6];
  name = NULL;
  name = readName(questionName,&nameSize,answer);
  questionType = (unsigned short*) &(answer)[sizeof(unsigned short)*6+nameSize];
  questionClass = (unsigned short*) &(answer)[sizeof(unsigned short)*7+nameSize];
  dataLength = sizeof(unsigned short)*8+nameSize;
  if((ntohs(*answerCount) == 0) && (ntohs(*authorityCount) == 0)){
    printf("ERROR: NON-ANSWERS\n\n");
  }
  for(answers=0; answers<ntohs(*answerCount); answers++){
    size = 0;
    answerName = &(answer)[dataLength];
    nameAnswer = NULL;
    nameAnswer = readName(answerName,&size,answer);
    dataLength += size;
    size = 0;
    answerType = (unsigned short*) &(answer)[dataLength];
    answerClass = (unsigned short*) &(answer)[sizeof(unsigned short)*1+dataLength];
    answerTTL = (unsigned int*) &(answer)[sizeof(unsigned short)*2+dataLength];
    answerDataLength = (unsigned short*) &(answer)[sizeof(unsigned short)*2+sizeof(unsigned int)+dataLength];

    if(type == TYPE_MX){
      answerPreference = (unsigned short*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)+dataLength];
      answerMailExchange = &(answer)[sizeof(unsigned short)*4+sizeof(unsigned int)+dataLength];
      nameMailExchange = NULL;
      nameMailExchange = readName(answerMailExchange,&size,answer);
    }
    else{
      answerData = &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)+dataLength];
      data = NULL;
      data = readData(answerData,ntohs(*answerDataLength));
    }
    dataLength+=sizeof(unsigned short)*3+sizeof(unsigned int)+ntohs(*answerDataLength);

    if(answers)
      printf("\t");
    if(answerType!=NULL && ntohs(*answerType) == TYPE_A){
      p=(long*)data;
      destiny.sin_addr.s_addr=(*p);
      printf("%s\n",inet_ntoa(destiny.sin_addr));
    }
    else if(answerType!=NULL && ntohs(*answerType) == TYPE_AAAA){
      p=(long*)data;
      destiny.sin_addr.s_addr=(*p);
      const char* result = inet_ntop(AF_INET6, p,ipv6, sizeof(ipv6));
      printf("%s\n", result);
    }
    else if(answerType!=NULL && ntohs(*answerType) == TYPE_MX){
      printf("%u %s\n", ntohs(*answerPreference),nameMailExchange);
    }
    else{
      printf("ERROR: UNTREATED TYPE\n");
    }
    free(nameAnswer);
    free(nameMailExchange);
    free(data);
  }
  for(authorities=0; authorities<ntohs(*authorityCount); authorities++){
    size = 0;
    authoritativeName = &(answer)[dataLength];
    nameAuthoritative = NULL;
    nameAuthoritative = readName(authoritativeName,&size,answer);
    dataLength += size;
    size = 0;
    authoritativeType = (unsigned short*) &(answer)[dataLength];
    authoritativeClass = (unsigned short*) &(answer)[sizeof(unsigned short)*1+dataLength];
    authoritativeTTL = (unsigned int*) &(answer)[sizeof(unsigned short)*2+dataLength];
    authoritativeDataLength = (unsigned short*) &(answer)[sizeof(unsigned short)*2+sizeof(unsigned int)+dataLength];
    authoritativePrimaryNameServer =  &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)+dataLength];
    namePrimaryNameServer = NULL;
    namePrimaryNameServer = readName(authoritativePrimaryNameServer,&size,answer);
    authoritativeResponsibleAuthorotysMailbox =  &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)+dataLength+size];
    nameResponsabileAuthorotysMailbox = NULL;
    nameResponsabileAuthorotysMailbox = readName(authoritativeResponsibleAuthorotysMailbox,&size,answer);
    authoritativeSerialNumber = (unsigned int*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)+dataLength+size];
    authoritativeRefreshInterval = (unsigned int*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)*2+dataLength+size];
    authoritativeRetryInterval = (unsigned int*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)*3+dataLength+size];
    authoritativeExpireLimit = (unsigned int*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)*4+dataLength+size];
    authoritativeMinimumTTL = (unsigned int*) &(answer)[sizeof(unsigned short)*3+sizeof(unsigned int)*5+dataLength+size];

    dataLength+=sizeof(unsigned short)*3+sizeof(unsigned int)+ntohs(*authoritativeDataLength);
    
    if(authorities)
      printf("\t");
    if(ntohs(*authoritativeType) == TYPE_SOA){
      if(type == TYPE_A){
        printf("<none>   \tAUTHORITATIVE RESPONSE: %s %s %u %u %u %u %u\n", namePrimaryNameServer, nameResponsabileAuthorotysMailbox,
                      ntohl(*authoritativeSerialNumber), ntohl(*authoritativeRefreshInterval), ntohl(*authoritativeRetryInterval),
                      htonl(*authoritativeExpireLimit), htonl(*authoritativeMinimumTTL));
      }
      else if(type == TYPE_AAAA){
        printf("<none>   \tAUTHORITATIVE RESPONSE: %s %s %u %u %u %u %u\n", namePrimaryNameServer, nameResponsabileAuthorotysMailbox,
                      ntohl(*authoritativeSerialNumber), ntohl(*authoritativeRefreshInterval), ntohl(*authoritativeRetryInterval),
                      htonl(*authoritativeExpireLimit), htonl(*authoritativeMinimumTTL));
      }
      else if(type == TYPE_MX){
        printf("<none>   \tAUTHORITATIVE RESPONSE: %s %s %u %u %u %u %u\n", namePrimaryNameServer, nameResponsabileAuthorotysMailbox,
                      ntohl(*authoritativeSerialNumber), ntohl(*authoritativeRefreshInterval), ntohl(*authoritativeRetryInterval),
                      htonl(*authoritativeExpireLimit), htonl(*authoritativeMinimumTTL));
      }
      else{
        printf("<none>   \tAUTHORITATIVE RESPONSE: ERROR: UNTREATED TYPE\n");
      }
    }
    else{
      printf("<none>   \tERROR: UNTREATED AUTHORITATIVE RESPONSE TYPE\n");
    }
    free(nameAuthoritative);
    free(namePrimaryNameServer);
    free(nameResponsabileAuthorotysMailbox);
  }

  free(name);
  close(sock);
}

int main(int argc, char **argv)
{
  unsigned char *host = NULL, *hostDNS = NULL, *server = NULL; 

  readInput(argc,argv,&host,&hostDNS,&server);

  printf("%s:\n", host);
  dns(hostDNS,TYPE_A,server);
  dns(hostDNS,TYPE_AAAA,server);
  dns(hostDNS,TYPE_MX,server);

  free(host);
  free(hostDNS);
  free(server);

  return 0;
}