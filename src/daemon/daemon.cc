///////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2000-2018 Ericsson Telecom AB
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v2.0
// which accompanies this distribution, and is available at
// https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
///////////////////////////////////////////////////////////////////////////////
//
//  Rev:                <RnXnn>
//  Prodnr:             CNL 113 827
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include "GTP_mem_handler.h"
#include "daemon.hh"


#define MAX_EVENTS_PER_THREAD 8

int lastIdx = 0;
char* tun_name=NULL;  // The interface name to use
int pipefd[2]; // The internal pipe
int address_set_mode=2;
bool threads_started=false;

// controll conection listen fd
int daemon_fd=-1;

// GTP Tunnel addresses
struct sockaddr_storage default_rem_addr;

// GTP Tunnel fds
int tun_fd=-1;  // TUN device

// read or write lock of the ip teid maps;
pthread_rwlock_t   ip_teid_lock;

// ip teid maps

// TEID -> IP database index
//str_int_map teid_idx_map;

// IP -> IP database index
str_int_map ip_idx_map;

// The IP database
ip_entry_t*  ip_teid_db=NULL;
int ip_teid_db_size=0;
int ip_teid_db_entries=0;

// map that holds the incoming teid - index map
str_int_map teidin_idx_map;

// read or write lock of it;
pthread_rwlock_t   teid_idx_lock;

// database of the pending IP prefix request
int ip_req_db_size=0;
int volatile ip_req_num=0;

ip_req_db_t* ip_req_db=0;

// thread identyfiers
int tun_handler_num=0;
pthread_t tun_handler;

// local udp endpoint/port database
int local_ep_length=0;
int local_ep_num=0;
local_ep_db_t *local_ep_db=NULL;

// IP:port -> endpoint db idx map
str_int_map ep_idx_map;
// read or write lock of it;
pthread_rwlock_t   ep_idx_lock;


// epoll fd
int epfd=-1;

// 1 thread is started after that many local gtp endpoint
int gtp_per_thread=3;

void print_usage(){

  printf("usage: GTP_daemon [--help| --interface_name <ifname> ]\r\n");
  printf("\r\n");
  printf("  --help: print this help\r\n");
  printf("  --interface_name <ifname>: use the given ifname for the TUN interface name\r\n");
  printf("                             if not specified the automatically selected name will be used\r\n");
  printf("                             the same name should be specified for the controlling test port\r\n");
  printf("\r\n");

}

#ifdef DEBUG
void log(const char *fmt, ...)
{
  time_t c_time = time(NULL);
  if (c_time != ((time_t)-1))
  {
    struct tm *c_time_struct = localtime(&c_time);
    if (c_time_struct != NULL)
    {
      char c_time_str[256];
      strftime(c_time_str, 256, "%T", c_time_struct);
      printf("%s: ", c_time_str);
    }
  }

  va_list args;
  va_start(args, fmt);
  vprintf(fmt,args);
  va_end(args);
  printf("\r\n");
}

void log_str_holder(const str_holder* data){
    time_t c_time = time(NULL);
    if (c_time != ((time_t)-1))
    {
      struct tm *c_time_struct = localtime(&c_time);
      if (c_time_struct != NULL) 
      {
        char c_time_str[256];
        strftime(c_time_str, 256, "%T", c_time_struct);
        printf("%s: ", c_time_str);
      }
    }
    printf("length: %d value:", data->str_size);
    for(int i=0;i<data->str_size;i++){
      printf("%02X", data->str_begin[i]);
    }
    printf("\r\n");
}    

#endif
//void close_local_ep(int idx, int force=0);
void close_local_ep(int idx, int force=0){
  log("Try to close local GTP endpoint...");
  if(idx==0 && force==0){
    log("Default one. Do not close.");
    return;
  }
  
  if(local_ep_db[idx].usage_num == 0  && local_ep_db[idx].fd!=-1){
    close(local_ep_db[idx].fd);
    local_ep_db[idx].fd=-1;
    local_ep_num--;
    ep_idx_map.erase(local_ep_db[idx].key);
    log("closed");
  } else {
    log("Can't be closed, in use.");
  }
}

void process_options(int argc, char **argv){
  if(argc==1) {
    return;  // no option specified
  } else if( argc == 2) {
    if(!strcasecmp("--interface_name",argv[1])){
      printf("Missing ifname.\r\n");
    } else if(strcasecmp("--help",argv[1])){
      printf("Unknown parameter\r\n");
    }
    print_usage();
    exit(1);
  } else if(argc == 3) {
    if(!strcasecmp("--interface_name",argv[1])){
      tun_name=strdup(argv[2]);
    } else {
      printf("Unknown parameter\r\n");
      print_usage();
      exit(1);
    }

  } else {
    printf("Unknown parameter\r\n");
    print_usage();
    exit(1);
  }
}

int fill_addr_struct(const char* local_ip, int local_port, struct sockaddr_storage *local_addr,const char* rem_ip, int rem_port, struct sockaddr_storage *rem_addr){
  struct addrinfo* addrinf;
  bzero(local_addr,sizeof(struct sockaddr_storage));
  bzero(rem_addr,sizeof(struct sockaddr_storage));

  if((getaddrinfo(local_ip, NULL, NULL, &addrinf))!=0){
    log("getaddrinfo(local_ip, NULL, NULL, &addrinf))!=0");
    return -1;
  }
  if(addrinf->ai_family==AF_INET){
    struct sockaddr_in* saddr=( struct sockaddr_in*)local_addr;
    struct sockaddr_in* locaddr=(struct sockaddr_in*)addrinf->ai_addr;

    saddr->sin_family=addrinf->ai_family;
    saddr->sin_port=htons((unsigned short)local_port);
    memcpy(&saddr->sin_addr,&locaddr->sin_addr,sizeof(struct in_addr));
  } else {
    struct sockaddr_in6* saddr=( struct sockaddr_in6*)local_addr;
    struct sockaddr_in6* locaddr=(struct sockaddr_in6*)addrinf->ai_addr;

    saddr->sin6_family=addrinf->ai_family;
    saddr->sin6_port=htons((unsigned short)local_port);
    memcpy(&saddr->sin6_addr,&locaddr->sin6_addr,sizeof(struct in6_addr));
  }

  if((getaddrinfo(rem_ip, NULL, NULL, &addrinf))!=0){
    log("getaddrinfo(rem_ip, NULL, NULL, &addrinf))!=0");
    return -1;
  }
  if(addrinf->ai_family==AF_INET){
    struct sockaddr_in* addr=( struct sockaddr_in*)rem_addr;
    struct sockaddr_in* remaddr=(struct sockaddr_in*)addrinf->ai_addr;

    addr->sin_family=addrinf->ai_family;
    addr->sin_port=htons((unsigned short)rem_port);
    memcpy(&addr->sin_addr,&remaddr->sin_addr,sizeof(struct in_addr));
  } else {
    struct sockaddr_in6* addr=( struct sockaddr_in6*)rem_addr;
    struct sockaddr_in6* remaddr=(struct sockaddr_in6*)addrinf->ai_addr;

    addr->sin6_family=addrinf->ai_family;
    addr->sin6_port=htons((unsigned short)rem_port);
    memcpy(&addr->sin6_addr,&remaddr->sin6_addr,sizeof(struct in6_addr));
  }

  freeaddrinfo(addrinf);

  if(rem_addr->ss_family!=local_addr->ss_family){
    log("fill_addr_struct rem_addr->ss_family!=local_addr->ss_family<0");
    return -1;
  }

  return 0;
}

int open_udp_port(struct sockaddr_storage *local_addr){
  int fd=socket(local_addr->ss_family, SOCK_DGRAM, 0);
  if (fd < 0) {
  log("open_udp port fd < 0");
    return -1;
  }
  int flags;

  flags = fcntl (fd, F_GETFL, 0);
  if (flags == -1) {
    perror ("fcntl");
    log("open_udp port flags = -1");
    close(fd);
    return -1;
  }

  flags |= O_NONBLOCK;
  if (fcntl (fd, F_SETFL, flags) < 0) {
    perror ("fcntl");
    close(fd);
    log("open_udp port fcntl<0");
    return -1;
  }

  if (bind(fd, (struct sockaddr *) local_addr, sizeof(struct sockaddr_storage)) < 0) {
    perror ("bind");
    close(fd);
    log("open_udp port bind<0");
    return -1;
  }
  log("open_udp return fd");
  return fd;
}

int process_msg(msg_buffer* buffer, int fd){

  inc_buff_size(buffer,4);

  int rd=read(fd, buffer->msg+buffer->pos, buffer->size - buffer->pos);

  if(rd<=0){
  log("Process msg rd < 0");
    return -1;
  }
  buffer->pos+=rd;
  int curr_pos=buffer->pos;

  while(curr_pos>=4){
    buffer->pos=0;
    int msg_len;
    if(get_int(buffer,&msg_len)<0) {
      log("Process msg get_int < 0");
      return -1;
    }  // read the msg length
    log("MSG len %d",msg_len);
    if(msg_len>curr_pos){  // we need more data
      log("Process msg_len>curr_pos");
      buffer->pos=curr_pos;
      inc_buff_size(buffer,msg_len-curr_pos); // reserve enough space in the buffer to receive data
      return 0;
    }
    if(msg_len<8) {
      log("Process msg msg_len < 0");
      return -1;
    } // No msg type????
    int msg_type;
    if(get_int(buffer,&msg_type)<0) {
      log("Process msg get_int2 < 0");
      return -1;
    } // read the msg type
    log("MSG type %d",msg_type);
    switch(msg_type){
      case GTP_CTRL_MSG_GET_TEID:{
        log("GTP_CTRL_MSG_GET_TEID received");
        str_holder local_addr;
        local_addr.str_size=-1;
        local_addr.str_begin=NULL;
        str_holder remote_addr;
        remote_addr.str_size=-1;
        remote_addr.str_begin=NULL;
        int local_port=-1;
        int remote_port=-1;
        int protocol_id=-1;

        while(msg_len>buffer->pos){
          int ie_type;
          get_int(buffer,&ie_type);
          switch(ie_type){
            case GTP_CTRL_IE_LOCAL_IP:  // oct
              get_str(buffer,&local_addr);
              log("GTP_CTRL_MSG_GET_TEID local_addr");
	      log_str_holder(&local_addr);
              break;

            case GTP_CTRL_IE_REMOTE_IP:  // oct
              get_str(buffer,&remote_addr);
              log("GTP_CTRL_MSG_GET_TEID remote_addr");
	      log_str_holder(&remote_addr);
              break;

            case GTP_CTRL_IE_LOCAL_PORT:  // int
              get_int(buffer,&local_port);
              log("GTP_CTRL_MSG_GET_TEID local_port %i", local_port);
              break;

            case GTP_CTRL_IE_REMOTE_PORT:  // int
              get_int(buffer,&remote_port);
              log("GTP_CTRL_MSG_GET_TEID remote_port %i", remote_port);
              break;

            case GTP_CTRL_IE_PROTO:  // int
              get_int(buffer,&protocol_id);
              log("protocol_id %i", protocol_id);
              break;

            default:
              break;
          }
        }

        str_int_map::const_iterator it;
        pthread_rwlock_rdlock(&ip_teid_lock);
        it=ip_idx_map.find(local_addr);
        int match_level=-1;
        int match_idx=-1;
        int idx=-1;
        if(it!=ip_idx_map.end()){
          idx=it->second;
          // find the matching teid

          for(int i=0;i<ip_teid_db[idx].teid_num;i++){
            const filter_t* ft=&ip_teid_db[idx].teid_list[i].filter;
            int match=0;
            if(ft->remote_ip.str_size!=-1){
              log("REMOTE IP:");
	      log_str_holder(&ft->remote_ip);
              if(str_eq(ft->remote_ip,remote_addr)==0){
                match++;
              } else {
                continue;
              }
            }
            log("PROTO: %i", ft->proto);
            log("PROTOCOL_ID: %i", protocol_id);
            if(ft->proto!=0){
              if(ft->proto==protocol_id){
                match++;
                // we need proto match to handle ports
                log("REMOTE_PORT: %i", ft->remote_port);
                if(ft->remote_port!=-1){
                  if(ft->remote_port==remote_port){
                   match++;
                  } else {
                    continue;
                  }
                }
                log("LOCAL_PORT: %i", ft->local_port);
                if(ft->local_port!=-1){
                  if(ft->local_port==local_port){
                    match++;
                  } else {
                    continue;
                  }
                }

              } else {
                continue;
              }
            }

            if(match>match_level){
              match_level=match;
              match_idx=i;
            }

          }
        }

        msg_buffer msg_buff;
        init_msg_buffer(&msg_buff);
        int out_len=put_int(&msg_buff,22);
        out_len+=put_int(&msg_buff,GTP_CTRL_MSG_GET_TEID_DATA);
        out_len+=put_int(&msg_buff,GTP_CTRL_IE_RES_CODE);

        if(match_idx!=-1){
          log("found the tunnel data");
          // found the tunnel data
          int loc_gtp_tun_fd=ip_teid_db[idx].teid_list[match_idx].local_fd;

          //find the address of the local GTP endpoint
          int ep_idx=-1;
          for(ep_idx=0;ep_idx<local_ep_length;ep_idx++){
            if(local_ep_db[ep_idx].fd==loc_gtp_tun_fd) break;
          }

          str_holder str;

          out_len+=put_int(&msg_buff,0);

          out_len+=put_int(&msg_buff,GTP_CTRL_IE_OUT_TEID);
          out_len+=put_str(&msg_buff,&ip_teid_db[idx].teid_list[match_idx].teid_out);


          const struct sockaddr_storage* ad=&ip_teid_db[idx].teid_list[match_idx].rem_addr;
          if(ad->ss_family==AF_INET){
            const struct sockaddr_in *sin=(const struct sockaddr_in *)ad;
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_IP);
            str.str_begin=(const unsigned char*)&(sin->sin_addr);
            str.str_size=4;
            out_len+=put_str(&msg_buff,&str);
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_PORT);
            out_len+=put_int(&msg_buff,ntohs(sin->sin_port));
          } else {
            const struct sockaddr_in6 *sin=(const struct sockaddr_in6 *)ad;
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_IP);
            str.str_begin=(const unsigned char*)&(sin->sin6_addr);
            str.str_size=16;
            out_len+=put_str(&msg_buff,&str);
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_REMOTE_PORT);
            out_len+=put_int(&msg_buff,ntohs(sin->sin6_port));
          }
          ad=(const struct sockaddr_storage*)local_ep_db[ep_idx].key.str_begin;
          if(ad->ss_family==AF_INET){
            const struct sockaddr_in *sin=(const struct sockaddr_in *)ad;
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_IP);
            str.str_begin=(const unsigned char*)&(sin->sin_addr);
            str.str_size=4;
            out_len+=put_str(&msg_buff,&str);
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_PORT);
            out_len+=put_int(&msg_buff,ntohs(sin->sin_port));
          } else {
            const struct sockaddr_in6 *sin=(const struct sockaddr_in6 *)ad;
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_IP);
            str.str_begin=(const unsigned char*)&(sin->sin6_addr);
            str.str_size=16;
            out_len+=put_str(&msg_buff,&str);
            out_len+=put_int(&msg_buff,GTP_CTRL_IE_LOCAL_PORT);
            out_len+=put_int(&msg_buff,ntohs(sin->sin6_port));
          }

          pthread_rwlock_unlock(&ip_teid_lock); // the lock is not needed any more

        } else {
          log("tunnel data not found");
          pthread_rwlock_unlock(&ip_teid_lock); // the lock is not needed any more
          out_len+=put_int(&msg_buff,0);
        }
        msg_buff.pos=0;
        put_int(&msg_buff,out_len);
        log("output length = %i", out_len);
        log("sending response");
#ifdef DEBUG
	for(int i=0;i<out_len;i++){
	  printf("%02X", msg_buff.msg[i]);
	}printf("\n");
#endif
        int s = send(fd,msg_buff.msg,out_len,0);
        log("response sent %i", s);
        free_msg_buffer(&msg_buff);

        break;
      }

      case GTP_CTRL_MSG_INIT:{
        log("GTP_CTRL_MSG_INIT msg");
        char *local_addr=NULL;
        char *remote_addr=NULL;
        int local_port=-1;
        int remote_port=-1;
        while(msg_len>buffer->pos){
          int ie_type;
          str_holder str;
          get_int(buffer,&ie_type);
          switch(ie_type){
            case GTP_CTRL_IE_LOCAL_IP:  // text
              get_str(buffer,&str);
              local_addr=strndup((const char*)str.str_begin,str.str_size);
              log("GTP_CTRL_MSG_INIT local_addr %s",local_addr);
              break;

            case GTP_CTRL_IE_REMOTE_IP:  // text
              get_str(buffer,&str);
              remote_addr=strndup((const char*)str.str_begin,str.str_size);
              log("remote_addr %s",remote_addr);
              break;

            case GTP_CTRL_IE_LOCAL_PORT:  // int
              get_int(buffer,&local_port);
              log("local_port %d",local_port);
              break;

            case GTP_CTRL_IE_REMOTE_PORT:  // int
              get_int(buffer,&remote_port);
              log("remote_port %d",remote_port);
              break;

            case GTP_CTRL_IE_PARAM_SET_ADDR_MODE:  // int
              get_int(buffer,&address_set_mode);
              break;
            default:
              break;
          }
        }
        if( // Something wrong with the parameters
          address_set_mode<0 || address_set_mode>2
         ){
            log("Something is missing");
            Free(local_addr);
            Free(remote_addr);
          return -1;
        }


        if(!threads_started){
          // init the local endpoint db
          // add the default entry
          local_ep_length=1;
          local_ep_num=1;
          local_ep_db = (local_ep_db_t *)Malloc(sizeof(local_ep_db_t));
          local_ep_db[0].fd=-1;
          local_ep_db[0].usage_num=0;
          local_ep_db[0].key.str_begin=(const unsigned char*)Malloc(sizeof(struct sockaddr_storage));
          local_ep_db[0].key.str_size=sizeof(struct sockaddr_storage);

          // init the local endpoint db
          // add the default entry

          if(local_addr){
            tun_handler_num=1;
            log("Process msg local_addr");
            //udp_to_tun
            if(fill_addr_struct(local_addr,local_port,(struct sockaddr_storage*)local_ep_db[0].key.str_begin,remote_addr,remote_port,&default_rem_addr)<0){
              Free(local_addr);
              Free(remote_addr);
              log("Process msg fill_addr_struct<0");
              return -1;
            }

            Free(local_addr);
            Free(remote_addr);
            int gtp_fd;
            if((gtp_fd=open_udp_port((struct sockaddr_storage*)local_ep_db[0].key.str_begin))<0){
            log("Process msg open_udp_port<0");
              return -1;
            }
            pthread_t gtp_handler;
            if ( pthread_create(&gtp_handler, NULL,udp_to_tun , &gtp_fd) )
            {
               printf("Can't start thread (gtp_handler_0)");
               exit(1);
            }
            ep_idx_map[local_ep_db[0].key]=0;
            local_ep_db[0].usage_num=1;
            local_ep_db[0].fd=gtp_fd;

            // add fd to the epoll list
            struct epoll_event event;
            event.data.fd = gtp_fd; /* return the fd to us later */
            event.events = EPOLLIN | EPOLLET ;

            if(epoll_ctl (epfd, EPOLL_CTL_ADD, gtp_fd, &event)<0){
              perror("epoll_ctl");
            }

            log("Creating tun_handler thread");
            //udp_to_tun
            if ( pthread_create(&tun_handler, NULL,tun_to_udp , NULL) )
            {
               printf("Can't start thread (tun_handler_0)");
               exit(1);
            }
          }
          log("Threads started");
          threads_started=true;
        }

        // send back the ACK
        msg_buffer msg_buff;
        init_msg_buffer(&msg_buff);

        put_int(&msg_buff,26);
        put_int(&msg_buff,GTP_CTRL_MSG_INIT_ACK);
        put_int(&msg_buff,GTP_CTRL_IE_RES_CODE);
        put_int(&msg_buff,0);
        put_int(&msg_buff,GTP_CTRL_IE_RES_TXT);

        str_holder str;
        str.str_begin=(const unsigned char*)"OK";
        str.str_size=2;
        put_str(&msg_buff,&str);

        /*int r =*/ send(fd,msg_buff.msg,msg_buff.pos,0);

        free_msg_buffer(&msg_buff);
        break;
      }

      case GTP_CTRL_MSG_CREATE:{
        str_holder teid_in;
        teid_in.str_size=-1;
        teid_in.str_begin=NULL;

        str_holder teid_out;
        teid_out.str_size=-1;
        teid_out.str_begin=NULL;

        str_holder ip;
        ip.str_size=-1;
        ip.str_begin=NULL;

        int ip_type=-1;

        int filter_rem_port=-1;
        int filter_loc_port=-1;
        int filter_proto=0;
        str_holder filter_rem_ip;
        filter_rem_ip.str_size=-1;
        filter_rem_ip.str_begin=NULL;

        char *local_addr=NULL;
        char *remote_addr=NULL;
        int local_port=-1;
        int remote_port=-1;

        while(msg_len>buffer->pos){
          int ie_type;
          //int ie_val;
          str_holder str;
          get_int(buffer,&ie_type);
          switch(ie_type){
            case GTP_CTRL_IE_OUT_TEID:  // oct
              get_str(buffer,&str);
              copy_str_holder(&teid_out,&str);
	      log("GTP_CTRL_MSG_CREATE with %d long out TEID:",teid_out.str_size);
	      log_str_holder(&teid_out);
              break;
            case GTP_CTRL_IE_IN_TEID:  // oct
              get_str(buffer,&teid_in);
              //copy_str_holder(&teid_in,&str);
              break;

            case GTP_CTRL_IE_ADDR:  // oct
              get_str(buffer,&ip);
              log("GTP_CTRL_MSG_CREATE ip");
	      log_str_holder(&ip);
              break;
            case GTP_CTRL_IE_ADDR_TYPE:  // int
              get_int(buffer,&ip_type);
              break;


            case GTP_CTRL_IE_LOCAL_IP:  // text
              get_str(buffer,&str); // skip
              local_addr=strndup((const char*)str.str_begin,str.str_size);
              log("GTP_CTRL_MSG_CREATE local_addr %s",local_addr);
              break;
            case GTP_CTRL_IE_REMOTE_IP:  // text
              get_str(buffer,&str); // skip
              remote_addr=strndup((const char*)str.str_begin,str.str_size);
              log("GTP_CTRL_MSG_CREATE remote_addr %s",remote_addr);
              break;
            case GTP_CTRL_IE_LOCAL_PORT:  // int
              get_int(buffer,&local_port);
              log("GTP_CTRL_MSG_CREATE local_port %d",local_port);
              break;
            case GTP_CTRL_IE_REMOTE_PORT:  // int
              get_int(buffer,&remote_port);
              log("GTP_CTRL_MSG_CREATE remote_port %d",remote_port);
              break;


            case GTP_CTRL_IE_FILTER_REMOTE_IP:  // oct
              get_str(buffer,&str);
              copy_str_holder(&filter_rem_ip,&str);
              log("GTP_CTRL_MSG_CREATE filter remote IP: %s", str);
              break;
            case GTP_CTRL_IE_FILTER_LOCAL_PORT:  // int
              get_int(buffer,&filter_loc_port);
              log("TGTP_CTRL_MSG_CREATE filter local port: %i", filter_loc_port);
              break;
            case GTP_CTRL_IE_FILTER_REMOTE_PORT:  // int
              get_int(buffer,&filter_rem_port);
              log("GTP_CTRL_MSG_CREATE filter remote port: %i", filter_rem_port);
              break;
            case GTP_CTRL_IE_FILTER_PROTO:  // int
              get_int(buffer,&filter_proto);
              log("GTP_CTRL_MSG_CREATE filter proto: %i", filter_proto);
              break;
            default:
              break;
          }
        }

        if(teid_out.str_size == -1){
          log("No out teid received");
          Free(local_addr);
          Free(remote_addr);
          return -1;
        }
        if(ip.str_size == -1){
          log("No ip received");
          free_str_holder(&teid_out);
          Free(local_addr);
          Free(remote_addr);
          return -1;
        }
        if(ip_type==-1){
          log("No ip type received");
          free_str_holder(&teid_out);
          Free(local_addr);
          Free(remote_addr);
          return -1;
        }


        int loc_fd=-1;
        struct sockaddr_storage *rem_addr_ptr=NULL;
        struct sockaddr_storage rem_addr;
        if(local_addr){
          struct sockaddr_storage loc_addr;
          if(fill_addr_struct(local_addr,local_port,&loc_addr,remote_addr,remote_port,&rem_addr)<0){
            Free(local_addr);
            Free(remote_addr);
            free_str_holder(&teid_out);
            send_error_ind(fd,"Can't set up tunnel addresses");
            log("Process msg cant set up tunnel addresses");
            return 0;
          }
          Free(local_addr);
          Free(remote_addr);
          rem_addr_ptr=&rem_addr;

          str_holder ep_key;
          ep_key.str_begin=(const unsigned char*)&loc_addr;
          ep_key.str_size=sizeof(struct sockaddr_storage);


          if(ep_idx_map.find(ep_key)==ep_idx_map.end()){ // local endpoint is not in the db
            int new_gtp_fd=open_udp_port(&loc_addr);
            if(new_gtp_fd==-1){
               free_str_holder(&teid_out);
               send_error_ind(fd,"Can't set up tunnel addresses, Check IP.");
               log("Process msg cant set up tunnel addresses, check ip");
               return 0;
            }

            if(local_ep_length==local_ep_num){ //we need to extend the list
//                pthread_rwlock_wrlock(ep_idx_lock);
              local_ep_length++;
              local_ep_db = (local_ep_db_t *)Realloc(local_ep_db,local_ep_length*sizeof(local_ep_db_t));
              local_ep_db[local_ep_num].fd=-1;
              local_ep_db[local_ep_num].usage_num=0;
              local_ep_db[local_ep_num].key.str_begin=(const unsigned char*)Malloc(sizeof(struct sockaddr_storage));
              local_ep_db[local_ep_num].key.str_size=sizeof(struct sockaddr_storage);
//                pthread_rwlock_unlock(ep_idx_lock);
            }

            //tun_to_udp
            int i;
            for(i=1;i<local_ep_length;i++){
              if(local_ep_db[i].fd==-1) break;
            }
            local_ep_db[i].fd=new_gtp_fd;
            local_ep_db[i].usage_num++;
            memcpy((void *)local_ep_db[i].key.str_begin,&loc_addr,sizeof(struct sockaddr_storage));
            ep_idx_map[local_ep_db[i].key]=i;
            local_ep_num++;
            loc_fd=local_ep_db[i].fd;

            // add fd to the epoll list
            struct epoll_event event;
            event.data.fd = new_gtp_fd; /* return the fd to us later */
            event.events = EPOLLIN | EPOLLET ;

            if(epoll_ctl (epfd, EPOLL_CTL_ADD, new_gtp_fd, &event)<0){
              perror("epoll_ctl");
            }


            if(local_ep_num>=(tun_handler_num*gtp_per_thread)){ // create threads if needed
              pthread_t gtp_handler;

              if ( pthread_create(&gtp_handler, NULL,udp_to_tun , &local_ep_db[i].fd) )
              {
                 printf("Can't start thread (gtp_handler_%i)", local_ep_num-1);
                 exit(1);
              }

              //udp_to_tun
              tun_handler_num++;
              pthread_t tun_handler_local;
              log("Creating tun_handler thread");
              if ( pthread_create(&tun_handler_local, NULL,tun_to_udp , NULL) )
              {
                 printf("Can't start thread (tun_handler_%i)", tun_handler_num-1);
                 exit(1);
              }
            }
          } else {
            int idx=ep_idx_map[ep_key];
            loc_fd=local_ep_db[idx].fd;
            local_ep_db[idx].usage_num++;
          }

        } else {
          loc_fd=local_ep_db[0].fd;
          if(loc_fd==-1){
            free_str_holder(&teid_out);
            send_error_ind(fd,"No tunnel addresses");
            log("Process msg no tunnel addresses");
            return 0;
          }
          local_ep_db[0].usage_num++;
          rem_addr_ptr=&default_rem_addr;
        }

        if(ip_type==0 || ip.str_size==16){  // IPv4 or full IPv6 address received

          if(address_set_mode==2){// assign the IP to the interface
            str_int_map::iterator it=ip_idx_map.find(ip);
            if(it==ip_idx_map.end()) {
              set_addr(&ip);
            }
          }

          add_teid_to_db(&ip,&teid_out,&filter_rem_ip,filter_loc_port,filter_rem_port,filter_proto,loc_fd,rem_addr_ptr);


//            if(address_set_mode==2){// assign the IP to the interface
//              set_addr(&ip);
//            }

          // send back the ACK
          msg_buffer msg_buff;
          str_holder str;
          init_msg_buffer(&msg_buff);
          int out_len=put_int(&msg_buff,22);
          out_len+=put_int(&msg_buff,GTP_CTRL_MSG_CREATE_ACK);
          out_len+=put_int(&msg_buff,GTP_CTRL_IE_OUT_TEID);
          out_len+=put_str(&msg_buff,&teid_out);
          out_len+=put_int(&msg_buff,GTP_CTRL_IE_IN_TEID);
          out_len+=put_str(&msg_buff,&teid_in);

          out_len+=put_int(&msg_buff,GTP_CTRL_IE_RES_CODE);
          out_len+=put_int(&msg_buff,0);
          out_len+=put_int(&msg_buff,GTP_CTRL_IE_RES_TXT);
          str.str_begin=(const unsigned char*)"OK";
          str.str_size=2;
          out_len+=put_str(&msg_buff,&str);

          out_len+=put_int(&msg_buff,GTP_CTRL_IE_ADDR);
          out_len+=put_str(&msg_buff,&ip);

          msg_buff.pos=0;
          put_int(&msg_buff,out_len);
          log("%X %X %X %X",msg_buff.msg[0],msg_buff.msg[1],msg_buff.msg[2],msg_buff.msg[3]);
          int r=
          send(fd,msg_buff.msg,out_len,0);
          free_msg_buffer(&msg_buff);
          log("Answer sent %d %d",out_len,r);
        } else {  // IPv6 prefix request is needed
          // We need a local copy of the incoming teid
          str_holder str=teid_in;
          copy_str_holder(&teid_in,&str);

          // Put the data into the db
          if(ip_req_db_size==ip_req_num){
            // increase the db
            pthread_rwlock_wrlock(&teid_idx_lock);
            ip_req_db_size+=10;
            ip_req_db=(ip_req_db_t*)Realloc(ip_req_db,ip_req_db_size*sizeof(ip_req_db_t));
            pthread_rwlock_unlock(&teid_idx_lock); // The new slots won't be accessed from other thread

            for(int i=ip_req_num;i<ip_req_db_size;i++){
              ip_req_db[i].teid_in.str_size=-1;
            }
          }

          int idx=0;
          for(;idx<ip_req_db_size;idx++){  // search for free slots, no need to lock, only this thread write it
            if(ip_req_db[idx].teid_in.str_size==-1) { break; }
          }
          ip_req_db[idx].teid_in=teid_in;
          ip_req_db[idx].teid_out=teid_out;
          ip_req_db[idx].fd=fd;
          ip_req_db[idx].ip.str_begin=(unsigned char*)Malloc(16*sizeof(unsigned char));
          memcpy((void*)(ip_req_db[idx].ip.str_begin+8),ip.str_begin,8);

          ip_req_db[idx].ip.str_size=16;

          ip_req_db[idx].local_ep_fd=loc_fd;
          memcpy(&ip_req_db[idx].rem_addr,rem_addr_ptr,sizeof(struct sockaddr_storage));
          ip_req_num++; // no problem if the thread reads the old value

          pthread_rwlock_wrlock(&teid_idx_lock);
          teidin_idx_map[teid_in]=idx;
          pthread_rwlock_unlock(&teid_idx_lock);

          // send the solicit message
          send_solicit(&teid_out,loc_fd,rem_addr_ptr);
        }
        break;
      }

      case GTP_CTRL_MSG_DESTROY:{
        str_holder teid_in;
        teid_in.str_size=-1;
        teid_in.str_begin=NULL;

        str_holder teid_out;
        teid_out.str_size=-1;
        teid_out.str_begin=NULL;

        str_holder ip;
        ip.str_size=-1;
        ip.str_begin=NULL;

        while(msg_len>buffer->pos){
          int ie_type;
          get_int(buffer,&ie_type);
          switch(ie_type){
            case GTP_CTRL_IE_OUT_TEID:  // oct
              get_str(buffer,&teid_out);
              break;
            case GTP_CTRL_IE_IN_TEID:  // oct
              get_str(buffer,&teid_in);
              break;
            case GTP_CTRL_IE_ADDR:  // oct
              get_str(buffer,&ip);
              break;
            default:
              break;
          }
        }
        if(teid_in.str_size == -1){
          log("No in teid received");
          return -1;
        }
        if(teid_out.str_size == -1){
          log("No out teid received");
          return -1;
        }

        remove_teid_from_db(&ip,&teid_out);
        break;
      }

      case GTP_CTRL_MSG_BYE:{
        msg_buffer msg_buff;
        init_msg_buffer(&msg_buff);
        close_local_ep(0,1);  // try to close the default endpoint
        put_int(&msg_buff,8);
        put_int(&msg_buff,GTP_CTRL_MSG_BYE_ACK);
        send(fd,msg_buff.msg,msg_buff.pos,0);
        free_msg_buffer(&msg_buff);
        return -1; // just close the fd after sending bye ack

        break;
      }

      default:
        // Unknown message, ignore it
        break;
    }

    if(msg_len!=curr_pos){  // there is data in the buffer, move it to the beginning
      memmove(buffer->msg,buffer->msg+msg_len,curr_pos-msg_len);
    }
    buffer->pos=curr_pos-msg_len;
    curr_pos=buffer->pos;
  }

 //log("Process msg return 0");
 return 0;
}

void send_error_ind(int fd,const char *fmt, ...){
}


void send_solicit(const str_holder* teid, int fd, struct sockaddr_storage *clientaddr){
  unsigned char  solicit_msg[]={
  //  The GTP header struct:
  //  octet 0:  Version, PT, reserved, flags: fixed values 0x30
  //  octet 1:  Message type: fixed value: 0xFF, GTP-U
  //  octet 2:  Payload length
  //  octet 3:  Payload length
  //  octet 4:  TEID
  //  octet 5:  TEID
  //  octet 6:  TEID
  //  octet 7:  TEID
  //  octet 8-n:  The payload
  0x03,
  0xFF,
  0x00,
  0x30,  // length 48
  0x00,0x00,0x00,0x00, // TEID placeholder
  0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,   // IPv6 header
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // No ip
  0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Every router
  0x85, 0x00, 0x7b, 0xb8, 0x00, 0x00, 0x00, 0x00};  // ICMPv6 Router Solicit

  solicit_msg[4]=teid->str_begin[0]; // set the TEID
  solicit_msg[5]=teid->str_begin[1];
  solicit_msg[6]=teid->str_begin[2];
  solicit_msg[7]=teid->str_begin[3];

  sendto(fd, solicit_msg, sizeof(solicit_msg) , 0, (const struct sockaddr *)clientaddr, sizeof(*clientaddr) );

}

// adds the address to the TUN if
int set_addr(const str_holder* ip){
  // the buffer holds the ip command:
  // ip addr add <address> dev <dev>
  // The max size of <address>: INET6_ADDRSTRLEN
  // the max size of <dev>: IFNAMSIZ
  // so the required buff size is: 18 + INET6_ADDRSTRLEN + IFNAMSIZ
  char buffer[18 + INET6_ADDRSTRLEN + IFNAMSIZ];
  char ip_name_buff[INET6_ADDRSTRLEN];

  // print the address into the buffer
  if(inet_ntop(ip->str_size==4?AF_INET:AF_INET6,ip->str_begin,ip_name_buff,INET6_ADDRSTRLEN)==NULL){
    //log("Address conversion failed: %d %s",errno,strerror(errno));
    return -1;
  }

  //log("IP addr to set: %s", ip_name_buff);

  // construct the ip command
  sprintf(buffer,"ip addr add %s dev %s",ip_name_buff,tun_name);

  log("command to execute: %s",buffer);

  system(buffer);
  return 0;
}

int del_addr(const str_holder* ip){
  // the buffer holds the ip command:
  // ip addr add <address> dev <dev>
  // The max size of <address>: INET6_ADDRSTRLEN
  // the max size of <dev>: IFNAMSIZ
  // so the required buff size is: 18 + INET6_ADDRSTRLEN + IFNAMSIZ
  char buffer[22 + INET6_ADDRSTRLEN + IFNAMSIZ];
  char ip_name_buff[INET6_ADDRSTRLEN];

  // print the address into the buffer
  if(inet_ntop(ip->str_size==4?AF_INET:AF_INET6,ip->str_begin,ip_name_buff,INET6_ADDRSTRLEN)==NULL){
    //log("Address conversion failed: %d %s",errno,strerror(errno));
    return -1;
  }

  //log("IP addr to set: %s", ip_name_buff);

  // construct the ip command
  sprintf(buffer,"ip addr del %s dev %s",ip_name_buff,tun_name);

  log("command to execute: %s",buffer);

  system(buffer);
  return 0;
}

void tun_set( ){
  struct ifreq netifr;
  int ctl_fd;
  memset(&netifr, 0, sizeof(netifr));

  if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
  {
    strncpy(netifr.ifr_name, tun_name, IFNAMSIZ);
    // set the tx queue length
    netifr.ifr_qlen = 65535;
    if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0){
      log("TUN/TAP TX queue length set to %d",netifr.ifr_qlen );
    }
    else{
      printf("Note: Cannot set tx queue length on %s %d %s\r\n", netifr.ifr_name,errno,strerror(errno));
    }
    // bring up the if
    netifr.ifr_flags = IFF_UP;

    if (ioctl (ctl_fd,SIOCSIFFLAGS , (void *) &netifr) >= 0){
      log("TUN if is up: %s", tun_name);
    }
    else{
      printf("Note: Cannot up the if %s %d %s\r\n", netifr.ifr_name,errno,strerror(errno));
    }

    close (ctl_fd);
  }
  else
  {
    printf("Note: Cannot open control socket on %s", netifr.ifr_name);
  }
}

int set_up_tun(int flags){
  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev, O_RDWR)) < 0 ) { // open the tun clone device
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr)); // clean the ifreq struct

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | flags ; // TUN interface, no proto info is needed

  if(tun_name) {
     /* if a TUN interface name was specified, put it in the structure; otherwise,
        the kernel will try to allocate the "next" device of the specified type */
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);
  }

   /* try to create the device */
  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return err;
  }

  if(!tun_name) {  // store the TUN dev name if not specified
    tun_name=strdup(ifr.ifr_name);
  }

  tun_set( );
  return fd;
}

// Creates a listening unix socket
// Because we target Linux only, use the abstarct socket feature
int start_ctrl_listen(){
  struct sockaddr_un localAddr;

  localAddr.sun_family = AF_UNIX;
  localAddr.sun_path[0]='\0';  // use abstract socket

  if(tun_name){
    snprintf(localAddr.sun_path+1,106,"gtp_tunel_daemon_%s",tun_name);
    log("Listen on: gtp_tunel_daemon_%s",tun_name);
  } else {
    snprintf(localAddr.sun_path+1,106,"gtp_tunel_daemon");
    log("Listen on: gtp_tunel_daemon");
  }

  if((daemon_fd = socket(PF_UNIX,SOCK_STREAM,0))<0) {
    int en=errno;
    printf("Socket creation error %d %s",en,strerror(en));
    return -1;
  }

  size_t addrLength;
  addrLength = sizeof(localAddr.sun_family) +1+ strlen(localAddr.sun_path+1);

  if(bind(daemon_fd, (struct sockaddr *) &localAddr, addrLength )<0) {
    int en=errno;
    printf("bind error %d %s",en,strerror(en));
    return -1;
  }

  if(listen(daemon_fd, 5)){
    int en=errno;
    printf("listen error %d %s",en,strerror(en));
    return -1;
  }

  return daemon_fd;
}

void *tun_to_udp(void *){
//  The GTP header struct:
//  octet 0:  Version, PT, reserved, flags: fixed values 0x30
//  octet 1:  Message type: fixed value: 0xFF, GTP-U
//  octet 2:  Payload length
//  octet 3:  Payload length
//  octet 4:  TEID
//  octet 5:  TEID
//  octet 6:  TEID
//  octet 7:  TEID
//  octet 8-n:  The payload
//


  unsigned char base_buffer[MAX_UDP_PACKET+8];
  unsigned char *buffer=base_buffer+8; // points to the data part of the GTP message
  int nread;
  int tun_fd_loc=tun_fd;

  str_holder ip;

  // init the fixed part of the GTP message
  base_buffer[0]=0x30;
  base_buffer[1]=0xFF; // message type
  while(1){
    nread = read(tun_fd_loc,buffer,MAX_UDP_PACKET);
    if(nread < 0) {
      perror("Reading from interface");
      exit(1);
    }
    //log("Message received with %d bytes in tun_to_udp",nread);
// check IP version to get the source address in the IP header. First octet:
//    ipv6 version: 6   0110xxxx  & 0x20 = 0010 0000 => true
//    ipv4 version: 4   0100xxxx  & 0x20 = 0000 0000 => false
    bool ipv6=false;
    if((buffer[0]&0x20)){
      // IPv6 address starts at octet 8 length 16
      ip.str_begin=buffer+8;
      ip.str_size=16;
      ipv6=true;
    } else {
      // IPv4 address starts at octet 12 length 4
      ip.str_begin=buffer+12;
      ip.str_size=4;
    }
    str_int_map::const_iterator it;
    pthread_rwlock_rdlock(&ip_teid_lock);
    it=ip_idx_map.find(ip);
    if(it!=ip_idx_map.end()){
      //log("it!=ip_idx_map.end()");
      const unsigned char* teid;
      int idx=it->second;
      // find the matching teid
      int match_level=-1;
      int match_idx=-1;

      const unsigned char* rem_addr=ipv6?buffer+24:buffer+16;
      int proto=ipv6?buffer[6]:buffer[9];

      int rem_port=-1;
      int loc_port=-1;
      //log("Captured proto = %i ", proto);
      if(proto==17 || proto==6){
        int start_offset=ipv6?40:(buffer[0]&0x0F)*4;
        loc_port=buffer[start_offset]*256+buffer[start_offset+1];
        rem_port=buffer[start_offset+2]*256+buffer[start_offset+3];
      }
      for(int i=0;i<ip_teid_db[idx].teid_num;i++){
        const filter_t* ft=&ip_teid_db[idx].teid_list[i].filter;
        int match=0;
        if(ft->remote_ip.str_size!=-1){
          //log("Captured ft->remote_ip.str_size!=-1");
          //log("Captured ft->remote_ip = %s , rem_addr = %s ", ft->remote_ip.str_begin,rem_addr);
          if(memcmp(ft->remote_ip.str_begin,rem_addr,ipv6?16:4)==0){
            //log("Capture memcmp(ft->remote_ip.str_begin,rem_addr,ipv6?16:4)==0");
            match++;
          } else {
            //log("Capture continue");
            continue;
          }
        }
        //log("Captured ft->proto = %i ", ft->proto);
        if(ft->proto!=0){
          if(ft->proto==proto){
            //log("Capture ft->proto==proto");
            match++;
            // we need proto match to handle ports
            if(ft->remote_port!=-1){
              //log("Capture ft->remote_port!=-1");
              //log("Capture ft->remote_port=%i , rem_port=%i", ft->remote_port,rem_port);
              if(ft->remote_port==rem_port){
               match++;
              } else {
                continue;
              }
            }
            if(ft->local_port!=-1){
              //log("Capture ft->local_port=%i , loc_port=%i", ft->local_port,loc_port);
              if(ft->local_port==loc_port){
                match++;
              } else {
                continue;
              }
            }

          } else {
            continue;
          }
        }

        if(match>match_level){
          //log("Capture match>match_leve");
          match_level=match;
          match_idx=i;
        }

      }
      if(match_idx!=-1){
        //log("Capture match_idx!=-1");
        teid=ip_teid_db[idx].teid_list[match_idx].teid_out.str_begin;
        base_buffer[4]=teid[0];
        base_buffer[5]=teid[1];
        base_buffer[6]=teid[2];
        base_buffer[7]=teid[3];
        pthread_rwlock_unlock(&ip_teid_lock); // the lock is not needed any more
        // update msg_length
        base_buffer[3]=nread & 0xFF;
        base_buffer[2]=(nread>>8) & 0xFF;
        if((sendto(ip_teid_db[idx].teid_list[match_idx].local_fd, base_buffer, nread+8, 0, (const struct sockaddr *)&ip_teid_db[idx].teid_list[match_idx].rem_addr, sizeof(struct sockaddr_storage) )) < 0) {
          perror("Sending to peer");
          exit(1);
        }
      } else {
        pthread_rwlock_unlock(&ip_teid_lock); // the lock is not needed any more
      }
    } else {
      // NO ip  -> teid map, just drop the packet
      pthread_rwlock_unlock(&ip_teid_lock);
    }



  }

}
void *udp_to_tun(void* a){
// for the magic number check the IPv6 RFCs
// The IP packet starts at the 8 after the GTP-U header
  int gtp_fd=*(int *)a;
  unsigned char buffer[MAX_UDP_PACKET+8];

  struct epoll_event events[MAX_EVENTS_PER_THREAD];

  while(1) {
    int num = epoll_wait (epfd, events,MAX_EVENTS_PER_THREAD , -1);
    if(num < 0) {
      continue;
    }
    for(int i=0;i<num;i++){
      gtp_fd=events[i].data.fd;
      int n=-1;
      while((n=recvfrom(gtp_fd, buffer, MAX_UDP_PACKET+8, 0, (struct sockaddr *)NULL, 0))!=-1){
        //log("GTP UDP received %d %d %s",n,errno,strerror(errno));
        if(buffer[1]!=0xFF){  // we received something which is not a T-PDU
          log("We received %d instead of T-PDU",buffer[1]);
          continue;
        }
        //    IPv6                 ICMPv6                      RA
        if((buffer[8] & 0x20) && ( buffer[14] == 0x3A )  && ( buffer[48] == 0x86 )  &&  ip_req_num){
             // there are outgoing IP request, ICMPv6 message received
          // check the teid in the database
          str_holder teid_in;
          teid_in.str_begin=buffer+4;
          teid_in.str_size=4;
          pthread_rwlock_rdlock(&teid_idx_lock);
          bool found= teidin_idx_map.find(teid_in)!=teidin_idx_map.end();
          pthread_rwlock_unlock(&teid_idx_lock);
          if(found){
            // This is the message we're looking for

            // Get the prefix                                     // The ICMPv6 RA header size before the first option is 16
            int option_length= buffer[12]*256 + buffer[13] - 16;
            unsigned char* opt=buffer+64;
            unsigned char* prefix_pt=NULL;
            while(option_length>0){  // search for the prefix option
              unsigned int tp=opt[0]; // option type
              unsigned int ol=opt[1]; // option length measured in 8 octets
              if(tp==0x03){
                prefix_pt=opt+16;
                break;
              }
              // move to the next option
              opt+=(ol*8);
              option_length-=(ol*8);
            }
            if(prefix_pt){ // The prefix is found in the msg
              pthread_rwlock_wrlock(&teid_idx_lock);
              str_int_map::iterator it;
              if((it=teidin_idx_map.find(teid_in))!=teidin_idx_map.end()){ // maybe other udp_to_tun thread received a same message and sent it to the main thread already
                int idx=it->second;
                teidin_idx_map.erase(it);  // remove it from the index map
                // copy the IP prefix, the place of it is
                memcpy((void*)(ip_req_db[idx].ip.str_begin),prefix_pt,8);

                pthread_rwlock_unlock(&teid_idx_lock);

                write(pipefd[1],&idx,sizeof(int)); // send to the main thread
              } else {
                pthread_rwlock_unlock(&teid_idx_lock);
              }

            }
            continue;
          }

        }

        int nread = write(tun_fd,buffer+8,n-8); // 8 : GTP header size
        //log("Writeing to interface %d, %d, %s",n-8,errno,strerror(errno));
        if(nread < 0) {
          perror("Writeing to interface");
          //exit(1);
        }
      }
    }
  }

  return 0;
}
int add_teid_to_db(str_holder* ip, str_holder* teid, str_holder* rem_ip,int loc_port, int rem_port, int proto, int  loc_fd,struct sockaddr_storage *rem_addr){
  pthread_rwlock_wrlock(&ip_teid_lock);

  str_int_map::iterator it=ip_idx_map.find(*ip);
  int idx=-1;
  if(it==ip_idx_map.end()){
    if(ip_teid_db_size==ip_teid_db_entries){
      if(ip_teid_db_size==0){ip_teid_db_size+=256;}
      ip_teid_db_size*=2;
      ip_teid_db=(ip_entry_t*)Realloc(ip_teid_db,ip_teid_db_size*sizeof(ip_entry_t));
      for(int i=ip_teid_db_entries;i<ip_teid_db_size;i++){
        ip_teid_db[i].teid_num=-1;
        ip_teid_db[i].teid_list=NULL;
      }
    }
    for(idx=lastIdx;idx<ip_teid_db_size;idx++){
      if(ip_teid_db[idx].teid_num==-1) {
        break;
      }
    }
    if(idx>=ip_teid_db_size) {
      for(idx=0;idx<lastIdx;idx++){
        if(ip_teid_db[idx].teid_num==-1) {
          break;
        }
      }
    }
    ip_teid_db[idx].teid_num=0;
    copy_str_holder(&ip_teid_db[idx].ip,ip);
    ip_idx_map[ip_teid_db[idx].ip]=idx;
    ip_teid_db_entries++;
    lastIdx=idx;
  } else {
    idx=it->second;
  }
  int filter_idx=ip_teid_db[idx].teid_num;
  ip_teid_db[idx].teid_num++;
  ip_teid_db[idx].teid_list=(teid_filter_t*)Realloc(ip_teid_db[idx].teid_list,ip_teid_db[idx].teid_num*sizeof(teid_filter_t));
  log("Adding teid to id db idx %d, filter %d",idx,filter_idx);

  ip_teid_db[idx].teid_list[filter_idx].teid_out=*teid;
  filter_t* filter=&ip_teid_db[idx].teid_list[filter_idx].filter;
  filter->proto=proto;
  filter->remote_port=rem_port;
  log("remote_port %d",rem_port);
  filter->local_port=loc_port;
  log("local_port %d",loc_port);
  if(rem_ip){
    filter->remote_ip=*rem_ip;
  } else {
    filter->remote_ip.str_size=-1;
  }
  log("rem-ip");
  log_str_holder(&(filter->remote_ip));

  ip_teid_db[idx].teid_list[filter_idx].local_fd=loc_fd;
  memcpy(&ip_teid_db[idx].teid_list[filter_idx].rem_addr,rem_addr,sizeof(struct sockaddr_storage));

  pthread_rwlock_unlock(&ip_teid_lock);
  return 0;
}

int remove_teid_from_db(str_holder* ip,str_holder* teid){
  pthread_rwlock_wrlock(&ip_teid_lock);

  str_int_map::iterator it=ip_idx_map.find(*ip);
  if(it!=ip_idx_map.end()){
    int idx=it->second;
    int i=0;
    for(i=0;i<ip_teid_db[idx].teid_num;i++){
      if(!str_eq(*teid,ip_teid_db[idx].teid_list[i].teid_out)){
        free_str_holder(&ip_teid_db[idx].teid_list[i].teid_out);
        free_str_holder(&ip_teid_db[idx].teid_list[i].filter.remote_ip);
        for(int j=0;j<local_ep_length;j++){
          if(local_ep_db[j].fd==ip_teid_db[idx].teid_list[i].local_fd){
            local_ep_db[j].usage_num--;
            close_local_ep(j);
          }
        }

        for(int k=i;k<ip_teid_db[idx].teid_num-1;k++){
          ip_teid_db[idx].teid_list[k]=ip_teid_db[idx].teid_list[k+1];
        }
        ip_teid_db[idx].teid_num--;
        if(ip_teid_db[idx].teid_num){
          ip_teid_db[idx].teid_list=(teid_filter_t*)Realloc(ip_teid_db[idx].teid_list,ip_teid_db[idx].teid_num*sizeof(teid_filter_t));
        }
//        break;  we should remove all teid entries. There can be several with different filter
      }
    }
    if(ip_teid_db[idx].teid_num==0){  // the last teid was removed
      ip_idx_map.erase(ip_teid_db[idx].ip);
      del_addr(&ip_teid_db[idx].ip);
      Free(ip_teid_db[idx].teid_list);
      ip_teid_db[idx].teid_list=NULL;
      ip_teid_db[idx].teid_num=-1;
      free_str_holder(&ip_teid_db[idx].ip);
      ip_teid_db_entries--;
    }
  }

  pthread_rwlock_unlock(&ip_teid_lock);
  return 0;
}

int main(int argc, char **argv){
  signal(SIGPIPE, SIG_IGN);
  process_options(argc, argv);  // check the command line options
  pthread_rwlock_init(&ip_teid_lock, NULL);
  pthread_rwlock_init(&teid_idx_lock, NULL);
  pthread_rwlock_init(&ep_idx_lock, NULL);
  log("Starting");
  if(start_ctrl_listen()<0){
    printf("Can't listen on control port\r\n");
    exit(1);
  }
  log("Listenning...");
  // create the TUN interface
  log("Creating tun");

  if((tun_fd=set_up_tun(0))<0){
    printf("Can't setup TUN interface\r\n");
    exit(1);
  }
  log("Tun opened: %s",tun_name);

  // create the internal pipe
  if (pipe(pipefd) == -1) {
    printf("Can't create internal pipe: %d %s\r\n",errno,strerror(errno));
    exit(1);
  }

  log("Internal pipe opened");

  int poll_list_size=4; // The initial size is 2: one listening
                        //                        one internal pipe
                        //                        2 space for clients
  int poll_nfds=2;  // The listening socket and internal pipe will be added to the list
  struct pollfd *fds=(struct pollfd *)Malloc(poll_list_size*sizeof(struct pollfd));

  memset(fds,0,poll_list_size*sizeof(struct pollfd));
  fds[0].fd=daemon_fd;
  fds[0].events= POLLIN | POLLPRI | POLLRDHUP;

  fds[1].fd=pipefd[0];
  fds[1].events= POLLIN | POLLPRI | POLLRDHUP;

  for(int i=2;i<poll_list_size;i++){
    fds[i].fd=-1;
  }

  epfd = epoll_create(100);  /* plan to watch ~100 fds */
  if (epfd < 0){
    perror ("epoll_create");
  }
  // create buffers for 2 client connections. As we have room for 2 client connection in the fds list
  msg_buffer *buffers=(msg_buffer *)Malloc((poll_list_size-2)*sizeof(msg_buffer));

  // Each buffer will be initialized when the connection is accepted


  while(true){  // controll connection handler
                //
    int res=poll(fds,poll_list_size,-1);
    log("poll returned %d",res);
    if(res<0){
      printf("poll error: %d %s\r\n",errno,strerror(errno));
      exit(1);
    }

    // first check the client fds
    for(int i=2;i<poll_list_size;i++){
      if((fds[i].fd != -1) && fds[i].revents){
        // No buffer for the first two fd
        log("Message on fd %d",fds[i].fd );
        if(process_msg(buffers+(i-2),fds[i].fd)<0){
          // the test port closed the connection or something went wrong
          log("Message processing failed");
          close(fds[i].fd);
          fds[i].fd = -1;
          free_msg_buffer(buffers+(i-2));
        }
        fds[i].revents=0;
      }
    }

    // check the intrnal pipe
    if(fds[1].revents){
      fds[1].revents=0;
      int idx=0;
      int rd=read(pipefd[0],&idx,sizeof(int));
      if(rd==sizeof(int)){
        // read was ok.
        if(address_set_mode==2){// assign the IP to the interface
          str_int_map::iterator it=ip_idx_map.find(ip_req_db[idx].ip);
          if(it==ip_idx_map.end()) {
            set_addr(&ip_req_db[idx].ip);
          }
        }

        // put the out teid into the maps
        add_teid_to_db(&ip_req_db[idx].ip,&ip_req_db[idx].teid_out,NULL,-1,-1,0,ip_req_db[idx].local_ep_fd,&ip_req_db[idx].rem_addr);

//            if(address_set_mode==2){// assign the IP to the interface
//              set_addr(&ip_req_db[idx].ip);
//            }

        // send back the ACK
        msg_buffer msg_buff;
        str_holder str;
        init_msg_buffer(&msg_buff);
        int out_len=put_int(&msg_buff,22);
        out_len+=put_int(&msg_buff,GTP_CTRL_MSG_CREATE_ACK);
        out_len+=put_int(&msg_buff,GTP_CTRL_IE_OUT_TEID);
        out_len+=put_str(&msg_buff,&ip_req_db[idx].teid_out);
        out_len+=put_int(&msg_buff,GTP_CTRL_IE_IN_TEID);
        out_len+=put_str(&msg_buff,&ip_req_db[idx].teid_in);

        out_len+=put_int(&msg_buff,GTP_CTRL_IE_RES_CODE);
        out_len+=put_int(&msg_buff,0);
        out_len+=put_int(&msg_buff,GTP_CTRL_IE_RES_TXT);
        str.str_begin=(const unsigned char*)"OK";
        str.str_size=2;
        out_len+=put_str(&msg_buff,&str);

        out_len+=put_int(&msg_buff,GTP_CTRL_IE_ADDR);
        out_len+=put_str(&msg_buff,&ip_req_db[idx].ip);

        msg_buff.pos=0;
        put_int(&msg_buff,out_len);
        //int r=
         send(ip_req_db[idx].fd,msg_buff.msg,out_len,0);
        free_msg_buffer(&msg_buff);

        // teid in is not needed any more
        free_str_holder(&ip_req_db[idx].teid_in);

        //log("Answer sent %d %d",out_len,r);

        // free the ip req db slot
        ip_req_db[idx].teid_in.str_size=-1;
      }
    }

    // check the listening socket
    if(fds[0].revents){
      int remote_fd=accept(daemon_fd, NULL, NULL);
      if(remote_fd<0){
        printf("accept error: %d %s\r\n",errno,strerror(errno));
        exit(1);
      }
      log("Accepted %d",remote_fd);

      if(poll_list_size==poll_nfds){
        // we need some more space to store the connection
        poll_list_size+=4;
        fds=(struct pollfd *)Realloc(fds,poll_list_size*sizeof(struct pollfd));
        for(int k=poll_nfds;k<poll_list_size;k++){
          fds[k].fd=-1;
          fds[k].events=0;
        }

        // reserve the buffers
        buffers=(msg_buffer *)Realloc(buffers,(poll_list_size-2)*sizeof(msg_buffer));
      }
      poll_nfds++;
      // find the first unused connection
      int k;
      for(k=2;k<poll_list_size;k++){
        if(fds[k].fd==-1){break;}
      }
      fds[k].fd=remote_fd;
      fds[k].events= POLLIN | POLLPRI | POLLRDHUP;
      fds[k].revents= 0;

      // No buffer for the first two fd
      init_msg_buffer(buffers+(k-2));

      fds[0].revents=0;
    }

  }

}
