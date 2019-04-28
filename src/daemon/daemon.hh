///////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2000-2019 Ericsson Telecom AB
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
#ifndef GTP_DAEMON_H_
#define GTP_DAEMON_H_
#include <stdarg.h>
#include <stdint.h>

#include "GTP_ctrl_handler.h"
#include <string>
#include <string.h>

class str_eq{
public:
  bool operator() (const str_holder &lhs, const str_holder &rhs) const{
    return (lhs.str_size == rhs.str_size) && (memcmp(lhs.str_begin,rhs.str_begin,lhs.str_size)==0);
  }
};
struct str_hash{
  std::size_t operator() (const str_holder &key) const{
    if(key.str_size==4){ // ipv4
      return *((uint32_t*)key.str_begin);
    } else if(key.str_size==16) { // ipv6 
      return *((uint32_t*)(key.str_begin+12));
    } else {
      return 162;
    }
  }
};


#if __cplusplus >= 201103L
#include <unordered_map>

//typedef std::unordered_map<str_holder,str_holder,str_hash > str_hash_map;
//typedef std::unordered_map<str_holder,int,str_hash > str_int_map;
#else
#include <tr1/unordered_map>
//typedef std::tr1::unordered_map<str_holder,str_holder,str_hash > str_hash_map;
//typedef std::tr1::unordered_map<str_holder,int,str_hash > str_int_map;

#endif
#include <map>

struct str_comp{
  bool operator() (const str_holder &lhs, const str_holder &rhs) const{
    if(lhs.str_size == rhs.str_size){
      return memcmp(lhs.str_begin,rhs.str_begin,lhs.str_size)<0;
    }
    return lhs.str_size < rhs.str_size;
  }
};

typedef std::map<str_holder,str_holder,str_comp> str_hash_map;

typedef std::map<str_holder,int,str_comp> str_int_map;
#ifdef DEBUG
void log(const char *fmt, ...);
#else

#define log(...) 
#define log_str_holder(...)
#endif

// outstanding IP prefix request database type
typedef struct{
  str_holder teid_in;
  str_holder teid_out;
  str_holder ip;
  int fd;  // fd on which send the create ok
  int local_ep_fd;  // local endpoint fd belongs to the request
  struct sockaddr_storage rem_addr;  // The address of the remote endpoint of the tunnel
} ip_req_db_t;

// filter representation
typedef struct{
  int proto;               // protocol num in the IP header
  str_holder remote_ip; 
  int        remote_port;  // host byte order
  int        local_port;   // host byte order
} filter_t;

// TEID's filter structure
typedef struct{
  str_holder teid_out;        // The TEID
  filter_t   filter;          // filter
  // data of the outgoing tunnel
  struct sockaddr_storage rem_addr;  // The address of the remote endpoint of the tunnel
  int local_fd;                       // local endpoint fd
} teid_filter_t;


// database type for IP->TEID mapping
typedef struct{
  str_holder     ip;         // holds the local IP data. 
  int            teid_num;   // How many teid belongs to the IP
  teid_filter_t* teid_list;  // the list of the teids
} ip_entry_t;

// local tunnel endpoint databasetypes
typedef struct{
  int fd;           // the fd, on which the messages should be sent & received.
                    // one local endpoint can serve several tunnel
  int usage_num;    // how many teids are using the local endpoint
  str_holder  key;  // points to a struct sockaddr_storage, used as a key in the db
} local_ep_db_t;


void print_usage();

void process_options(int argc, char **argv);

int set_up_tun(int flags); // additional flags

int start_ctrl_listen();

int process_msg(msg_buffer* buffer, int fd);

int fill_addr_struct(const char* local_ip, int local_port, struct sockaddr_storage *local_addr,const char* rem_ip, int rem_port, struct sockaddr_storage *rem_addr);

int open_udp_port(struct sockaddr_storage *local_addr);

void send_error_ind(int fd,const char *fmt, ...);

void *tun_to_udp(void *);
void *udp_to_tun(void* );
#define MAX_UDP_PACKET 1500

int set_addr(const str_holder*);

void send_solicit(const str_holder*, int fd, struct sockaddr_storage *clientaddr);

int add_teid_to_db(str_holder* ip, str_holder* teid, str_holder* rem_ip,int loc_port, int rem_port, int proto, int loc_fd,struct sockaddr_storage *rem_addr);
int remove_teid_from_db(str_holder* ip,str_holder* teid);
#endif
