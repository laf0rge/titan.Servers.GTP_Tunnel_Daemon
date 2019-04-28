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
// Contains the definitions of the message handler function, msg & IE codes
// Used by both the test port and the daemon.

#ifndef GTP_CTRL_HANDLER_H_
#define GTP_CTRL_HANDLER_H_
#ifdef __cplusplus
//extern "C" {
#endif
#include <string.h>
// MSG structure between the TP & Daemon
//
//      |------------------------|
//      |    LENGTH              |
//      |------------------------|
//      |    MSG code            |
//      |------------------------|
//      |  IE  list              |
//      |------------------------|
//
//
// IE structure
//
//      |------------------------|
//      |    IE code             |
//      |------------------------|
//      | DATA  (int, string, IE)|
//      |------------------------|
//


// MSG type and IE type codes used by messages between the App and the Daemon

typedef enum {
// MSG codes
GTP_CTRL_MSG_INIT = 0,  GTP_CTRL_MSG_INIT_ACK = 1,
GTP_CTRL_MSG_BYE = 2,   GTP_CTRL_MSG_BYE_ACK = 3,
GTP_CTRL_MSG_CREATE = 4,GTP_CTRL_MSG_CREATE_ACK = 5,
GTP_CTRL_MSG_DESTROY = 6,
GTP_CTRL_MSG_INDICATION = 7,
GTP_CTRL_MSG_GET_TEID = 8,
GTP_CTRL_MSG_GET_TEID_DATA =9,
// IE codes

GTP_CTRL_IE_OUT_TEID= 1000,
GTP_CTRL_IE_IN_TEID= 1001,
GTP_CTRL_IE_LOCAL_PORT= 1002,
GTP_CTRL_IE_LOCAL_IP= 1003,
GTP_CTRL_IE_REMOTE_IP= 1004,
GTP_CTRL_IE_REMOTE_PORT= 1005,
GTP_CTRL_IE_IF_NAME= 1006,
GTP_CTRL_IE_PARAM_SET_ADDR_MODE= 1007,
GTP_CTRL_IE_RES_CODE= 1008,
GTP_CTRL_IE_RES_TXT= 1009,
GTP_CTRL_IE_ADDR_TYPE= 1010,
GTP_CTRL_IE_ADDR= 1011,
GTP_CTRL_IE_FILTER_LOCAL_PORT= 1012,
GTP_CTRL_IE_FILTER_REMOTE_IP= 1013,
GTP_CTRL_IE_FILTER_REMOTE_PORT= 1014,
GTP_CTRL_IE_FILTER_PROTO= 1015,
GTP_CTRL_IE_PROTO= 1016
} ctrl_msg_ie_codes;


// Buffer type
typedef struct {
  unsigned char* msg;
  int size;
  int pos;
} msg_buffer;

void init_msg_buffer(msg_buffer*);
void free_msg_buffer(msg_buffer*);



// String representation 

typedef struct str_holder_struct {
  const unsigned char* str_begin; // points to the beginning of the string
                                  // in the storage area
  int str_size;
  
  bool operator==(const struct str_holder_struct &other) const{
    return (str_size == other.str_size) && (memcmp(str_begin,other.str_begin,str_size)==0);
  };
  
} str_holder;

void copy_str_holder(str_holder*, const str_holder*);
void free_str_holder(str_holder*);

// puts an int into the buffer, 4 byte, msb first
int put_int(msg_buffer*,const int);
// retrieves an int from a buffer
int get_int(msg_buffer*,int*);

// stores or retrieve a string (octet or char)
// first store the length as int (in 4 octets)
// then the string (without \0 at the end)
// The get function sets only the pointer and the length value, doesn't copy

int put_str(msg_buffer*,const str_holder*);
int get_str(msg_buffer*,str_holder*);

int str_eq(const str_holder &lhs, const str_holder &rhs);
// increase the free space in the buffer to at least new_size octets
void inc_buff_size(msg_buffer*,int new_size);

#ifdef __cplusplus
//}
#endif
#endif
