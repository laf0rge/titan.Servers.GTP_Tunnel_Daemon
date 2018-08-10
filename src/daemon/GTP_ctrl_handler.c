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
#include "GTP_ctrl_handler.h"
#include "GTP_mem_handler.h"
#include <string.h>
#include <stdio.h>

int put_int(msg_buffer* buffer ,const int data){

  inc_buff_size(buffer,4);
  
  buffer->msg[buffer->pos] = (data >> 24) & 0xff;
  buffer->pos++;
  buffer->msg[buffer->pos] = (data >> 16) & 0xff;
  buffer->pos++;
  buffer->msg[buffer->pos] = (data >> 8) & 0xff;
  buffer->pos++;
  buffer->msg[buffer->pos] = data & 0xff;
  buffer->pos++;
  
  return 4;
}


int get_int(msg_buffer* buffer,int* data){
  if((buffer->pos + 4 ) >  buffer->size){  
    return -1; // not enough octets in the buffer
  }

  *data=buffer->msg[buffer->pos];
  (*data) <<= 8;

  buffer->pos++;

  *data+=buffer->msg[buffer->pos];
  (*data) <<= 8;
  buffer->pos++;
  *data+=buffer->msg[buffer->pos];
  (*data) <<= 8;
  buffer->pos++;
  *data+=buffer->msg[buffer->pos];
  buffer->pos++;

  return 4;
}

int put_str(msg_buffer* buffer,const str_holder* data){
  int ret_val=put_int(buffer,data->str_size);
  
  inc_buff_size(buffer,data->str_size);
  
  memcpy(buffer->msg+buffer->pos,data->str_begin,data->str_size);
  buffer->pos += data->str_size;
  return ret_val + data->str_size;

}

int get_str(msg_buffer* buffer,str_holder* data){
  int ret_val=-1;
  int str_size;
  if(get_int(buffer,&str_size)!=-1){
    if((buffer->pos +  str_size) <=  buffer->size){
      data->str_begin = buffer->msg+buffer->pos;
      data->str_size = str_size;
      ret_val = 4+ str_size;
      buffer->pos += str_size;
    }
  }
  return ret_val;

}

void init_msg_buffer(msg_buffer* buffer){
  buffer->msg=(unsigned char*)Malloc(256*sizeof(unsigned char));
  buffer->size =256;
  buffer->pos =0;
}
void free_msg_buffer(msg_buffer* buffer){
  Free(buffer->msg);
}

void inc_buff_size(msg_buffer* buffer,int new_size){
  while((buffer->pos + new_size ) >=  buffer->size){
    buffer->size *=2;
    buffer->msg=(unsigned char*)Realloc(buffer->msg,buffer->size);
  }
}

void copy_str_holder(str_holder* target, const str_holder* source){
  unsigned char* tmp=(unsigned char*)Malloc(source->str_size*sizeof(unsigned char));
  memcpy(tmp,source->str_begin,source->str_size);
  target->str_size=source->str_size;
  target->str_begin=tmp;
}
void free_str_holder(str_holder* str){
  if(str->str_size>=0){
    Free((void*)str->str_begin);
  }
}
int str_eq(const str_holder &lhs, const str_holder &rhs){

    if(lhs.str_size == rhs.str_size){
      return memcmp(lhs.str_begin,rhs.str_begin,lhs.str_size);
    }
    return lhs.str_size - rhs.str_size;

}

