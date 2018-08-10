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
#include "GTP_mem_handler.h"
#include <stdlib.h>

void *Malloc(size_t size){
  void *ret_val=malloc(size);
  if(ret_val==NULL){
    abort();
  }
  return ret_val;
}
void Free(void *ptr){
  free(ptr);
}
void *Realloc(void *ptr, size_t size){
  void *ret_val=realloc(ptr,size);
  if(ret_val==NULL){
    abort();
  }
  return ret_val;
}

