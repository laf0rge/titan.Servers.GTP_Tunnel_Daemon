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
#ifndef GTP_MEM_HANDLER_H_
#define GTP_MEM_HANDLER_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


void *Malloc(size_t size);
void Free(void *ptr);
void *Realloc(void *ptr, size_t size);

#ifdef __cplusplus
}
#endif


#endif
