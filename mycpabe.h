#ifndef _MYCPABE_H
#define _MYCPABE_H
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <sys/time.h>
#include <pbc_random.h>
#include <hiredis/hiredis.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#ifdef __cplusplus 
extern "C" {  
#endif  
int setMsg(const char*);
int getMsg(const char*,const char*,char **,char**);
int init_hiredis();
#ifdef __cplusplus  
}  
#endif

#endif
