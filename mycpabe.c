#include "mycpabe.h"


char * ALL_ATTRS="(sysadmin and (hire_date < 946702800 or security_team)) or\
				  (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team))";

char *policy=0;

redisContext * conn=0;
char *usage="hello";

	gint 
comp_string( gconstpointer a, gconstpointer b)
{
		return strcmp(a,b);
}

int setup(bswabe_pub_t** pub,bswabe_msk_t**msk){
		bswabe_setup(pub,msk);
		return 0;
}


int keygen(bswabe_pub_t* pub,bswabe_msk_t* msk,
				char*attribute[],bswabe_prv_t** prv){
		GSList* alist;
		GSList* ap;
		int n;
		int i=0;
		alist=0;	
	
		while(attribute[i]){
				parse_attribute(&alist,attribute[i++]);
		}

		char**attrs=0;
		alist = g_slist_sort(alist,comp_string);
		n = g_slist_length(alist);
		attrs = malloc((n+1)*sizeof(char*));
		i=0;
		for(ap = alist;ap;ap=ap->next)
				attrs[i++]=ap->data;	
		attrs[i]=0;
		(*prv)=bswabe_keygen(pub,msk,attrs);

		return 0;
}

int enc(bswabe_pub_t* pub,bswabe_msk_t*msk,GByteArray* plt,
				GByteArray**cph_buf, GByteArray** aes_buf){
		bswabe_cph_t* cph;
		element_t m;
		if(!policy) 
				policy=parse_policy_lang(ALL_ATTRS);
		cph = bswabe_enc(pub, m, policy);
		(*cph_buf) = bswabe_cph_serialize(cph);
		(*aes_buf) = aes_128_cbc_encrypt(plt, m);
		element_clear(m);
		return 0;
}

int dec(bswabe_pub_t* pub,bswabe_prv_t*prv,GByteArray*aes_buf,
				GByteArray*cph_buf,GByteArray**plt){
		element_t m ;
		bswabe_cph_t* cph;
		cph=bswabe_cph_unserialize(pub,cph_buf,1);
		if( !bswabe_dec(pub,prv,cph,m))
				printf("%s\n", bswabe_error());
		(*plt)=aes_128_cbc_decrypt(aes_buf,m);
		return 0;
}

int init_hiredis(){
		//init redis connect,and check connect 
		conn = redisConnect("127.0.0.1", 6379);
		if(NULL == conn) {
				fprintf(stderr, "redisConnect 127.0.0.1:6379 error!\n");
				exit(EXIT_FAILURE);
		}   
		if(conn->err) {
				fprintf(stderr, "redisConect error:%d\n", conn->err);
				redisFree(conn);
				exit(EXIT_FAILURE);
		}   

		return 0;
}
int get_pub_and_msk(bswabe_prv_t**pub,bswabe_msk_t**msk)
{
		redisReply * pubReply=redisCommand(conn,"get pub");
		redisReply * mskReply=redisCommand(conn,"get msk");
		//2. if found then unserialize pub,msk
		if(pubReply&&(pubReply->type==REDIS_REPLY_STRING)
						&&mskReply&&(mskReply->type==REDIS_REPLY_STRING)){
				GByteArray* tmp1;
				tmp1 = g_byte_array_new();
				g_byte_array_set_size(tmp1,pubReply->len);
				memcpy(tmp1->data,pubReply->str,pubReply->len);
				(*pub)=bswabe_pub_unserialize(tmp1,1);

				GByteArray* tmp2;
				tmp2 = g_byte_array_new();
				g_byte_array_set_size(tmp2,mskReply->len);
				memcpy(tmp2->data,mskReply->str,mskReply->len);
				(*msk)=bswabe_msk_unserialize((*pub),tmp2,1);
				printf("found pub and msk\n");
				freeReplyObject(pubReply);
				freeReplyObject(mskReply);

		}else //3.if not found,then call setup() and save into redis
		{

				setup(pub,msk);
				GByteArray* pub_buf=bswabe_pub_serialize(*pub);
				redisReply* result=redisCommand(conn, "set pub %b",pub_buf->data,pub_buf->len);	
				if(result)
						freeReplyObject(result);

				GByteArray* msk_buf=bswabe_msk_serialize(*msk);
				result=redisCommand(conn, "set msk %b",msk_buf->data,msk_buf->len);	
				if(result)
						freeReplyObject(result);
				printf("not found pub and msk\n");
		}
		return 0;

}

int get_encrypted_msg(GByteArray**cph_buf,
				GByteArray**aes_buf)
{
		redisReply* cphReply=redisCommand(conn,"get cph_buf");
		redisReply* aesReply=redisCommand(conn,"get aes_buf");
		if(cphReply&&cphReply->type==REDIS_REPLY_STRING
						&&aesReply&&aesReply->type==REDIS_REPLY_STRING){
				(*cph_buf)= g_byte_array_new();
				g_byte_array_set_size((*cph_buf),cphReply->len);
				memcpy((*cph_buf)->data,cphReply->str,cphReply->len);

				(*aes_buf)=g_byte_array_new();
				g_byte_array_set_size((*aes_buf),aesReply->len);
				memcpy((*aes_buf)->data,aesReply->str,aesReply->len);

				freeReplyObject(cphReply);
				freeReplyObject(aesReply);
				printf("found cph_buf and aes_buf\n");
		}
		return 0;
}

int get_prv(bswabe_pub_t* pub,bswabe_msk_t*msk,
				char*uid,char*update_time,char **m_attrbutes,bswabe_prv_t**prv)
{
		//if no find user's prv then
		//keygen for user,save prv in redis
		//1. get the byte[] of prv from redis
		bswabe_prv_t* tmp_prv=0;
		redisReply* prvReply=redisCommand(conn,"get prv_%s_%s",uid,update_time);
		//2.if found then unserialize prv
		if(prvReply&&prvReply->type==REDIS_REPLY_STRING){
				GByteArray* tmp1;
				tmp1 = g_byte_array_new();
				g_byte_array_set_size(tmp1,prvReply->len);
				memcpy(tmp1->data,prvReply->str,prvReply->len);
				tmp_prv = bswabe_prv_unserialize(pub, tmp1, 1);
				freeReplyObject(prvReply);
				printf("found prv\n");
		}
		//3.if not found then call keygen(),gen prv,unserialize,  and save the byte[] into redis
		else{
				redisReply* oldKeys=redisCommand(conn,"keys prv_%s*",uid);
				if(oldKeys&&oldKeys->type==REDIS_REPLY_ARRAY){
					redisReply** element=oldKeys->element;
					size_t size=oldKeys->elements;
					int i;
					for(i=0;i<size;i++){
					printf("%s\n",oldKeys->element[i]->str);
					}
				}
				keygen(pub,msk,m_attrbutes,&tmp_prv);
				GByteArray*prv_buf=bswabe_prv_serialize(tmp_prv);
				redisReply* result=redisCommand(conn, "set prv_%s_%s %b",
											uid,update_time,prv_buf->data,prv_buf->len);
				if(result)
						freeReplyObject(result);
				printf("not found prv\n");
		}

		(*prv)=tmp_prv;
		return 0;

}


int setMsg(const char * msg){
		if(msg==0) {
				pbc_random_set_deterministic(0);
		}
		bswabe_pub_t*pub=0;
		bswabe_msk_t*msk=0;
		get_pub_and_msk(&pub,&msk);

		GByteArray*	cph_buf;
		GByteArray* aes_buf;

		if(msg!=NULL){
				size_t msg_len=strlen(msg);
				GByteArray* plt=g_byte_array_new();
				g_byte_array_set_size(plt,msg_len);
				memcpy(plt->data,msg,msg_len);
				enc(pub,msk,plt,&cph_buf,&aes_buf);
				redisReply* result;
				result=redisCommand(conn,"set cph_buf %b",cph_buf->data,cph_buf->len);
				if(result)
						freeReplyObject(result);

				result=redisCommand(conn,"set aes_buf %b",aes_buf->data,aes_buf->len);
				if(result)
						freeReplyObject(result);
				printf("set encrypted messge\n");
		}else
		{
				printf("set msg error: msg=null\n");
		}
		return 0;	

}
int getMsg(const char*uid,const char*update_time,char** attrs,char**result){
		bswabe_pub_t*pub=0;
		bswabe_msk_t*msk=0;
		get_pub_and_msk(&pub,&msk);

		GByteArray*	cph_buf;
		GByteArray* aes_buf;
		get_encrypted_msg(&cph_buf,&aes_buf);

		bswabe_prv_t*prv=0;
		get_prv(pub,msk,uid,update_time,attrs,&prv);
		

		char**tm=attrs;
		while((*tm)!=NULL)
		{	printf("%s*\n",*tm);
			tm++;
		}
		printf("here\n");
		GByteArray* ans=0;
		dec(pub,prv,aes_buf,cph_buf,&ans);
		printf("%d\n",ans->len);
		char*tmp=(char*)malloc(ans->len);
		strcpy(tmp,ans->data);
		(*result)=tmp;
		//spit_file("hhf.tmp",ans,1);
	
}


