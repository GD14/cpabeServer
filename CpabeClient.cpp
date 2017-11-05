#include "Cpabe.h"  
#include <config.h>  
#include <transport/TSocket.h>  
#include <transport/TBufferTransports.h>  
#include <protocol/TCompactProtocol.h>  
#include <sys/time.h>
using namespace apache::thrift;  
using namespace apache::thrift::protocol;  
using namespace apache::thrift::transport;  
using boost::shared_ptr;  
using namespace std; 
int main(int argc, char **argv) {  
        boost::shared_ptr<TSocket> socket(new TSocket("localhost", 9090));  
        boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));  
        boost::shared_ptr<TProtocol> protocol(new TCompactProtocol(transport));  
  
        transport->open();  
  
		map<string,string> attr;
		attr.insert(pair <string,string>("uid","123"));
		attr.insert(pair <string,string>("update","123"));

        CpabeClient client(protocol);  
		string result;
  
		struct timeval myst,myend;
		gettimeofday(&myst,NULL);	
        client.getMessage(result,attr); 
  		gettimeofday(&myend,NULL);
		double usetime;
		usetime=1000000.0*(myend.tv_sec-myst.tv_sec)+myend.tv_usec-myst.tv_usec;
		printf("the time: %.2fus\n",usetime/1000);
        transport->close();  
        return 0;  
}  
