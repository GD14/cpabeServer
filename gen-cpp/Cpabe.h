/**
 * Autogenerated by Thrift Compiler (0.10.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef Cpabe_H
#define Cpabe_H

#include <thrift/TDispatchProcessor.h>
#include <thrift/async/TConcurrentClientSyncInfo.h>
#include "cpabe_types.h"



#ifdef _WIN32
  #pragma warning( push )
  #pragma warning (disable : 4250 ) //inheriting methods via dominance 
#endif

class CpabeIf {
 public:
  virtual ~CpabeIf() {}
  virtual void getMessage(std::string& _return, const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs) = 0;
  virtual bool setMessage(const std::string& msg) = 0;
};

class CpabeIfFactory {
 public:
  typedef CpabeIf Handler;

  virtual ~CpabeIfFactory() {}

  virtual CpabeIf* getHandler(const ::apache::thrift::TConnectionInfo& connInfo) = 0;
  virtual void releaseHandler(CpabeIf* /* handler */) = 0;
};

class CpabeIfSingletonFactory : virtual public CpabeIfFactory {
 public:
  CpabeIfSingletonFactory(const boost::shared_ptr<CpabeIf>& iface) : iface_(iface) {}
  virtual ~CpabeIfSingletonFactory() {}

  virtual CpabeIf* getHandler(const ::apache::thrift::TConnectionInfo&) {
    return iface_.get();
  }
  virtual void releaseHandler(CpabeIf* /* handler */) {}

 protected:
  boost::shared_ptr<CpabeIf> iface_;
};

class CpabeNull : virtual public CpabeIf {
 public:
  virtual ~CpabeNull() {}
  void getMessage(std::string& /* _return */, const std::string& /* uid */, const std::string& /* update_time */, const std::vector<std::string> & /* attrs */) {
    return;
  }
  bool setMessage(const std::string& /* msg */) {
    bool _return = false;
    return _return;
  }
};

typedef struct _Cpabe_getMessage_args__isset {
  _Cpabe_getMessage_args__isset() : uid(false), update_time(false), attrs(false) {}
  bool uid :1;
  bool update_time :1;
  bool attrs :1;
} _Cpabe_getMessage_args__isset;

class Cpabe_getMessage_args {
 public:

  Cpabe_getMessage_args(const Cpabe_getMessage_args&);
  Cpabe_getMessage_args& operator=(const Cpabe_getMessage_args&);
  Cpabe_getMessage_args() : uid(), update_time() {
  }

  virtual ~Cpabe_getMessage_args() throw();
  std::string uid;
  std::string update_time;
  std::vector<std::string>  attrs;

  _Cpabe_getMessage_args__isset __isset;

  void __set_uid(const std::string& val);

  void __set_update_time(const std::string& val);

  void __set_attrs(const std::vector<std::string> & val);

  bool operator == (const Cpabe_getMessage_args & rhs) const
  {
    if (!(uid == rhs.uid))
      return false;
    if (!(update_time == rhs.update_time))
      return false;
    if (!(attrs == rhs.attrs))
      return false;
    return true;
  }
  bool operator != (const Cpabe_getMessage_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const Cpabe_getMessage_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class Cpabe_getMessage_pargs {
 public:


  virtual ~Cpabe_getMessage_pargs() throw();
  const std::string* uid;
  const std::string* update_time;
  const std::vector<std::string> * attrs;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _Cpabe_getMessage_result__isset {
  _Cpabe_getMessage_result__isset() : success(false) {}
  bool success :1;
} _Cpabe_getMessage_result__isset;

class Cpabe_getMessage_result {
 public:

  Cpabe_getMessage_result(const Cpabe_getMessage_result&);
  Cpabe_getMessage_result& operator=(const Cpabe_getMessage_result&);
  Cpabe_getMessage_result() : success() {
  }

  virtual ~Cpabe_getMessage_result() throw();
  std::string success;

  _Cpabe_getMessage_result__isset __isset;

  void __set_success(const std::string& val);

  bool operator == (const Cpabe_getMessage_result & rhs) const
  {
    if (!(success == rhs.success))
      return false;
    return true;
  }
  bool operator != (const Cpabe_getMessage_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const Cpabe_getMessage_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _Cpabe_getMessage_presult__isset {
  _Cpabe_getMessage_presult__isset() : success(false) {}
  bool success :1;
} _Cpabe_getMessage_presult__isset;

class Cpabe_getMessage_presult {
 public:


  virtual ~Cpabe_getMessage_presult() throw();
  std::string* success;

  _Cpabe_getMessage_presult__isset __isset;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

typedef struct _Cpabe_setMessage_args__isset {
  _Cpabe_setMessage_args__isset() : msg(false) {}
  bool msg :1;
} _Cpabe_setMessage_args__isset;

class Cpabe_setMessage_args {
 public:

  Cpabe_setMessage_args(const Cpabe_setMessage_args&);
  Cpabe_setMessage_args& operator=(const Cpabe_setMessage_args&);
  Cpabe_setMessage_args() : msg() {
  }

  virtual ~Cpabe_setMessage_args() throw();
  std::string msg;

  _Cpabe_setMessage_args__isset __isset;

  void __set_msg(const std::string& val);

  bool operator == (const Cpabe_setMessage_args & rhs) const
  {
    if (!(msg == rhs.msg))
      return false;
    return true;
  }
  bool operator != (const Cpabe_setMessage_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const Cpabe_setMessage_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class Cpabe_setMessage_pargs {
 public:


  virtual ~Cpabe_setMessage_pargs() throw();
  const std::string* msg;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _Cpabe_setMessage_result__isset {
  _Cpabe_setMessage_result__isset() : success(false) {}
  bool success :1;
} _Cpabe_setMessage_result__isset;

class Cpabe_setMessage_result {
 public:

  Cpabe_setMessage_result(const Cpabe_setMessage_result&);
  Cpabe_setMessage_result& operator=(const Cpabe_setMessage_result&);
  Cpabe_setMessage_result() : success(0) {
  }

  virtual ~Cpabe_setMessage_result() throw();
  bool success;

  _Cpabe_setMessage_result__isset __isset;

  void __set_success(const bool val);

  bool operator == (const Cpabe_setMessage_result & rhs) const
  {
    if (!(success == rhs.success))
      return false;
    return true;
  }
  bool operator != (const Cpabe_setMessage_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const Cpabe_setMessage_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _Cpabe_setMessage_presult__isset {
  _Cpabe_setMessage_presult__isset() : success(false) {}
  bool success :1;
} _Cpabe_setMessage_presult__isset;

class Cpabe_setMessage_presult {
 public:


  virtual ~Cpabe_setMessage_presult() throw();
  bool* success;

  _Cpabe_setMessage_presult__isset __isset;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

class CpabeClient : virtual public CpabeIf {
 public:
  CpabeClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
    setProtocol(prot);
  }
  CpabeClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    setProtocol(iprot,oprot);
  }
 private:
  void setProtocol(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
  setProtocol(prot,prot);
  }
  void setProtocol(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    piprot_=iprot;
    poprot_=oprot;
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
 public:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void getMessage(std::string& _return, const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs);
  void send_getMessage(const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs);
  void recv_getMessage(std::string& _return);
  bool setMessage(const std::string& msg);
  void send_setMessage(const std::string& msg);
  bool recv_setMessage();
 protected:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
};

class CpabeProcessor : public ::apache::thrift::TDispatchProcessor {
 protected:
  boost::shared_ptr<CpabeIf> iface_;
  virtual bool dispatchCall(::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, const std::string& fname, int32_t seqid, void* callContext);
 private:
  typedef  void (CpabeProcessor::*ProcessFunction)(int32_t, ::apache::thrift::protocol::TProtocol*, ::apache::thrift::protocol::TProtocol*, void*);
  typedef std::map<std::string, ProcessFunction> ProcessMap;
  ProcessMap processMap_;
  void process_getMessage(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
  void process_setMessage(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
 public:
  CpabeProcessor(boost::shared_ptr<CpabeIf> iface) :
    iface_(iface) {
    processMap_["getMessage"] = &CpabeProcessor::process_getMessage;
    processMap_["setMessage"] = &CpabeProcessor::process_setMessage;
  }

  virtual ~CpabeProcessor() {}
};

class CpabeProcessorFactory : public ::apache::thrift::TProcessorFactory {
 public:
  CpabeProcessorFactory(const ::boost::shared_ptr< CpabeIfFactory >& handlerFactory) :
      handlerFactory_(handlerFactory) {}

  ::boost::shared_ptr< ::apache::thrift::TProcessor > getProcessor(const ::apache::thrift::TConnectionInfo& connInfo);

 protected:
  ::boost::shared_ptr< CpabeIfFactory > handlerFactory_;
};

class CpabeMultiface : virtual public CpabeIf {
 public:
  CpabeMultiface(std::vector<boost::shared_ptr<CpabeIf> >& ifaces) : ifaces_(ifaces) {
  }
  virtual ~CpabeMultiface() {}
 protected:
  std::vector<boost::shared_ptr<CpabeIf> > ifaces_;
  CpabeMultiface() {}
  void add(boost::shared_ptr<CpabeIf> iface) {
    ifaces_.push_back(iface);
  }
 public:
  void getMessage(std::string& _return, const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->getMessage(_return, uid, update_time, attrs);
    }
    ifaces_[i]->getMessage(_return, uid, update_time, attrs);
    return;
  }

  bool setMessage(const std::string& msg) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->setMessage(msg);
    }
    return ifaces_[i]->setMessage(msg);
  }

};

// The 'concurrent' client is a thread safe client that correctly handles
// out of order responses.  It is slower than the regular client, so should
// only be used when you need to share a connection among multiple threads
class CpabeConcurrentClient : virtual public CpabeIf {
 public:
  CpabeConcurrentClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
    setProtocol(prot);
  }
  CpabeConcurrentClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    setProtocol(iprot,oprot);
  }
 private:
  void setProtocol(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
  setProtocol(prot,prot);
  }
  void setProtocol(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    piprot_=iprot;
    poprot_=oprot;
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
 public:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void getMessage(std::string& _return, const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs);
  int32_t send_getMessage(const std::string& uid, const std::string& update_time, const std::vector<std::string> & attrs);
  void recv_getMessage(std::string& _return, const int32_t seqid);
  bool setMessage(const std::string& msg);
  int32_t send_setMessage(const std::string& msg);
  bool recv_setMessage(const int32_t seqid);
 protected:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
  ::apache::thrift::async::TConcurrentClientSyncInfo sync_;
};

#ifdef _WIN32
  #pragma warning( pop )
#endif



#endif
