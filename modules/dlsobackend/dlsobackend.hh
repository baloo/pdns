/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef REMOTEBACKEND_REMOTEBACKEND_HH

#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>

#include <string>
#include "pdns/arguments.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/logger.hh"
#include "pdns/namespaces.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sstuff.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/lock.hh"

struct resource_record {
  uint16_t qtype;
  char * qname;
  uint32_t qname_len;
  char * content;
  uint32_t content_len;
  uint32_t ttl;
  bool auth;
  uint8_t scopeMask;
  uint32_t domain_id;
};

struct dnskey {
  uint32_t id;
  uint16_t flags;
  bool active;
  uint16_t data_len;
  const char * data;
};

struct dns_meta_value {
  uint8_t value_len;
  char * value;
};

struct dns_meta {
  uint8_t property_len;
  char * property;
  uint8_t value_len;
  const struct dns_meta_value * values;
};

struct before_after_t;

typedef void (*fill_cb_t)(DNSResourceRecord *, const struct resource_record *);
typedef void (*fill_key_cb_t)(std::vector<DNSBackend::KeyData>*, const struct dnskey *);
typedef void (*fill_tsig_key_cb_t)(std::string*, uint8_t key_len, const char * key);
typedef void (*fill_meta_cb_t)(std::vector<std::string>*, uint8_t value_len, const struct dns_meta_value *);
typedef void (*fill_metas_cb_t)(std::map<std::string, std::vector<std::string>>*, uint8_t meta_len, const struct dns_meta *);
typedef void (*fill_before_after_t)(struct before_after_t *, uint8_t before_len, const char * before, uint8_t after_len, const char * after);

struct lib_so_api {
   void * (*new_)(bool dnssec, const char * args);
   void (*free_)(void *);

   bool (*lookup)(void * handle, const uint16_t qtype, uint8_t qlen, const char * qname, const struct sockaddr * client_ip);
   bool (*list)(void * handle, uint8_t qlen, const char * qname);
   bool (*get)(void * handle, fill_cb_t cb, void * rr);

   bool (*get_domain_keys)(void * handle, uint8_t qlen, const char * qname, fill_key_cb_t cb, void * keys);
   bool (*get_metas)(void * handle, uint8_t qlen, const char * qname, fill_metas_cb_t cb, void * metas);
   bool (*get_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, fill_meta_cb_t cb, void * meta);

   bool (*get_before_after)(void * handle, uint32_t domain_id, uint8_t qlen, const char * qname, fill_before_after_t cb, void * beforeAfter);
   bool (*get_tsig_key)(void * handle, uint8_t qlen, const char * qname, uint8_t alg_len, const char * alg, fill_tsig_key_cb_t cb, void * content);

};

class DlsoBackend : public DNSBackend
{
public:
  DlsoBackend(const std::string &suffix="");
  ~DlsoBackend();

  //static DNSBackend *maker();

  void lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  bool get(DNSResourceRecord &rr);
  bool list(const DNSName& target, int domain_id, bool include_disabled=false);

  // the DNSSEC related (getDomainMetadata has broader uses too)
  virtual bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta);
  virtual bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys);
  virtual bool removeDomainKey(const DNSName& name, unsigned int id);
  virtual bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id);
  virtual bool activateDomainKey(const DNSName& name, unsigned int id);
  virtual bool deactivateDomainKey(const DNSName& name, unsigned int id);
  virtual bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content);
  virtual bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  virtual bool deleteTSIGKey(const DNSName& name);
  virtual bool getTSIGKeys(std::vector< struct TSIGKey > &keys);
  virtual bool doesDNSSEC();

  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after);
  // end of DNSSEC

private:
  int build();
  void * dlhandle;
  void * handle;
  bool d_dnssec;

  bool in_query;

  struct lib_so_api api;
};


#endif
