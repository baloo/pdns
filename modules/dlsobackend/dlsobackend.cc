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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dlsobackend.hh"
#include <dlfcn.h>

static const char *kBackendId = "[DlsoBackend]";

/**
 * Standard ctor and dtor
 */
DlsoBackend::DlsoBackend(const std::string &suffix)
{
  setArgPrefix("dlso"+suffix);

  std::string libpath = getArg("path");
  std::string args = getArg("args");

  this->d_dnssec = mustDo("dnssec");
  this->in_query = false;

  this->dlhandle = dlopen(libpath.c_str(), RTLD_LAZY);

  if (!this->dlhandle) {
      throw PDNSException("Unable to load library: " + libpath);
  }

  dlso_register_t register_api = (dlso_register_t) dlsym(this->dlhandle, "pdns_dlso_register");
  if (register_api == NULL) {
    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, no pdns_dlso_register symbol exposed");
  }

  memset(&this->api, 0, sizeof(this->api));

  bool success = register_api(&this->api, this->d_dnssec, args.c_str());
  if (!success) {
    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, pdns_dlso_register returned false");
  }

  // Sanity checks
  if (this->api.get == NULL) {
    if (this->api.release != NULL)
      this->api.release(this->api.handle);

    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, lib did not register a mandatory get function");
  }
  if (this->api.lookup == NULL) {
    if (this->api.release != NULL)
      this->api.release(this->api.handle);

    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, lib did not register a mandatory lookup function");
  }
}

DlsoBackend::~DlsoBackend() {
  if (this->api.release != NULL)
    this->api.release(this->api.handle);
  dlclose(this->dlhandle);
}

/**
 * The functions here are just remote json stubs that send and receive the method call
 * data is mainly left alone, some defaults are assumed.
 */
void DlsoBackend::lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p, int zoneId) {
  if(in_query)
    throw PDNSException("Attempt to lookup while one running");

  string qname = qdomain.toString();
  bool success;

  if (pkt_p != NULL) {
    ComboAddress edns_or_resolver_ip = pkt_p->getRealRemote().getNetwork();
    success = api.lookup(api.handle, qtype.getCode(), qname.size(), qname.c_str(), (sockaddr*) &edns_or_resolver_ip.sin4);
  } else {
    success = api.lookup(api.handle, qtype.getCode(), qname.size(), qname.c_str(), NULL);
  }

  if (!success)
    throw PDNSException("Backend failed");
}

bool DlsoBackend::list(const DNSName& target, int domain_id, bool include_disabled) {
  if (api.list == NULL)
    return false;

  string qname = target.toString();
  bool success;

  success = api.list(api.handle, qname.size(), qname.c_str());

  if (!success)
    throw PDNSException("Backend failed");

  return success;
}

void fill_cb(void * ptr, const struct resource_record *record) {
  DNSResourceRecord *rr = (DNSResourceRecord *) ptr;
  rr->qtype = record->qtype;
  rr->qname = DNSName(string(record->qname, record->qname_len));
  rr->qclass = QClass::IN;
  rr->content = string(record->content, record->content_len);
  rr->ttl = record->ttl;
  rr->auth = record->auth;
  rr->scopeMask = record->scopeMask;
  rr->domain_id = record->domain_id;
}

bool DlsoBackend::get(DNSResourceRecord &rr) {
  bool success = api.get(api.handle, fill_cb, &rr);

  if (!success) {
    in_query = false;
    return false;
  }

  return true;
}

void fill_meta_cb(void * ptr, uint8_t value_len, const struct dns_meta_value * values) {
  std::vector<std::string>* meta = (std::vector<std::string>*) ptr;
  for (uint8_t i=0; i<value_len; i++) {
    const struct dns_meta_value *value = &values[i];
    string value_s = string(value->value, value->value_len);

    (*meta).push_back(value_s);
  }
}

void fill_metas_cb(void * ptr, uint8_t meta_len, const struct dns_meta * c_metas) {
  std::map<std::string, std::vector<std::string>>* metas = (std::map<std::string, std::vector<std::string>>*) ptr;
  for (uint8_t i=0; i<meta_len; i++) {
    const struct dns_meta *meta = &c_metas[i];
    string property = string(meta->property, meta->property_len);
    const struct dns_meta_value * values = meta->values;

    fill_meta_cb(&(*metas)[property], meta->value_len, values);
  }
}

bool DlsoBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& metas) {
  if (d_dnssec == false) return false;
  if (api.get_metas == NULL) return false;

  metas.clear();

  string qname = name.toString();
  return api.get_metas(api.handle, qname.size(), qname.c_str(), fill_metas_cb, &metas);
}

bool DlsoBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) {
  if (d_dnssec == false) return false;
  if (api.get_meta == NULL) return false;

  meta.clear();

  string qname = name.toString();
  return api.get_meta(api.handle, qname.size(), qname.c_str(), kind.size(), kind.c_str(), fill_meta_cb, &meta);
}

bool DlsoBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) {
  return false;
}

void fill_key_cb(void * ptr, const struct dnskey *dnskey) {
  std::vector<DNSBackend::KeyData>* keys = (std::vector<DNSBackend::KeyData> *) ptr;
  DNSBackend::KeyData key;
  key.id = dnskey->id;
  key.flags = dnskey->flags;
  key.active = dnskey->active;
  key.content = string(dnskey->data, dnskey->data_len);
  keys->push_back(key);
}

bool DlsoBackend::getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys) {
  // no point doing dnssec if it's not supported
  if (d_dnssec == false) return false;
  if (api.get_domain_keys == NULL) return false;

  keys.clear();

  string qname = name.toString();
  return api.get_domain_keys(api.handle, qname.size(), qname.c_str(), fill_key_cb, &keys);
}


bool DlsoBackend::removeDomainKey(const DNSName& name, unsigned int id) {
  return false;
}

bool DlsoBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) {
  return false;
}

bool DlsoBackend::activateDomainKey(const DNSName& name, unsigned int id) {
  return false;
}

bool DlsoBackend::deactivateDomainKey(const DNSName& name, unsigned int id) {
  return false;
}

bool DlsoBackend::doesDNSSEC() {
  return d_dnssec;
}

void fill_tsig_key(void * ptr, uint8_t key_len, const char * key) {
  std::string* content = (std::string*) ptr;
  content->operator=(string(key, key_len));
}

bool DlsoBackend::getTSIGKey(const DNSName& name, DNSName* algorithm, std::string* content) {
  if (api.get_tsig_key == NULL) return false;

  string qname = name.toString();
  string alg = algorithm->toString();

  return api.get_tsig_key(api.handle, qname.size(), qname.c_str(), alg.size(), alg.c_str(), fill_tsig_key, content);
}

bool DlsoBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const std::string& content) {
  return false;
}

bool DlsoBackend::deleteTSIGKey(const DNSName& name) {
  return false;
}

bool DlsoBackend::getTSIGKeys(std::vector<struct TSIGKey>& keys) {
  return false;
}

struct before_after_t {
  DNSName* before;
  DNSName* after;
};

void fill_before_after(void * ptr, uint8_t before_len, const char * before, uint8_t after_len, const char * after) {
  struct before_after_t * ba = (struct before_after_t *) ptr;
  (*ba->before).clear();
  (*ba->before)+= DNSName(string(before, before_len));
  (*ba->after).clear();
  (*ba->after )+= DNSName(string(after, after_len));
}

bool DlsoBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) {
  if (d_dnssec == false) return false;
  if (api.get_before_after == NULL) return false;

  string qname_ = qname.toString();
  struct before_after_t ba;
  ba.before = &before;
  ba.after  = &after;

  return api.get_before_after(api.handle, id, qname_.size(), qname_.c_str(), fill_before_after, &ba);
}

class DlsoBackendFactory : public BackendFactory
{
  public:
      DlsoBackendFactory() : BackendFactory("dlso") {}

      void declareArguments(const std::string &suffix="")
      {
          declare(suffix,"dnssec","Enable dnssec support","no");
          declare(suffix,"path","Path","");
          declare(suffix,"args","args","");
      }

      DNSBackend *make(const std::string &suffix="")
      {
         return new DlsoBackend(suffix);
      }
};

class DlsoLoader
{
public:
    DlsoLoader();
};


DlsoLoader::DlsoLoader() {
    BackendMakers().report(new DlsoBackendFactory);
    L << Logger::Info << kBackendId << "This is the dlso backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
}

static DlsoLoader dlsoloader;
