#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>



struct resource_record {
  uint16_t qtype;
  const char * qname;
  uint32_t qname_len;
  const char * content;
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

struct dns_value {
  uint8_t value_len;
  const char * value;
};

struct dns_meta {
  uint8_t property_len;
  char * property;
  uint8_t value_len;
  const struct dns_value * values;
};

#define DOMAIN_INFO_KIND_MASTER 0
#define DOMAIN_INFO_KIND_SLAVE 1
#define DOMAIN_INFO_KIND_NATIVE 2

struct domain_info {
  uint32_t id;
  uint32_t serial;
  uint32_t notified_serial;
  time_t last_check;
  uint8_t kind;
  uint8_t zone_len;
  uint8_t master_len;
  uint8_t account_len;
  const char * zone;
  const struct dns_value * masters;
  const char * account;
};

typedef void (*fill_cb_t)(const void *, const struct resource_record *);
typedef void (*fill_key_cb_t)(const void *, const struct dnskey *);
typedef void (*fill_tsig_key_cb_t)(const void *, uint8_t key_len, const char * key);
typedef void (*fill_meta_cb_t)(const void *, uint8_t value_len, const struct dns_value *);
typedef void (*fill_metas_cb_t)(const void *, uint8_t meta_len, const struct dns_meta *);
typedef void (*fill_before_after_t)(const void *, uint8_t unhashed_len, const char * unhashed, uint8_t before_len, const char * before, uint8_t after_len, const char * after);
typedef void (*fill_domain_info_t)(const void *, struct domain_info * di);

struct lib_so_api {
  void * handle;
  void (*release)(void * handle);

  bool (*lookup)(void * handle, const uint16_t qtype, uint8_t qlen, const char * qname, const struct sockaddr * client_ip);
  bool (*list)(void * handle, uint8_t qlen, const char * qname, int32_t domain_id);
  bool (*get)(void * handle, fill_cb_t cb, void * rr);

  bool (*get_domain_keys)(void * handle, uint8_t qlen, const char * qname, fill_key_cb_t cb, const void * keys);
  bool (*add_domain_key)(void * handle, uint8_t qlen, const char * qname, struct dnskey * key, int64_t *id);

  bool (*get_metas)(void * handle, uint8_t qlen, const char * qname, fill_metas_cb_t cb, const void * metas);
  bool (*get_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, fill_meta_cb_t cb, const void * meta);
  bool (*set_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, uint8_t value_len, struct dns_value * values);

  bool (*get_before_after)(void * handle, uint32_t domain_id,
                           uint8_t qlen, const char * qname,
                           uint8_t unhashed_len, const char * unhashed_name,
                           uint8_t before_len, const char * before_name,
                           uint8_t after_len, const char * after_name,
                           fill_before_after_t cb, void * beforeAfter);

  bool (*get_tsig_key)(void * handle, uint8_t qlen, const char * qname, uint8_t alg_len, const char * alg, fill_tsig_key_cb_t cb, void * content);
  bool (*set_tsig_key)(void * handle, uint8_t qlen, const char * qname, uint8_t alg_len, const char * alg, uint8_t content_len, const char * content);

  bool (*update_dnssec_order_name_and_auth)(void * handle, uint32_t domain_id,
                                            uint8_t qlen, const char * qname,
                                            uint8_t ordername_len, const char * ordername,
                                            bool auth, uint16_t qtype);

  bool (*update_empty_non_terminals)(void * handle, uint32_t domain_id,
                                     uint8_t qlen, const char * qname,
                                     bool add);
  bool (*remove_empty_non_terminals)(void * handle, uint32_t domain_id);

  bool (*get_domain_info)(void * handle, uint8_t qlen, const char * qname, fill_domain_info_t cb, void * di);

  bool (*start_transaction)(void * handle, uint32_t domain_id, uint8_t qlen, const char * qname);
  bool (*commit_transaction)(void * handle);
  bool (*abort_transaction)(void * handle);


};

typedef bool (*dlso_register_t)(struct lib_so_api* api, bool dnssec, const char * args);

