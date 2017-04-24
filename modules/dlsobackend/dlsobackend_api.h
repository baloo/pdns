#include <sys/types.h>
#include <stdint.h>


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


typedef void (*fill_cb_t)(void *, const struct resource_record *);
typedef void (*fill_key_cb_t)(void *, const struct dnskey *);
typedef void (*fill_tsig_key_cb_t)(void *, uint8_t key_len, const char * key);
typedef void (*fill_meta_cb_t)(void *, uint8_t value_len, const struct dns_meta_value *);
typedef void (*fill_metas_cb_t)(void *, uint8_t meta_len, const struct dns_meta *);
typedef void (*fill_before_after_t)(void *, uint8_t before_len, const char * before, uint8_t after_len, const char * after);

struct lib_so_api {
   void * handle;
   void (*release)(void * handle);

   bool (*lookup)(void * handle, const uint16_t qtype, uint8_t qlen, const char * qname, const struct sockaddr * client_ip);
   bool (*list)(void * handle, uint8_t qlen, const char * qname);
   bool (*get)(void * handle, fill_cb_t cb, void * rr);

   bool (*get_domain_keys)(void * handle, uint8_t qlen, const char * qname, fill_key_cb_t cb, void * keys);
   bool (*get_metas)(void * handle, uint8_t qlen, const char * qname, fill_metas_cb_t cb, void * metas);
   bool (*get_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, fill_meta_cb_t cb, void * meta);

   bool (*get_before_after)(void * handle, uint32_t domain_id, uint8_t qlen, const char * qname, fill_before_after_t cb, void * beforeAfter);
   bool (*get_tsig_key)(void * handle, uint8_t qlen, const char * qname, uint8_t alg_len, const char * alg, fill_tsig_key_cb_t cb, void * content);
};

typedef bool (*dlso_register_t)(struct lib_so_api* api, bool dnssec, const char * args);

