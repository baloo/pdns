#include "../../../pdns/logger.hh"
#include "../../../pdns/dnsbackend.hh"
#include "../../../pdns/backends/gsql/gsqlbackend.hh"
#include "../../../modules/dlsobackend/dlsobackend_api.h"
#include "../../../modules/gsqlite3backend/gsqlite3backend.hh"
#include <sys/types.h>
#include <stdlib.h>


struct dlso_gsql {
	DNSBackend * module;
	bool in_error;
};

void release(void * ptr) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	if (handle) {
		delete handle->module;
		free(handle);
	}
}

bool lookup(void * ptr, const uint16_t qtype, uint8_t qlen, const char * qname, const struct sockaddr * client_ip, int32_t domain_id) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	if (!handle) {
		return false;
	}
	handle->in_error = false;

	struct QType type = QType(qtype);
	struct DNSName qname_ = DNSName(string(qname, qlen));
	try {
		handle->module->lookup(type, qname_, NULL, domain_id);
	} catch (const PDNSException &e) {
		handle->in_error = true;
	}

	return true;
}

bool list(void * ptr, uint8_t qlen, const char * qname, int32_t domain_id) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	if (!handle) {
		return false;
	}
	handle->in_error = false;

	struct DNSName qname_ = DNSName(string(qname, qlen));
	try {
		handle->module->list(qname_, domain_id, false);
	} catch (const PDNSException &e) {
		handle->in_error = true;
	}

	return true;
}

bool get(void * ptr, fill_cb_t cb, void * rr) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	if (handle->in_error) {
		return false;
	}
	struct DNSResourceRecord record;

	if (handle->module->get(record)) {
		struct resource_record resource_record;
		string qname = record.qname.toString();
		string content = record.content;

		resource_record.qtype = record.qtype.getCode();
		resource_record.qname = qname.c_str();
		resource_record.qname_len = qname.size();
		resource_record.content = content.c_str();
		resource_record.content_len = content.size();
		resource_record.ttl = record.ttl;
		resource_record.auth = record.auth;
		resource_record.scopeMask = record.scopeMask;
		resource_record.domain_id = record.domain_id;

		cb(rr, &resource_record);

		return true;
	} else {
		return false;
	}
}

bool get_tsig_key(void * ptr, uint8_t qlen, const char * qname_, uint8_t alg_len, const char * alg_, fill_tsig_key_cb_t cb, void * content) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	DNSName alg = DNSName(string(alg_, alg_len));
	// TODO content should be rewritten

	return handle->module->getTSIGKey(qname, &alg, (string *) content);
}

bool set_tsig_key(void * ptr, uint8_t qlen, const char * qname_, uint8_t alg_len, const char * alg_, uint8_t content_len, const char * content_) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	DNSName alg = DNSName(string(alg_, alg_len));
	string content = string(content_, content_len);

	return handle->module->setTSIGKey(qname, alg, content);
}

bool get_meta(void * ptr, uint8_t qlen, const char * qname_, uint8_t kind_len, const char * kind_, fill_meta_cb_t cb, const void * meta) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	string kind = string(kind_, kind_len);
	std::vector<std::string>* meta_ = (std::vector<std::string> *)meta;
	// TODO meta should be reparsed

	if (handle->module->getDomainMetadata(qname, kind, *meta_)) {
		return true;
	} else {
		return false;
	}
}

bool set_meta(void * ptr, uint8_t qlen, const char * qname_, uint8_t kind_len, const char * kind_, uint8_t value_len, struct dns_value * values) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	string kind = string(kind_, kind_len);

	for (int i=0; i<value_len; i++) {
		string value = string(values[i].value, values[i].value_len);
		if (!handle->module->setDomainMetadataOne(qname, kind, value)) {
			return false;
		}
	}

	return true;
}

bool remove_empty_non_terminals(void * ptr, uint32_t domain_id) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	set<DNSName> insert;
	set<DNSName> erase;

	return handle->module->updateEmptyNonTerminals(domain_id, insert, erase, true);
}

bool update_empty_non_terminals(void * ptr, uint32_t domain_id, uint8_t qlen, const char * qname, bool add) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;

	set<DNSName> empty;
	set<DNSName> values_set;

	DNSName value = DNSName(string(qname, qlen));
	values_set.insert(value);

	if (add) {
		return handle->module->updateEmptyNonTerminals(domain_id, values_set, empty, false);
	} else {
		return handle->module->updateEmptyNonTerminals(domain_id, empty, values_set, false);
	}
}

bool get_domain_info(void * ptr, uint8_t qlen, const char * qname_, fill_domain_info_cb_t cb, void * di) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	DomainInfo my_di;
	struct domain_info info;

	if (handle->module->getDomainInfo(qname, my_di)) {
		info.id = my_di.id;
		info.notified_serial = my_di.notified_serial;
		info.serial = my_di.serial;
		info.last_check = my_di.last_check;
		info.kind = my_di.kind;

		string zone = my_di.zone.toString();
		info.zone_len = zone.size();
		info.zone = zone.c_str();

		info.account_len = my_di.account.size();
		info.account = my_di.account.c_str();

		info.master_len = my_di.masters.size();

		struct dns_value * masters = (struct dns_value *) malloc(sizeof(struct dns_value) * info.master_len);
		if (masters == NULL) {
			return false;
		}

		for (int i=0; i < info.master_len; i++) {
			masters[i].value_len = my_di.masters[i].size();
			masters[i].value = my_di.masters[i].c_str();
		}
		info.masters = masters;

		cb(di, &info);
		return true;
	} else {
		return false;
	}
}

bool add_domain_key(void * ptr, uint8_t qlen, const char * qname_, struct dnskey * dnskey, int64_t *id) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));
	DNSBackend::KeyData key;

	key.id = dnskey->id;
	key.flags = dnskey->flags;
	key.active = dnskey->active;
	key.content = string(dnskey->data, dnskey->data_len);

	return handle->module->addDomainKey(qname, key, *id);
}

bool get_domain_keys(void * ptr, uint8_t qlen, const char * qname_, fill_key_cb_t cb, const void * keys_) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qlen));

	std::vector<DNSBackend::KeyData> keys;

	if (handle->module->getDomainKeys(qname, keys)) {
		for (DNSBackend::KeyData key: keys) {
			struct dnskey dnskey;

			dnskey.id = key.id;
			dnskey.flags = key.flags;
			dnskey.active = key.active;
			dnskey.data = key.content.c_str();
			dnskey.data_len = key.content.size();

			cb(keys_, &dnskey);
		}
		return true;
	} else {
		return false;
	}
}

bool get_before_after(void * ptr, uint32_t domain_id,
		uint8_t qname_len, const char * qname_,
		uint8_t unhashed_len, const char * unhashed_,
		uint8_t before_len, const char * before_,
		uint8_t after_len, const char * after_,
		fill_before_after_cb_t cb, void * beforeAfter) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qname_len));
	DNSName unhashed;
	if (unhashed_len > 0) {
		unhashed = DNSName(string(unhashed_, unhashed_len));
	}
	DNSName before;
	if (before_len > 0) {
		before = DNSName(string(before_, before_len));
	}
	DNSName after;
	if (after_len > 0) {
		after = DNSName(string(after_, after_len));
	}

	if (handle->module->getBeforeAndAfterNamesAbsolute(domain_id, qname, unhashed, before, after)) {
		//cout << "get_before_after before:" << before.wirelength() << endl;
		//cout << "get_before_after after:" << after.wirelength() << endl;
		string unhashed_;
		string before_;
		string after_;

		if (!unhashed.empty()) {
			unhashed_ = unhashed.toString();
		}
		if (!before.empty()) {
			before_ = before.toString();
		}
		if (!after.empty()) {
			after_ = after.toString();
		}

		cb(beforeAfter, unhashed_.size(), unhashed_.c_str(), before_.size(), before_.c_str(), after_.size(), after_.c_str());
		return true;
	} else {
		//cout << "nope getBeforeAndAfterNamesAbsolute" << endl;
		return false;
	}
}

bool update_dnssec_order_name_and_auth(void * ptr, uint32_t domain_id,
		uint8_t qname_len, const char * qname_,
		uint8_t ordername_len, const char * ordername_,
		bool auth, uint16_t qtype) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;

	DNSName qname = DNSName(string(qname_, qname_len));
	DNSName ordername;
	if (ordername_len) {
		ordername = DNSName(string(ordername_, ordername_len));
	}

	return handle->module->updateDNSSECOrderNameAndAuth(domain_id, qname, ordername, auth, qtype);
}

bool start_transaction(void * ptr, uint32_t domain_id,
		uint8_t qname_len, const char * qname_) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	DNSName qname = DNSName(string(qname_, qname_len));
	return handle->module->startTransaction(qname, domain_id);
}

bool abort_transaction(void * ptr) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	return handle->module->abortTransaction();
}

bool commit_transaction(void * ptr) {
	struct dlso_gsql * handle = (struct dlso_gsql *) ptr;
	return handle->module->commitTransaction();
}
extern "C" bool pdns_dlso_register(struct lib_so_api* api, bool dnssec, const char * args) {
	struct dlso_gsql * gsql = (struct dlso_gsql *) malloc(sizeof(struct dlso_gsql));
	if (gsql == NULL) {
		return false;
	}

	// First load the sqlite3 backend, and declare arguments
	gSQLite3Factory * factory;
	try {
		factory = new gSQLite3Factory("gsqlite3");
		factory->declareArguments();
	} catch (const PDNSException &e) {
		free(gsql);
		return false;
	}

	// Then, loads configuration from file (gsqlite3 arguments are
	// only parsed after being declared)
	string s_programname="pdns";
	if(arg()["config-name"]!="")
		s_programname+="-"+arg()["config-name"];
	string configname=arg()["config-dir"]+"/"+s_programname+"-sqlite3.conf";
	L << Logger::Info << "Config name: " << configname << endl;
	arg().laxFile(configname.c_str());

	L << Logger::Info << "dlsotest is going to open sqlite: " << arg()["gsqlite3-database"] << endl;
	// And finaly build the module
	try {
		gsql->module = factory->make();
	} catch (const PDNSException &e) {
		free(gsql);
		return false;
	}
	if (gsql->module == NULL) {
		free(gsql);
		return false;
	}

	api->handle = gsql;
	api->release = release;

	api->lookup = lookup;
	api->get = get;
	api->list = list;

	api->get_tsig_key = get_tsig_key;
	api->set_tsig_key = set_tsig_key;

	api->get_meta = get_meta;
	api->set_meta = set_meta;

	api->update_empty_non_terminals = update_empty_non_terminals;
	api->remove_empty_non_terminals = remove_empty_non_terminals;

	api->get_domain_info = get_domain_info;

	api->get_domain_keys = get_domain_keys;
	api->add_domain_key = add_domain_key;

	api->get_before_after = get_before_after;
	api->update_dnssec_order_name_and_auth = update_dnssec_order_name_and_auth;

	api->start_transaction = start_transaction;
	api->commit_transaction = commit_transaction;
	api->abort_transaction = abort_transaction;

	return true;
}
