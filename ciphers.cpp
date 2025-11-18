//	ciphers.cpp
//	实现加密参数的解析、使用等
#include "ciphers.h"
#include <pjlib-util/base64.h>
#include "config.h"
#include <fstream>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

namespace ccsua {

	//	验证证书child是否为parent签发
	inline bool cert_verify(X509* parent, X509* child) {
		assert(nullptr != parent && nullptr != child);
		//	返回1 表示验证成功
		int ret = X509_verify(child, X509_get_pubkey(parent));
		return 1 == ret;
	}
	inline EVP_PKEY* load_pubkey(const std::string& keypem) {
		EVP_PKEY* pkey = nullptr;
		BIO *bio = BIO_new(BIO_s_mem());
		BIO_write(bio, keypem.data(), keypem.size());
		
		pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
		assert(nullptr != pkey);
		BIO_free(bio);
		return pkey;
	}
	inline EVP_PKEY* load_privkey(const std::string& keypem) {
		EVP_PKEY* pkey = nullptr;
		BIO* bio = BIO_new(BIO_s_mem());
		BIO_write(bio, keypem.data(), keypem.size());

		pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
		assert(nullptr != pkey);
		BIO_free(bio);		
		return pkey;
	}
	inline std::string b64_encode(const std::string& in) {
		pj_status_t status = PJ_SUCCESS;
		int outlen = in.size() * 2;
		if (outlen < 10) outlen = 16;
		std::string ret;
		ret.resize(outlen);
		status = pj_base64_encode((const unsigned char *)in.data(), in.size(), (char *)ret.data(), &outlen);
		ret.resize(outlen);
		return ret;
	}
	inline std::string b64_decode(const std::string& in) {
		pj_status_t status = PJ_SUCCESS;
		int outlen = in.size() * 2;
		if (outlen < 10) outlen = 16;
		std::string ret;
		ret.resize(outlen);
		pj_str_t ins;
		ins.ptr = (char *)in.data();
		ins.slen = in.size();
		status = pj_base64_decode(&ins, (unsigned char *)ret.data(), &outlen);
		ret.resize(outlen);
		return ret;
	}
	void dump_hex(const unsigned char* pbuf, int buflen, const char* title) {
		char szLine[64];
		memset(szLine, 0, sizeof(szLine));
		printf("-------- Begin %s --------\n", title);;
		for (int i = 0; i < buflen; i++) {
			snprintf(&szLine[(i % 16) * 3], 64, "%02X ", pbuf[i]);
			if (0 == (i + 1) % 16) {
				printf("%s\n", szLine);
				memset(szLine, 0, sizeof(szLine));
			}
		}
		if (0 != buflen % 16) {
			printf("%s\n", szLine);
		}
		printf("-------- End %s --------\n", title);;
	}

	std::string sesscipher::_self_cert, sesscipher::_self_privkey;
	
	//	认证与验证相关. 先用openssl的模拟，后面再重新封装接口
	X509* sesscipher::_parent_cert_x509, * sesscipher::_self_cert_x509;
	EVP_PKEY* sesscipher::_self_pubkey_key, * sesscipher::_self_privkey_key;
	bool sesscipher::m_self_can_enc = false;

	sesscipher::sesscipher() : m_self_temp_pubkey(nullptr), m_self_temp_privkey(nullptr),
		m_remote_pubkey(nullptr), m_remote_temp_pubkey(nullptr), m_parent_cert_x509(nullptr),
		m_self_cert_x509(nullptr), m_self_pubkey_key(nullptr), m_self_privkey_key(nullptr), 
		m_role(E_UNDEFINED)
	{}
	sesscipher::~sesscipher() {
	}

	//	加载文本文件
	std::string load_txtfile(const std::string& fname) {
		std::string ret;
		char szTmp[4096];
		std::ifstream ins(fname, std::ios::in);
		ins.seekg(std::ios::beg);
		char ch;
		while (ins.get(ch)) {			
			ret.push_back(ch);
		}
		return ret;
	}
	//	加载自己的加密参数: 证书、证书链、产生临时公钥
	bool sesscipher::load_self() {
		//	加载前需要加载OpenSSL的库
		int ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
			| OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
		assert(1 == ret); //	加载失败则无法继续

		std::list<std::string> chainfile = config::get().root_cert_file();
		std::string selfcert = config::get().self_cert_file();
		std::string selfkey = config::get().self_priv_key();
		//	加载证书、私钥、证书链，并且做验证。
		_self_cert = load_txtfile(selfcert);
		_self_privkey = load_txtfile(selfkey);
		std::list<std::string> certchain;
		std::for_each(chainfile.begin(), chainfile.end(), [&](const std::string& fn) {
			std::string chain_cert = load_txtfile(fn);
			certchain.push_back(chain_cert);
			});
		//	解析证书和私钥，并验证匹配性
		BIO* bio = BIO_new(BIO_s_mem());
		BIO_write(bio, _self_cert.data(), _self_cert.size());
		//X509* selfcert509 = nullptr;
		_self_cert_x509 = PEM_read_bio_X509(bio, &_self_cert_x509, NULL, NULL);
		assert(nullptr != _self_cert_x509);
		BIO_free(bio);

		//	证书后续需要导出给对端，为方便直接使用，先在这儿将它转在b64
		_self_cert = b64_encode(_self_cert);

		//	读私钥
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, _self_privkey.data(), _self_privkey.size());
		_self_privkey_key = nullptr;
		_self_privkey_key = PEM_read_bio_PrivateKey(bio, &_self_privkey_key, NULL, NULL);
		assert(nullptr != _self_privkey_key);
		BIO_free(bio);
		
		//	验证证书与私钥的匹配性--私钥签名，公钥验签,,
		unsigned char szSign[256], szIn[32];
		size_t signlen = 256, inlen = 32;
		memset(szSign, 0, sizeof(szSign));
		memset(szIn, 0x0a, sizeof(szIn));
		EVP_PKEY_CTX* pctx = nullptr;
		
		EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
		EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, _self_privkey_key);
		EVP_DigestSignUpdate(mdctx, szIn, inlen);
		ret = EVP_DigestSignFinal(mdctx, szSign, &signlen);
		assert(1 == ret);
		EVP_MD_CTX_free(mdctx);
		//	自己的公钥需要保存
		_self_pubkey_key = X509_get_pubkey(_self_cert_x509);
		//	验签		
		pctx = nullptr;
		mdctx = EVP_MD_CTX_new();
		EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, _self_pubkey_key);
		EVP_DigestVerifyUpdate(mdctx, szIn, inlen);
		ret = EVP_DigestVerifyFinal(mdctx, szSign, signlen);
		EVP_PKEY_CTX_free(pctx);
		if (1 != ret) {
			//	自签自验失败:
			assert(false);
			return false;
		}

		//	加载证书链并依次验证
		X509* parcert = nullptr;
		bool certcheck = true;

		std::for_each(certchain.begin(), certchain.end(), [&](const std::string& cc) {
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, cc.data(), cc.size());
			X509* curcert = nullptr;
			curcert = PEM_read_bio_X509(bio, &curcert, NULL, NULL);
			if (nullptr == curcert) {
				assert(false);
				return; //	证书解析失败
			}
			if (nullptr != parcert) {
				//	如果父不为空，则需要用父的验证当前证书
				if (!cert_verify(parcert, curcert)) {
					certcheck = false;
					return;
				}
			}
			parcert = curcert;
			});
		if (!certcheck) {
			assert(false); //	证书链的验证失败
			return false;
		}
		_parent_cert_x509 = parcert;
		//	再用尾巴上的那个验证用户证书
		if (!cert_verify(parcert, _self_cert_x509)) {
			assert(false); //	用户证书使用签发证书验证失败
			return false;
		}
		m_self_can_enc = true;
		return true;
	}
	bool sesscipher::load_from_config() {
		m_parent_cert_x509 = _parent_cert_x509;
		m_self_cert_x509 = _self_cert_x509;
		m_self_pubkey_key = _self_pubkey_key;
		m_self_privkey_key = _self_privkey_key;

		m_self_cert = _self_cert;
		m_self_privkey = _self_privkey;
		//	自身的用户名信息从证书中获取到
		//	获取证书中携带的使用者信息
		const X509_NAME* nm = X509_get_subject_name(m_self_cert_x509);
		if (nullptr == nm) {
			assert(false);
			return false;
		}
		int ret = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);
		if (-1 == ret) {
			return false;
		}
		X509_NAME_ENTRY* ne = X509_NAME_get_entry(nm, ret);
		if (nullptr == ne) {
			return false;
		}
		ASN1_STRING* cn = X509_NAME_ENTRY_get_data(ne);
		if (nullptr == cn) {
			return false;
		}
		this->m_local_name = std::string((char*)cn->data, cn->length);

		return true;
	}
	//	产生本次通话的临时参数用于后续密钥协商
	bool sesscipher::generate_temp_para() {
		//	产生临时公私钥对，注意现在使用的是openssl模拟，它需要的椭圆曲线需要和自已的证书中匹配
		assert(nullptr != m_self_pubkey_key);
		const EC_GROUP* pgrp = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(m_self_pubkey_key));
		int nid = EC_GROUP_get_curve_name(pgrp);

		EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
		assert(nullptr != pctx);
		int ret = EVP_PKEY_keygen_init(pctx);
		assert(1 == ret);
		ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
		assert(1 == ret);

		EVP_PKEY* tmppkey = nullptr;
		ret = EVP_PKEY_generate(pctx, &tmppkey);
		assert(1 == ret);
		//	获取到临时公私钥句柄
		BIO* bio = BIO_new(BIO_s_mem());
		ret = PEM_write_bio_PUBKEY(bio, tmppkey);
		BUF_MEM* buffer = nullptr;
		BIO_get_mem_ptr(bio, &buffer);
		assert(nullptr != buffer);
		//	再将临时公钥导出为PEM格式
		m_self_tmp_pubkey.resize(buffer->length * 2);
		//	PEM格式需要base64编码
		int outlens = m_self_tmp_pubkey.size();
		pj_base64_encode((const unsigned char *)buffer->data, buffer->length, (char *)m_self_tmp_pubkey.data(), &outlens);
		m_self_tmp_pubkey.resize(outlens);

		//	openssl中的 EVP_PKEY 包含有公钥和私钥
		m_self_temp_privkey = tmppkey;
		m_self_temp_pubkey = tmppkey;
		
		return true;
	}

	bool sesscipher::parse_remote_by_rx_data(pjsip_rx_data* rdata) {
		
		pj_assert(nullptr != rdata && nullptr != rdata->msg_info.msg);
		//	rdata作为REQUEST时，METHOD必须是INVITE; rdata作为RESPONSE时，code必须是180或者200，METHOD必须为INVITE
		if (!is_invite_request(rdata) && /*!is_invite_180_response(rdata) && */!is_invite_ok_response(rdata)) {
			return false;
		}
		//	调用方会在合适的时候调用这，这里面只对数据做解析，不作方向的验证
		//	先查找 User-Agent 是否有，它并不可靠，可能会被任意设置，因此最关键的是需要获取到 SDP 中的协商参数
		/*	协商参数为附加到 sdp_session的属性列表中，现在暂定两个: cert 和 tpk,分别代表用户证书、用户临时公钥,
		* sdp中需要解析到这两个才行。这俩都使用 base64 编码
		*/

		//  获取User-Agent
		pjsip_user_agent_hdr* uac_user_agent_hdr = (pjsip_user_agent_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_USER_AGENT_UNIMP, NULL);
		const pj_str_t _ua_name = { (char*)"User-Agent", 10 };
		uac_user_agent_hdr = (pjsip_user_agent_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &_ua_name, NULL);
		if (nullptr == uac_user_agent_hdr) {
			//  无User-Agent头，对端可能为普通话机，对端可能为ccs securit voip,但是sip服务或者其它代理把user-agent给漏掉了
			//  因此这个判断并不一定合适，可能需要在接通的时候验证SDP信息更好
		}
		else {
			std::cout << "Remote User agent: " << std::string(uac_user_agent_hdr->hvalue.ptr, uac_user_agent_hdr->hvalue.slen) << std::endl;
		}

		if (nullptr == rdata->msg_info.msg->body->data || rdata->msg_info.msg->body->len < 256) {
			return false;
		}
		pjmedia_sdp_session* pmedia = nullptr;
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			(char*)rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len, &pmedia);
		if (PJ_SUCCESS != status) {
			pj_assert(PJ_SUCCESS == status);
			return false;
		}

		//	直接从 attr 中解析，如果没有相应的attr则不处理
		m_remote_cert.clear();
		m_remote_tmp_pubkey.clear();
		do {
			if (pmedia->attr_count < 1) {
				break; //	无属性，不处理
			}
			//	有属性，解析需要的: ucert 和 tmpkey
			for (int i = 0; i < pmedia->attr_count; i++) {
				std::string attname(pmedia->attr[i]->name.ptr, pmedia->attr[i]->name.slen);
				//	解析证书与公钥
				if ("ucert" == attname){
					this->m_remote_cert = std::string(pmedia->attr[i]->value.ptr, pmedia->attr[i]->value.slen);
					continue;
				}
				if ("tmpkey" == attname) {
					this->m_remote_tmp_pubkey = std::string(pmedia->attr[i]->value.ptr, pmedia->attr[i]->value.slen);
					continue;
				}
			}
		} while (false);

		//	s01. 获取到证书后需要验证证书
		if (m_remote_cert.empty() || m_remote_tmp_pubkey.empty())
		{
			return false;
		}
		
		//	上一步解析到的证书与临时公钥都是base64编码过的，需要先解码成PEM/DER等，注意SDP有回车符分割属性，因此
		//	PEM格式的证书、公钥虽然是字符串也不能直接用，统一都得做base64编解码
		m_remote_cert = b64_decode(m_remote_cert);
		m_remote_tmp_pubkey = b64_decode(m_remote_tmp_pubkey);

		//	解析对端参数先挪出去，增加代码的可测试性
		return parse_remote_paras();
	}

	//	解析对端的相关参数
	bool sesscipher::parse_remote_paras() {
		//	以下是使用openssl模拟的证书验证过程，使用P时其流程一致，调用的接口会有差异
		BIO* bio = BIO_new(BIO_s_mem());
		BIO_write(bio, m_remote_cert.data(), m_remote_cert.size());
		X509* remotecert509 = nullptr;
		remotecert509 = PEM_read_bio_X509(bio, &remotecert509, NULL, NULL);
		assert(nullptr != remotecert509);
		BIO_free(bio);
		int ret = cert_verify(m_parent_cert_x509, remotecert509);
		if (1 != ret) {
			assert(false);
			return false; //	有证书，但是使用证书链验证失败，不是同CA签发或者过期、未到使用时间等等
		}
		//	获取证书中携带的使用者信息
		const X509_NAME* nm = X509_get_subject_name(remotecert509);
		if (nullptr == nm) {
			assert(false);
			return false;
		}
		ret = X509_NAME_get_index_by_NID(nm, NID_commonName, -1);
		if (-1 == ret) {
			return false;
		}
		X509_NAME_ENTRY* ne = X509_NAME_get_entry(nm, ret);
		if (nullptr == ne) {
			return false;
		}
		ASN1_STRING* cn = X509_NAME_ENTRY_get_data(ne);
		if (nullptr == cn) {
			return false;
		}
		std::string cname((char*)cn->data, cn->length);

		assert(!m_remote_name.empty());
		if (cname != m_remote_name) {
			//	证书信息与呼叫信息不匹配
			assert(false);
			return false;
		}
		//	获取证书中的公钥
		m_remote_pubkey = X509_get_pubkey(remotecert509);

		//	证书验证完成,再获取到对端临时公钥, 		
		m_remote_temp_pubkey = load_pubkey(m_remote_tmp_pubkey);

		if (nullptr == m_remote_temp_pubkey) {
			assert(nullptr != m_remote_temp_pubkey);
			return false;
		}
		//	到此，所有参数都获取完毕，协商出加解密的密钥
		return this->exchange_work_key();
	}

	/*先使用openssl做一个模拟协商，因openssl中未定义有类似国密的密钥交换，参照3??中的KAA,协商参数需要自身公钥，自身临时公钥，自身
	私钥，自身临时私钥、对方公钥、对方临时公钥的模式，两次调用ECDH，再将两次ECDH的结果kdf派生出来，以实现完整的协商流程*/
	bool derive_some_key(EVP_PKEY *pprivkey, EVP_PKEY *prmtpubkey, std::vector<unsigned char> &keyout) {
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pprivkey, nullptr);
		int ret = EVP_PKEY_derive_init(ctx);
		assert(1 == ret);
		ret = EVP_PKEY_derive_set_peer(ctx, prmtpubkey);
		assert(1 == ret);
		size_t keylen = 0;
		ret = EVP_PKEY_derive(ctx, nullptr, &keylen);
		assert(1 == ret);
		keyout.resize(keylen);
		ret = EVP_PKEY_derive(ctx, keyout.data(), &keylen);
		assert(1 == ret);
		EVP_PKEY_CTX_free(ctx);
		
		return true;
	}
	//	这个是使用openssl模拟的cm api中KAA协商过程
	bool sesscipher::exchange_work_key() {
		if (m_remote_cert.empty() || m_remote_tmp_pubkey.empty() ||
			m_self_cert.empty() || m_self_tmp_pubkey.empty()) {
			pj_assert(false);
			return false;
		}
		//	先留一个接口在这，后面再做
		m_dec_key = "dec_key";
		m_enc_key = "enc_key";
		assert(nullptr != m_self_privkey_key);
		assert(nullptr != m_self_pubkey_key);
		assert(nullptr != m_self_temp_privkey);
		assert(nullptr != m_self_temp_pubkey);
		assert(nullptr != m_remote_pubkey);
		assert(nullptr != m_remote_temp_pubkey);

		//	密钥协商位于加解密之前，需要协商出的信息包括: 本地加密密钥；本地解密密钥；加密IV初值；解密IV初值
		std::vector<unsigned char> vkey0, vkey1;
		derive_some_key(m_self_privkey_key, m_remote_pubkey, vkey0);
		derive_some_key(m_self_temp_privkey, m_remote_temp_pubkey, vkey1);
		//	
		EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
		assert(nullptr != kdf);
		EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);

		OSSL_PARAM params[6];
		std::vector<unsigned char> vkeycomb;
		vkeycomb.insert(vkeycomb.begin(), vkey0.begin(), vkey0.end());
		vkeycomb.insert(vkeycomb.begin(), vkey1.begin(), vkey1.end());
		
		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 6);
		params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, vkeycomb.data(), vkeycomb.size());
		//	ossl中derive中的salt在实际中使用 呼叫方和被叫方的用户名连接设置
		std::string salt = "ccsua."; //	this->m_local_name + this->m_remote_name;
		if (is_sender()) {	//	发起方，是自己的名称在前，对端的名称在后
			salt += this->m_local_name + this->m_remote_name;
		}
		else if (is_receiver()){ //	接收方,是自己的名称在后，对端的名称在前
			salt += this->m_remote_name + this->m_local_name;
		}
		else {
			assert(false); //	角色必须要设置
		}
		params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (char *)salt.data(), salt.size());
		params[3] = OSSL_PARAM_construct_end();

		EVP_KDF_CTX_set_params(kctx, params);

		unsigned char szkey[256];
		memset(szkey, 0, sizeof(szkey));
		int ret = EVP_KDF_derive(kctx, szkey, 128, params);
		assert(1 == ret);
		//	衍生出来的KEY分成两个部分，用于后续的加密
		if (is_sender()) {
			memcpy(m_enckey, szkey, sizeof(m_enckey));
			memcpy(m_deckey, &szkey[32], sizeof(m_deckey));
			memcpy(m_enciv, &szkey[64], sizeof(m_enciv));
			memcpy(m_deciv, &szkey[80], sizeof(m_deciv));
		}
		else if (is_receiver()){	//	按照规则，发起方和接收方的加密参数是相反的
			memcpy(m_deckey, szkey, sizeof(m_deckey));
			memcpy(m_enckey, &szkey[32], sizeof(m_enckey));
			memcpy(m_deciv, &szkey[64], sizeof(m_deciv));
			memcpy(m_enciv, &szkey[80], sizeof(m_enciv));
		}
		else {
			assert(false);
			return false; //	角色是必须要设置的
		}
		return true;
	}


	//	加密定义: blkind: 编号, 这是一个递增的序列，需要根据它变换IV
	//	pinbuf, inlen: 输入的数据地址及长度; 
	//	poutbuf, outlen: 输出的密文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
	bool sesscipher::encrypt(unsigned int blkind, const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen) {
		//	使用AES GCM模拟
		EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();
		unsigned char sziv[16];
		memcpy(sziv, m_enciv, sizeof(m_enciv));
		unsigned long long* pinds = (unsigned long long*)&sziv[8];
		*pinds += blkind;	//	IV需要根据块号变幻

		
		int ret = EVP_EncryptInit(pctx, EVP_aes_256_gcm(), m_enckey, sziv);
		assert(1 == ret);
		int outl = outlen, outl2l = 0;
		//	不做附加认证
		int offs = sizeof(ST_CIPHER_BLOCK_HEAD);
		const char* padd = "ccsb2bua";
		ret = EVP_EncryptUpdate(pctx, nullptr, &outl, (const unsigned char *)padd, strlen(padd));
		assert(1 == ret);
		ret = EVP_EncryptUpdate(pctx, poutbuf + offs, &outl, pinbuf, inlen);
		assert(1 == ret);
		outl2l = outlen - outl;
		ret = EVP_EncryptFinal(pctx, poutbuf + offs + outl, &outl2l);
		assert(1 == ret);
		outlen = sizeof(ST_CIPHER_BLOCK_HEAD) + outl + outl2l;
		EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_GET_TAG, 16, poutbuf + outlen);
		outlen += 16;

		EVP_CIPHER_CTX_free(pctx);

		ST_CIPHER_BLOCK_HEAD heads;
		heads.plainsize = inlen;
		heads.serial = blkind;
		memcpy(poutbuf, &heads, sizeof(ST_CIPHER_BLOCK_HEAD));
				
		return true;
	}
	//	解密定义: 编号从密文块中解析到，不需要输入。
	//	pinbuf, inlen: 输入的密文块数据地址及长度; 
	//	poutbuf, outlen: 输出的明文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
	bool sesscipher::decrypt(const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen) {
		//	使用AES GCM模拟
		PST_CIPHER_BLOCK_HEAD pheads = (PST_CIPHER_BLOCK_HEAD)pinbuf;
		if (pheads->magic[0] != 0x30 || pheads->magic[1] != 'E') {
			assert(false);
			return false; //	magic不匹配
		}
		if (pheads->plainsize != inlen - sizeof(ST_CIPHER_BLOCK_HEAD) - 16) {
			assert(false);
			return false; //	LAPE/GCM模式是计数器模式，不会将密文变长，增加的只是TAG校验
		}

		unsigned char sziv[16];
		memcpy(sziv, m_deciv, sizeof(m_deciv));
		unsigned long long* pinds = (unsigned long long*) & sziv[8];
		*pinds += pheads->serial;	//	IV需要根据块号变幻

		EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();
		
		int ret = EVP_DecryptInit(pctx, EVP_aes_256_gcm(), m_deckey, sziv);
		assert(1 == ret);
		int outl = outlen, outl2 = outlen;
		const char* padd = "ccsb2bua";
		ret = EVP_DecryptUpdate(pctx, nullptr, &outl, (const unsigned char*)padd, strlen(padd));
		assert(1 == ret);
		//	尾巴上16个字节为tag,这个gcm是忽略掉了附加认证的
		EVP_CIPHER_CTX_ctrl(pctx, EVP_CTRL_GCM_SET_TAG, 16, (char*)pinbuf + inlen - 16);

		ret = EVP_DecryptUpdate(pctx, poutbuf, &outl, pinbuf + sizeof(ST_CIPHER_BLOCK_HEAD), inlen - sizeof(ST_CIPHER_BLOCK_HEAD) - 16);
		outl2 -= outl;
		ret = EVP_DecryptFinal(pctx, poutbuf + outl, &outl2);
		assert(1 == ret);
		EVP_CIPHER_CTX_free(pctx);
		outlen = outl + outl2;
		return true;
	}
}	//	namespace ccsua
