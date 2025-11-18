//	ciphers.h
//	处理加密相关的操作
#ifndef _CCS_UA_CIPHERS_H_
#define _CCS_UA_CIPHERS_H_

#include "commons.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

namespace ccsua {
	class testclass;

	class sesscipher : public std::enable_shared_from_this<sesscipher> {
	protected:
		typedef enum e_role {
			E_SENDER = 0,
			E_RECEIVER = 1,
			E_UNDEFINED = 2
		}E_ROLE;
	public:
		sesscipher();
		virtual ~sesscipher();
		//	sesscipher
		//	加载自己的加密参数: 证书、证书链、私钥
		static bool load_self();
		static bool self_can_enc() { return m_self_can_enc; }

		//	引入单元测试模式下需要同时模拟两端的，因此需要一个从静态加载结果向类成员复制的过程
		bool load_from_config();

		//	产生本次通话的临时参数用于后续密钥协商
		bool generate_temp_para();

		//	根据rxdata获取到一个加密信息，如果rdata中无加密相关的信息则返回一个无效对象
		bool parse_remote_by_rx_data(pjsip_rx_data *rdata);

		const std::string get_self_cert() const { 
			pj_assert(!m_self_cert.empty());
			return m_self_cert; 
		}
		const std::string get_self_tmp_pubkey() const { 
			pj_assert(!m_self_tmp_pubkey.empty());
			return m_self_tmp_pubkey; 
		}
		const std::string get_remote_cert() const { 
			pj_assert(!m_remote_cert.empty());
			return m_remote_cert;
		}
		const std::string get_remote_tmp_pubkey() const {
			pj_assert(!m_remote_tmp_pubkey.empty());
			return m_remote_tmp_pubkey; 
		}
		//	内网呼出的时候，在UAS Request中解析被叫方并设置。外网呼入的时候，在UAS Request
		//	中解析主叫方并设置, cipher中只是做验证
		void set_remote_name(const std::string& rmtname) {
			m_remote_name = rmtname;
		}
		const std::string& get_remote_name() const { return m_remote_name; }

		//	设置协商的方向，需要一个发起方，一个接收方
		void set_role_is_sender() {
			m_role = E_SENDER;
		}
		void set_role_is_receiver() {
			m_role = E_RECEIVER;
		}
		bool is_sender() { return m_role == E_SENDER; }
		bool is_receiver() { return m_role == E_RECEIVER; }

		//	cipher对外提供加密和解密的接口，在协议中直接调用它，接口的定义参考通话数据流:
		/* 加密: 输入明文、编号，输出加密后的密文块，或者解密失败。
		* 解密: 输入密文块，输出解密后的明文，或者解密失败。
		* 密文块格式定义: Magic(4: 0x30, 'V','E', 'A'):编号(4):明文长(2):校验(2):数据(不定长)
		* 密文块为RTP或SRTP报文，通常不会超过一个UDP能承载的最大长度，实测时也只有几KB级别的数据长。
		* 但是后续如果要考虑视频，可能会有差异，但整体不会超过一个UDP报文上限(65536)
		* 密文块中的编号是用于变换IV的，现在使用LAPE模式，每一个块的IV不同，依据初值按块号变换,块号是上层
		* 应用中接收到的数据包序号。这个序号只是网络中接收的序号，与真实的发送方发送的序号不一定相同
		*/

		//	加密定义: blkind: 编号, 这是一个递增的序列，需要根据它变换IV
		//	pinbuf, inlen: 输入的数据地址及长度; 
		//	poutbuf, outlen: 输出的密文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
		bool encrypt(unsigned int blkind, const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen);
		//	解密定义: 编号从密文块中解析到，不需要输入。
		//	pinbuf, inlen: 输入的密文块数据地址及长度; 
		//	poutbuf, outlen: 输出的明文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
		bool decrypt(const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen);

		friend class testclass;
	protected:
		/*当两端的参数都解析正确后，协商工作密钥。 按照其它设备的实现，
		一次通话工作密钥应该是两个，一个收解密，一个发加密。密钥协商也是有两个方向，一个发起方，一个接收方，
		*/
		bool exchange_work_key();

		//	解析对端的相关参数
		bool parse_remote_paras();

#ifdef _UNIT_TEST_
		void set_remote_cert(const std::string& rmtcert) { m_remote_cert = rmtcert; }
		void set_remote_temp_pubkey(const std::string& rmtpubkey) { m_remote_tmp_pubkey = rmtpubkey; }
#endif
	protected:
		typedef struct _st_cipher_block_head {
			unsigned char magic[2];
			unsigned short plainsize;
			unsigned int serial; //	编号
			//	--LAPE模式有加有校验，因此不需要校验值检测
			_st_cipher_block_head() {
				memset(this, 0, sizeof(struct _st_cipher_block_head));
				magic[0] = 0x30;
				magic[1] = 'E';
			}
		}ST_CIPHER_BLOCK_HEAD, *PST_CIPHER_BLOCK_HEAD;
		static bool m_self_can_enc;
		//	保存自己和对端的用户名--证书验证的时候需要使用到
		std::string m_local_name, m_remote_name;

		//	sth. needed.证书和私钥只需要加载一次，做成静态的
		static std::string _self_cert, _self_privkey;
		std::string m_self_cert, m_self_privkey;

		std::string m_self_tmp_pubkey, m_remote_cert, m_remote_tmp_pubkey;

		//	按一般的做法，协商出来的是两个KEY,一个用作发送加密，一个用作接收解密
		std::string m_enc_key, m_dec_key;

		//	认证与验证相关. 先用openssl的模拟，后面再重新封装接口

		static X509* _parent_cert_x509, * _self_cert_x509;
		static EVP_PKEY* _self_pubkey_key, * _self_privkey_key;
		//	单元测试模式下需要模拟两端，静态的会失效..
		X509* m_parent_cert_x509, * m_self_cert_x509;
		EVP_PKEY* m_self_pubkey_key, * m_self_privkey_key;

		EVP_PKEY *m_self_temp_pubkey, * m_self_temp_privkey, * m_remote_pubkey, * m_remote_temp_pubkey;

		//	IV初值,协商的时候需要一并协商出来，如果算法配置够用，可以考虑协商出三个密钥: 
		//	两个对称密钥用于通话数据加解密，一个MAC密钥用于计算IV,IV可以用协商出来的MAC密钥对一固定数据(如通话双方的用户名拼接)
		//	计算出MAC后抽取两个16字节用于加解密IV
		unsigned char m_enciv[16], m_deciv[16], m_enckey[32], m_deckey[32];
		E_ROLE m_role; //	标识是协商发起方还是接收方, true: 发起方; false:接收方
	}; //	class sesscipher

#ifdef _UNIT_TEST_
	inline std::string b64_encode(const std::string& in);
	inline std::string b64_decode(const std::string& in);

	void dump_hex(const unsigned char* pbuf, int buflen, const char* title);
#endif
} //	namespace ccsua

#endif //	_CCS_UA_CIPHERS_H_
