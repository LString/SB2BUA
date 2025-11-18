//	test.cpp
//	测试相关代码
#include "test.h"
#include "config.h"
#include "ciphers.h"

pj_pool_t* g_pool;
namespace ccsua {

	testclass::testclass() {}
	testclass::~testclass() {}

	int testclass::test_ciphers(int argc, const char* argv[]) {
		//	先实例化A端
		bool bret = false;
		ccsua::sesscipher::load_self();
		std::shared_ptr<ccsua::sesscipher> _cipher_A = std::make_shared<ccsua::sesscipher>();
		_cipher_A->load_from_config();
		_cipher_A->set_role_is_sender();

		bret = _cipher_A->generate_temp_para();
		assert(bret);
		std::string _a_tmp_pubkey = _cipher_A->get_self_tmp_pubkey();
		std::string _a_cert = _cipher_A->get_self_cert();
		//	先解码再设置给对端，
		_a_tmp_pubkey = b64_decode(_a_tmp_pubkey);
		_a_cert = b64_decode(_a_cert);

		//	再实例化B端--需要手动修改配置重新加载
		ccsua::config::get().set_self_cert_file("1008.crt");
		ccsua::config::get().set_self_priv_key("1008.key");
		ccsua::config::get().set_sip_user("1008");
		ccsua::sesscipher::load_self();	//	必须要重新加载
		std::shared_ptr<ccsua::sesscipher> _cipher_B = std::make_shared<ccsua::sesscipher>();
		_cipher_B->load_from_config();
		_cipher_B->set_role_is_receiver();
		bret = _cipher_B->generate_temp_para();
		assert(bret);
		std::string _b_tmp_pubkey = _cipher_B->get_self_tmp_pubkey();
		std::string _b_cert = _cipher_B->get_self_cert();
		//	先解码再设置给对端，
		_b_tmp_pubkey = b64_decode(_b_tmp_pubkey);
		_b_cert = b64_decode(_b_cert);

		//	双向设置协商参数
		_cipher_A->set_remote_cert(_b_cert);
		_cipher_A->set_remote_temp_pubkey(_b_tmp_pubkey);
		_cipher_A->set_remote_name("1008");

		_cipher_B->set_remote_cert(_a_cert);
		_cipher_B->set_remote_temp_pubkey(_a_tmp_pubkey);
		_cipher_B->set_remote_name("1005");

		//	这两个调用包含了key协商
		bret = _cipher_A->parse_remote_paras();
		assert(bret);
		bret = _cipher_B->parse_remote_paras();
		assert(bret);
		//	测试加密
		unsigned char szInA[64], szOutA[256], szInB[64], szOutB[256];
		memset(szInA, 0xa, sizeof(szInA));
		memset(szInB, 0xb, sizeof(szInB));
		memset(szOutA, 0x0, sizeof(szOutA));
		memset(szOutB, 0x0, sizeof(szOutB));
		size_t outa = 256, outb = 256;
		bret = _cipher_A->encrypt(1, szInA, 64, szOutA, outa);
		assert(bret);
		dump_hex(szOutA, outa, "Serial 1 Enc ret");
		bret = _cipher_B->decrypt(szOutA, outa, szOutB, outb);
		assert(bret);

		outa = 256, outb = 256;
		bret = _cipher_A->encrypt(19, szInA, 64, szOutA, outa);
		assert(bret);
		dump_hex(szOutA, outa, "Serial 19 Enc ret");

		bret = _cipher_B->decrypt(szOutA, outa, szOutB, outb);
		assert(bret);
		//	再验证反向加解密
		outa = 256, outb = 256;
		bret = _cipher_B->encrypt(1, szInA, 64, szOutA, outa);
		assert(bret);
		dump_hex(szOutA, outa, "B->A Serial 1 Enc ret");
		bret = _cipher_A->decrypt(szOutA, outa, szOutB, outb);
		assert(bret);

		outa = 256, outb = 256;
		bret = _cipher_B->encrypt(19, szInA, 64, szOutA, outa);
		assert(bret);
		dump_hex(szOutA, outa, "B->A Serial 19 Enc ret");

		bret = _cipher_A->decrypt(szOutA, outa, szOutB, outb);
		assert(bret);

		return 0;
	}
}	//	namespace ccsua


int main(int argc, const char* argv[]) {
	//  加载配置信息
	ccsua::config::get().load();
	//  加载加解密信息、证书、私钥等
	ccsua::sesscipher::load_self();

	ccsua::testclass t;

	return t.test_ciphers(argc, argv);
}