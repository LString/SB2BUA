//	config.cpp
//	configϢʵ
#include "config.h"

namespace ccsua {
	config config::m_config;
	config::config() {
                // Default locations differ between Windows development and POSIX deployments.
#ifdef _WIN32
                m_wav_dir = "F:\\wg\\voip\\sb2bua20251023\\wav_files\\";
                m_certkey_dir = "F:\\wg\\voip\\sb2bua20251023\\certkey\\";
#else
                m_wav_dir = "./wav_files/";
                m_certkey_dir = "./certkey/";
#endif

		m_certchain = "rootCA.crt";
		m_selfcert = "1005.crt";
		m_selfkey = "1005.key";
		m_user = "1005";
		m_userpwd = "password555";

		m_sip_addr = "60.40.0.205";
		m_outer_addr = "60.40.0.233";
		m_inner_addr = "192.168.99.233";
	}
	config::~config() {}
	config& config::get() {
		return m_config;
	}


	//	Ϣ--Ҫָļ·Ȼȡļ
	bool config::load() {
		return true;
	}

	//	ȡõĸϢ

	//	ȡwavļ·
	const std::string config::wav_dir() const {
		return m_wav_dir;
	}
	//	ȡ֤·--֤·ĸʽΪ: ->ǩ0->ǩ1->...ǩN, Ҫ֤еһû֤
	//	ֱøǩû֤飬֤·оֻһ֤
	const std::list<std::string> config::root_cert_file() const {
		std::string _rootcert = m_certkey_dir + m_certchain;
		std::list<std::string> _ret;
		_ret.push_back(_rootcert);
		return _ret;
	}
	//	ȡ֤·
	const std::string config::self_cert_file() const {
		return m_certkey_dir + m_selfcert;
	}
	//	ȡ˽Կ·
	const std::string config::self_priv_key() const {
		return m_certkey_dir + m_selfkey;
	}

	//	ȡsipע--ûӦֱӴ֤ȡ,Ҫ֤,û֤ƥ
	const std::string config::sip_user_pwd() const {
		return m_userpwd;
	}
	const std::string config::sip_user() const {
		return m_user;
	}

	//	sip ַ
	const std::string config::sip_addr() const {
		return m_sip_addr;
	}
	//	ַ: sip
	const std::string config::outer_addr() const {
		return m_outer_addr;
	}
	//	ַ: 뻰
	const std::string config::inner_addr() const {
		return m_inner_addr;
	}

}	//	namespace ccsua
