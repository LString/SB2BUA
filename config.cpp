//	config.cpp
//	configϢʵ
#include "config.h"

namespace ccsua {

    // 注意：这里不再定义 config config::m_config;
    // 避免跨翻译单元的静态初始化顺序问题。

    config::config() {
        // Default locations differ between Windows development and POSIX deployments.
#ifdef _WIN32
        m_wav_dir     = "F:\\wg\\voip\\sb2bua20251023\\wav_files\\";
        m_certkey_dir = "F:\\wg\\voip\\sb2bua20251023\\certkey\\";
#else
        m_wav_dir     = "/home/ark/Projects/SB2BUA/wav_files/";
        m_certkey_dir = "/home/ark/Projects/SB2BUA/certkey/";
#endif

        m_certchain = "rootCA.crt";
        m_selfcert  = "1001.crt";
        m_selfkey   = "1001.key";
        m_user      = "1001";
        m_userpwd   = "1001pass";

        m_sip_addr   = "10.0.6.91";
        m_outer_addr = "10.0.6.175";
        m_inner_addr = "10.0.6.175";
    }

    config::~config() {}

    // 新的单例实现：函数内 static
    config& config::get() {
        static config instance;   // 第一次调用 get() 时构造
        return instance;
    }

    bool config::load() {
        return true;
    }

    const std::string config::wav_dir() const {
        return m_wav_dir;
    }

    const std::list<std::string> config::root_cert_file() const {
        std::string _rootcert = m_certkey_dir + m_certchain;
        std::list<std::string> _ret;
        _ret.push_back(_rootcert);
        return _ret;
    }

    const std::string config::self_cert_file() const {
        return m_certkey_dir + m_selfcert;
    }

    const std::string config::self_priv_key() const {
        return m_certkey_dir + m_selfkey;
    }

    const std::string config::sip_user_pwd() const {
        return m_userpwd;
    }

    const std::string config::sip_user() const {
        return m_user;
    }

    const std::string config::sip_addr() const {
        return m_sip_addr;
    }

    const std::string config::outer_addr() const {
        return m_outer_addr;
    }

    const std::string config::inner_addr() const {
        return m_inner_addr;
    }

} // namespace ccsua
