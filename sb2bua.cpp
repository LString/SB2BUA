
#include "sb2bua.h"
#include "uasess.h"
#include "ciphers.h"
#include "config.h"

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
# pragma comment(lib, "Ws2_32.lib")
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <fcntl.h>
# define closesocket close
#endif

b2broute g_routemap;

ccsua::sessman g_sess;
ccsua::mediathread g_mediathread;

int g_expired = 3600; //    默认1小时保活

/* ====== global objects ====== */
static pj_caching_pool g_cp;
pj_pool_t* g_pool;
pjsip_endpoint* g_endpt;
pjmedia_endpt* g_med_endpt;
pjmedia_event_mgr* g_media_event_mgr = NULL;

static pj_bool_t module_on_rx_request(pjsip_rx_data* rdata);
static pj_bool_t module_on_rx_response(pjsip_rx_data* rdata);

static pjsip_tx_data* create_out_invite_from(pjsip_rx_data* rdata/*, const char* dst_uri*/);
static pj_status_t pjsip_msg_add_body(pjsip_msg* msg,
    const pj_str_t* content_type,
    const pj_str_t* body);

pj_str_t g_pcallid;

//  wg. 20251029, 保留两个传输端点，一个对内，一个对外。生成的请求时需要根据方向指定传输端点
pjsip_transport* g_transport_outer = NULL, * g_transport_inner = NULL;

/* Global authentication session for upstream registration and calls */
static struct {
    pjsip_auth_clt_sess auth_sess;  /* Client authentication session */
    pj_bool_t     auth_initialized;  /* Whether auth is initialized */
} g_auth;

std::string pjstr_to_string(const pj_str_t* pjs) {
    if (NULL == pjs)  return "";
    if (NULL == pjs->ptr || pjs->slen < 1)  return "";
    return std::string(pjs->ptr, pjs->slen);
}
std::string pjstr_to_string(const pj_str_t& pjs) {
    if (NULL == pjs.ptr || pjs.slen < 1)  return "";
    return std::string(pjs.ptr, pjs.slen);
}

/* Create RTP/RTCP socket pair */
pj_status_t create_media_transport(const char* local_ip,
    media_sock_pair_t* sock_pair);

/* Close media transport */
void close_media_transport(media_sock_pair_t* sock_pair);

static pj_bool_t is_port_available(const char* ip, int port)
{
    struct sockaddr_in addr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return PJ_FALSE;

    pj_bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons((pj_uint16_t)port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return PJ_FALSE;
    }

    closesocket(sock);
    return PJ_TRUE;
}

/* Find available port pair (even port for RTP, odd for RTCP) */
static pj_status_t find_available_port_pair(const char* ip,
    int* rtp_port,
    int* rtcp_port)
{
    int base_port = 10000;  // Starting from port 10000

    while (base_port < 65535 - 1) {
        if ((base_port & 0x01) == 1)  // Ensure even port
            base_port++;

        if (is_port_available(ip, base_port) &&
            is_port_available(ip, base_port + 1))
        {
            *rtp_port = base_port;
            *rtcp_port = base_port + 1;
            return PJ_SUCCESS;
        }
        base_port += 2;
    }

    return PJ_EUNKNOWN;
}

//  将sockaddr_in转换成 pj_sockaddr_in, 若干年后可能需要IPV6，现在只做一个IPV4的
void trans_sockaddr_in(const sockaddr_in& _from_addrin, pj_sockaddr_in& _to_pj_addrin) {
    _to_pj_addrin.sin_family = _from_addrin.sin_family;
    _to_pj_addrin.sin_port = _from_addrin.sin_port;
    //  这个类型相同，只是重命名了一把
    memcpy(&_to_pj_addrin.sin_addr, &_from_addrin.sin_addr, sizeof(_from_addrin.sin_addr));
    memcpy(&_to_pj_addrin.sin_zero_pad, &_from_addrin.sin_zero, sizeof(_from_addrin.sin_zero));
}

pj_status_t create_media_transport(const char* local_ip,
    media_sock_pair_t* sock_pair)
{
    struct sockaddr_in addr;
    int rtp_port, rtcp_port;
    pj_status_t status;

    /* Find available port pair */
    status = find_available_port_pair(local_ip, &rtp_port, &rtcp_port);
    if (status != PJ_SUCCESS)
        return status;

    /* Create RTP socket */
    sock_pair->rtp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_pair->rtp_sock < 0)
        return PJ_EUNKNOWN;

    /* Create RTCP socket */
    sock_pair->rtcp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_pair->rtcp_sock < 0) {
        closesocket(sock_pair->rtp_sock);
        return PJ_EUNKNOWN;
    }

    /* Bind RTP socket */
    pj_bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(local_ip);
    addr.sin_port = htons((pj_uint16_t)rtp_port);

    if (bind(sock_pair->rtp_sock, (struct sockaddr*)&addr,
        sizeof(addr)) != 0) {
        closesocket(sock_pair->rtp_sock);
        closesocket(sock_pair->rtcp_sock);
        return PJ_EUNKNOWN;
    }
    // RTP的绑定
    trans_sockaddr_in(addr, sock_pair->rtp_sockaddr.ipv4);

    /* Bind RTCP socket */
    addr.sin_port = htons((pj_uint16_t)rtcp_port);
    if (bind(sock_pair->rtcp_sock, (struct sockaddr*)&addr,
        sizeof(addr)) != 0) {
        closesocket(sock_pair->rtp_sock);
        closesocket(sock_pair->rtcp_sock);
        return PJ_EUNKNOWN;
    }
    // RTCP的绑定
    trans_sockaddr_in(addr, sock_pair->rtcp_sockaddr.ipv4);

    sock_pair->rtp_port = rtp_port;
    sock_pair->rtcp_port = rtcp_port;

    return PJ_SUCCESS;
}

void close_media_transport(media_sock_pair_t* sock_pair)
{
    if (sock_pair->rtp_sock >= 0) {
        closesocket(sock_pair->rtp_sock);
        sock_pair->rtp_sock = -1;
    }
    if (sock_pair->rtcp_sock >= 0) {
        closesocket(sock_pair->rtcp_sock);
        sock_pair->rtcp_sock = -1;
    }
}

/* Initialize authentication session for upstream calls */
static pj_status_t init_auth_sess(void)
{
    pj_status_t status;

    if (g_auth.auth_initialized)
        return PJ_SUCCESS;

    status = pjsip_auth_clt_init(&g_auth.auth_sess, g_endpt, g_pool, 0);
    if (status != PJ_SUCCESS)
        return status;

    /* Add credentials */
    {
        pjsip_cred_info cred;
        pj_bzero(&cred, sizeof(cred));
        //  这个应该是服务端的..
        cred.realm = pj_str((char*)SIP_SERVER);
        cred.scheme = pj_str((char*)"digest");
        cred.username = pj_str((char*)UPSTREAM_USER);
        cred.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
        cred.data = pj_str((char*)UPSTREAM_PASS);

        status = pjsip_auth_clt_set_credentials(&g_auth.auth_sess, 1, &cred);
        if (status != PJ_SUCCESS)
            return status;
    }

    g_auth.auth_initialized = PJ_TRUE;
    return PJ_SUCCESS;
}


/* pjsip module */
static pjsip_module mod_b2b = {
    NULL, NULL,
    { (char*)"mod-b2b", 0 },
    -1,
#ifdef AI
    //PJSIP_MOD_PRIORITY_APPLICATION,  //   ACK消息没有被处理到,测试一下改优先级
#else
    PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, //  测试修改成UA或代理层
#endif
    NULL, NULL, NULL, NULL,
    &module_on_rx_request,
    &module_on_rx_response,
    NULL, NULL, NULL
};


/* Notification on incoming messages */
static pj_bool_t logging_on_rx_msg_request(pjsip_rx_data* rdata)
{
    pjsip_method method = rdata->msg_info.msg->line.req.method;
    if (method.id == PJSIP_ACK_METHOD) {
        printf("--------------------\n");
        printf("        ACK Received.\n");
        printf("--------------------\n");
    }
    PJ_LOG(4, (THIS_FILE, "RX_request %d bytes %s from %s %s:%d:\n"
        "%.*s\n"
        "--end msg--",
        rdata->msg_info.len,
        pjsip_rx_data_get_info(rdata),
        rdata->tp_info.transport->type_name,
        rdata->pkt_info.src_name,
        rdata->pkt_info.src_port,
        (int)rdata->msg_info.len,
        rdata->msg_info.msg_buf));

    /* Always return false, otherwise messages will not get processed! */
    return PJ_FALSE;
}

/* Notification on incoming messages */
static pj_bool_t logging_on_rx_msg_response(pjsip_rx_data* rdata)
{
    PJ_LOG(4, (THIS_FILE, "RX_respon %d bytes %s from %s %s:%d:\n"
        "%.*s\n"
        "--end msg--",
        rdata->msg_info.len,
        pjsip_rx_data_get_info(rdata),
        rdata->tp_info.transport->type_name,
        rdata->pkt_info.src_name,
        rdata->pkt_info.src_port,
        (int)rdata->msg_info.len,
        rdata->msg_info.msg_buf));

    /* Always return false, otherwise messages will not get processed! */
    return PJ_FALSE;
}

/* Notification on outgoing messages */
static pj_status_t logging_on_tx_msg(pjsip_tx_data* tdata)
{

    /* Important note:
     *  tp_info field is only valid after outgoing messages has passed
     *  transport layer. So don't try to access tp_info when the module
     *  has lower priority than transport layer.
     */

    PJ_LOG(4, (THIS_FILE, "TX %ld bytes %s to %s %s:%d:\n"
        "%.*s\n"
        "--end msg--",
        (tdata->buf.cur - tdata->buf.start),
        pjsip_tx_data_get_info(tdata),
        tdata->tp_info.transport->type_name,
        tdata->tp_info.dst_name,
        tdata->tp_info.dst_port,
        (int)(tdata->buf.cur - tdata->buf.start),
        tdata->buf.start));

    /* Always return success, otherwise message will not get sent! */
    return PJ_SUCCESS;
}

/* The module instance. */
pjsip_module msg_logger =
{
    NULL, NULL,                         /* prev, next.          */
    { (char *)"mod-msg-log", 13 },              /* Name.                */
    -1,                                 /* Id                   */
    PJSIP_MOD_PRIORITY_TRANSPORT_LAYER - 1,/* Priority            */
    NULL,                               /* load()               */
    NULL,                               /* start()              */
    NULL,                               /* stop()               */
    NULL,                               /* unload()             */
    &logging_on_rx_msg_request,                 /* on_rx_request()      */
    &logging_on_rx_msg_response,                 /* on_rx_response()     */
    &logging_on_tx_msg,                 /* on_tx_request.       */
    &logging_on_tx_msg,                 /* on_tx_response()     */
    NULL,                               /* on_tsx_state()       */

};

/* ====== Digest helpers ====== */
extern "C"{
    static void md5_hex(const char* in, char out[33]) {
        unsigned char md[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)in, (unsigned int)strlen(in), md);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) pj_ansi_snprintf(out + i * 2, 3, "%02x", md[i]);
        out[32] = '\0';
    }
}
typedef struct auth_kv { char k[64]; char v[256]; struct auth_kv* next; } auth_kv_t;
static auth_kv_t* parse_auth_params(const char* s) {
    auth_kv_t* head = NULL;
    const char* p = s;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char* eq = strchr(p, '=');
        if (!eq) break;
        int klen = (int)(eq - p);
        char key[64] = { 0 };
        strncpy(key, p, klen < 63 ? klen : 63);
        p = eq + 1;
        char val[256] = { 0 };
        if (*p == '"') {
            p++;
            const char* q = strchr(p, '"');
            if (!q) break;
            int vlen = (int)(q - p);
            strncpy(val, p, vlen < 255 ? vlen : 255);
            p = q + 1;
        }
        else {
            const char* q = p;
            while (*q && *q != ',' && *q != ' ') q++;
            int vlen = (int)(q - p);
            strncpy(val, p, vlen < 255 ? vlen : 255);
            p = q;
        }
        auth_kv_t* kv = (auth_kv_t*)pj_pool_alloc(g_pool, sizeof(*kv));
        kv->next = head;
        pj_ansi_strncpy(kv->k, key, sizeof(kv->k));
        pj_ansi_strncpy(kv->v, val, sizeof(kv->v));
        head = kv;
    }
    return head;
}
static const char* auth_kv_get(auth_kv_t* h, const char* k) {
    for (auth_kv_t* p = h; p; p = p->next) if (strcasecmp(p->k, k) == 0) return p->v;
    return NULL;
}
static pj_bool_t validate_digest(const char* username, const char* realm, const char* password,
    const char* method, const char* uri, auth_kv_t* kv)
{
    const char* nonce = auth_kv_get(kv, "nonce");
    const char* response = auth_kv_get(kv, "response");
    const char* qop = auth_kv_get(kv, "qop");
    const char* nc = auth_kv_get(kv, "nc");
    const char* cnonce = auth_kv_get(kv, "cnonce");
    if (!nonce || !response || !username || !realm || !password) return PJ_FALSE;
    char ha1_in[512]; pj_ansi_snprintf(ha1_in, sizeof(ha1_in), "%s:%s:%s", username, realm, password);
    char ha1[33]; md5_hex(ha1_in, ha1);
    char ha2_in[512]; pj_ansi_snprintf(ha2_in, sizeof(ha2_in), "%s:%s", method, uri);
    char ha2[33]; md5_hex(ha2_in, ha2);
    char resp_in[1024];
    if (qop && strcmp(qop, "auth") == 0 && nc && cnonce)
        pj_ansi_snprintf(resp_in, sizeof(resp_in), "%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
    else
        pj_ansi_snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce, ha2);
    char expected[33]; md5_hex(resp_in, expected);
    return (strcasecmp(expected, response) == 0) ? PJ_TRUE : PJ_FALSE;
}

/* ====== utilities ====== */
static char* get_hdr_value_raw(pjsip_msg* msg, const char* hdrname) {
	pj_str_t hdr_str = pj_str((char*)hdrname);
    pjsip_hdr* h = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &hdr_str, NULL);
    if (!h) return NULL;
    pj_str_t buf = pj_str((char*)pj_pool_alloc(g_pool, 4096));
    memset(buf.ptr, 0, 4096);
    //pjsip_hdr_print(h, g_pool, &buf);
    buf.slen = pjsip_hdr_print_on(h, buf.ptr, 4096);
    char* colon = strchr(buf.ptr, ':');
    if (!colon) {
        //return pj_strdup3(g_pool, buf.ptr).ptr;
        int retlen = strlen(buf.ptr);
        char* pret = (char*)pj_pool_alloc(g_pool, retlen + 1);
        memset(pret, 0, retlen + 1);
        memcpy(pret, buf.ptr, retlen);
        return pret;
    }
    char* val = colon + 1; while (*val == ' ') val++;
    int retlen = strlen(val);
    char* pret = (char*)pj_pool_alloc(g_pool, retlen + 1);
    memset(pret, 0, retlen + 1);
    memcpy(pret, val, retlen);
    return pret;
}
extern "C" {
    static void gen_nonce(char out[33]) {
        unsigned char md[MD5_DIGEST_LENGTH];
        char tmp[64];
        pj_ansi_snprintf(tmp, sizeof(tmp), "%u:%u", (unsigned)rand(), (unsigned)time(NULL));
        MD5((unsigned char*)tmp, (unsigned)strlen(tmp), md);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) pj_ansi_snprintf(out + i * 2, 3, "%02x", md[i]);
        out[32] = 0;
    }
}

//  根据rdata获取到路由信息
PST_ROUTE_INFO get_route_info(pjsip_rx_data* rdata) {
	PST_ROUTE_INFO pRouteInfo = new ST_ROUTE_INFO();
    pjsip_sip_uri* target_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.msg->line.req.uri);
	pjsip_sip_uri* from_uri = (pjsip_sip_uri*)pjsip_uri_get_uri((void*)rdata->msg_info.from->uri);
	pjsip_sip_uri* to_uri = (pjsip_sip_uri*)pjsip_uri_get_uri((void*)rdata->msg_info.to->uri);
	pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
    
    std::string usrname(target_uri->user.ptr, target_uri->user.slen);

    std::stringstream sstarget, ssfrom, ssto, sscontact;
    pRouteInfo->is_call_outer = true;
	//  当呼叫方是 b2bua 向sip注册的用户时,路由信息到向b2b注册的111用户
    if (usrname == std::string(UPSTREAM_USER)) {
        std::shared_ptr< b2buser> buser = g_routemap.get_user(LOCAL_REG_USER);
        if (!buser) {
            return NULL;   //   没有找到返回NULL,调用方当成404处理
        }

        pRouteInfo->is_call_outer = false;
        buser->get_contact_info();
		sstarget << "sip:" << LOCAL_REG_USER << "@" << buser->get_contactip() << ":" << buser->get_contactport();
		//ssfrom << "sip:" << LOCAL_REG_USER << "@" << std::string(from_uri->host.ptr, from_uri->host.slen) << ":" << from_uri->port;
        ssfrom << "sip:" << std::string(from_uri->user.ptr, from_uri->user.slen) << "@" << LOCAL_IP_PHONE << ":" << SIP_PORT;
		ssto << "sip:" << LOCAL_REG_USER << "@" << LOCAL_IP_PHONE << ":" << SIP_PORT;
        
        if (contact_hdr && contact_hdr->uri) {
            pjsip_sip_uri* contact_uri = (pjsip_sip_uri*)pjsip_uri_get_uri((void*)contact_hdr->uri);
            
            sscontact << "sip:" << std::string(contact_uri->user.ptr, contact_uri->user.slen) << "@" << LOCAL_IP_PHONE << ":" << SIP_PORT;
        }
        else {
			sscontact << "sip:" << LOCAL_REG_USER << "@" << LOCAL_IP_PHONE << ":" << SIP_PORT;
        }
        pRouteInfo->from_user = std::string(from_uri->user.ptr, from_uri->user.slen);
        pRouteInfo->to_user = UPSTREAM_USER;
    }
    else {
		//  当呼叫方是其它用户时，表示是注册到b2bua的111用户呼叫出去的
		sstarget << "sip:" << std::string(to_uri->user.ptr, to_uri->user.slen) << "@" << SIP_SERVER;
		ssfrom << "sip:" << UPSTREAM_USER << "@" << SIP_SERVER;
        ssto << "sip:" << std::string(to_uri->user.ptr, to_uri->user.slen) << "@" << SIP_SERVER;
        if (contact_hdr && contact_hdr->uri) {
            pjsip_sip_uri* contact_uri = (pjsip_sip_uri*)pjsip_uri_get_uri((void*)contact_hdr->uri);
            sscontact << "sip:" << UPSTREAM_USER << "@" << LOCAL_IP_UPSTREAM;
        }
        else {
			sscontact << "sip:" << UPSTREAM_USER << "@" << LOCAL_IP_UPSTREAM;
        }
        pRouteInfo->from_user = UPSTREAM_USER;
        pRouteInfo->to_user = std::string(to_uri->user.ptr, to_uri->user.slen);
    }
	pRouteInfo->target = sstarget.str();
	pRouteInfo->from = ssfrom.str();
	pRouteInfo->to = ssto.str();
	pRouteInfo->contact = sscontact.str();

    return pRouteInfo;
}

/* ====== UDP relay thread ====== */
#define MAX_PACKET_SIZE 8192

/* Media relay thread argument structure */
typedef struct relay_thread_param {
    media_sock_pair_t* src_pair;    /* Source RTP/RTCP socket pair */
    media_sock_pair_t* dst_pair;    /* Destination RTP/RTCP socket pair */
    char dst_rtp_addr[64];          /* Destination RTP IP address */
    int dst_rtp_port;               /* Destination RTP port */
    char dst_rtcp_addr[64];         /* Destination RTCP IP address */
    int dst_rtcp_port;              /* Destination RTCP port */
    //pj_bool_t* is_active;           /* Pointer to active flag */
    //  标识接收加密转发还是接收解密转发，由呼叫方是内端还是外端与UAC/UAS身份联合判断,满足以下规则:
    /* 呼叫方是内端: UAS侧是接收后加密转发; UAC侧是接收后解密转发
    * 呼叫方是外端: UAS侧是接收后解密转发; UAC侧是接收后加密转发
    */
    E_RTP_PROC_TYPE body_process;
    std::shared_ptr<ccsua::uasess> _uasess;
} relay_thread_param;

/* Media relay thread function */
static int PJ_THREAD_FUNC relay_thread_func(void* arg)
{
    relay_thread_param* param = (relay_thread_param*)arg;
    char buffer[MAX_PACKET_SIZE], destbuf[MAX_PACKET_SIZE];
    pj_fd_set_t rdset;
    int max_fd;

    /* Calculate max fd for select() */
    max_fd = param->src_pair->rtp_sock;
    if (param->src_pair->rtcp_sock > max_fd)
        max_fd = param->src_pair->rtcp_sock;

    /* Prepare destination addresses */
    struct sockaddr_in rtp_dst_addr, rtcp_dst_addr;
    pj_bzero(&rtp_dst_addr, sizeof(rtp_dst_addr));
    pj_bzero(&rtcp_dst_addr, sizeof(rtcp_dst_addr));

    rtp_dst_addr.sin_family = rtcp_dst_addr.sin_family = AF_INET;
    rtp_dst_addr.sin_addr.s_addr = inet_addr(param->dst_rtp_addr);
    rtcp_dst_addr.sin_addr.s_addr = inet_addr(param->dst_rtcp_addr);
    rtp_dst_addr.sin_port = htons((pj_uint16_t)param->dst_rtp_port);
    rtcp_dst_addr.sin_port = htons((pj_uint16_t)param->dst_rtcp_port);

    PJ_LOG(2, (THIS_FILE, "Media relay thread started: RTP %s:%d->%s:%d, RTCP %s:%d->%s:%d",
        pj_inet_ntoa(*(pj_in_addr*)&param->src_pair->rtp_sock),
        param->src_pair->rtp_port,
        param->dst_rtp_addr, param->dst_rtp_port,
        pj_inet_ntoa(*(pj_in_addr*)&param->src_pair->rtcp_sock),
        param->src_pair->rtcp_port,
        param->dst_rtcp_addr, param->dst_rtcp_port));

    unsigned int blkind = 0;
    
    while (/**param->is_active*/param->_uasess->is_running()) {
        PJ_FD_ZERO(&rdset);
        PJ_FD_SET(param->src_pair->rtp_sock, &rdset);
        PJ_FD_SET(param->src_pair->rtcp_sock, &rdset);

        /* Wait for data */
        //struct timeval timeout = { 0, 10000 }; // 10ms timeout
        pj_time_val timeout = {0, 10000};
        
        int n = pj_sock_select(max_fd + 1, &rdset, NULL, NULL, &timeout);
                
        if (n < 0) {
            continue;
        }

        //  RTP里面应该是通话数据，这里面就需要根据通话方向实现加解密处理后再转发
        //  转发规则: 由参数中定义
        /* Check RTP socket */
        if (PJ_FD_ISSET(param->src_pair->rtp_sock, &rdset)) {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);

            int len = recvfrom(param->src_pair->rtp_sock, buffer,
                MAX_PACKET_SIZE, 0,
                (struct sockaddr*)&addr, &addr_len);            
            if (len > 0) {
                size_t destlen = len;
                switch (param->body_process) {  //  这儿需要从_uasess中获取到协商后的加密密钥
                case E_ENCRYPT_TRANS:
                {   //  执行接收到的数据加密
                    param->_uasess->encrypt(blkind, (unsigned char*)buffer, len, (unsigned char*)destbuf, destlen);
                }
                break;
                case E_DECRYPT_TRANS:
                {   //  执行接收到的数据解密
                    param->_uasess->decrypt((unsigned char*)buffer, len, (unsigned char*)destbuf, destlen);
                }
                break;
                default:
                {
                    memcpy(destbuf, buffer, len);
                    destlen = len;
                }
                break; //   明通
                }

                sendto(param->dst_pair->rtp_sock, /*buffer*/destbuf, /*len*/destlen, 0,
                    (struct sockaddr*)&rtp_dst_addr,
                    sizeof(rtp_dst_addr));
            }
        }

        /* Check RTCP socket */
        if (PJ_FD_ISSET(param->src_pair->rtcp_sock, &rdset)) {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);

            int len = recvfrom(param->src_pair->rtcp_sock, buffer,
                MAX_PACKET_SIZE, 0,
                (struct sockaddr*)&addr, &addr_len);

            if (len > 0) {
                sendto(param->dst_pair->rtcp_sock, buffer, len, 0,
                    (struct sockaddr*)&rtcp_dst_addr,
                    sizeof(rtcp_dst_addr));
            }
        }
    }

    PJ_LOG(2, (THIS_FILE, "Media relay thread stopped"));
    return 0;
}

/* Start media relay thread */
pj_status_t start_media_relay_thread(pj_pool_t* pool,
    relay_thread_param* param,
    pj_thread_t** p_thread)
{
    return pj_thread_create(pool, "media_relay", &relay_thread_func,
        param, 0, 0, p_thread);
}

/* create UDP socket bound to local_ip ephemeral port */

static pj_bool_t setup_media_bridge_for_map(std::shared_ptr<ccsua::uasess> _uasess)
{
    if (!_uasess)
        return PJ_FALSE;
    if (_uasess->is_hung_up()) {
        return PJ_FALSE; // 如果是确认前被挂断，不执行转发桥的创建
    }

    // Parse remote media addresses from SDPs
    char uas_remote_ip[64], uac_remote_ip[64];
    int uas_rtp_port = 0, uas_rtcp_port = 0;
    int uac_rtp_port = 0, uac_rtcp_port = 0;

    uas_rtp_port = _uasess->get_uas_remote_rtp();
    uas_rtcp_port = _uasess->get_uas_remote_rtcp();
    uac_rtp_port = _uasess->get_uac_remote_rtp();
    uac_rtcp_port = _uasess->get_uac_remote_rtcp();
    memset(uas_remote_ip, 0, sizeof(uas_remote_ip));
    memset(uac_remote_ip, 0, sizeof(uac_remote_ip));
    memcpy(uas_remote_ip, _uasess->get_uas_remote_ip().c_str(), _uasess->get_uas_remote_ip().size());
    memcpy(uac_remote_ip, _uasess->get_uac_remote_ip().c_str(), _uasess->get_uac_remote_ip().size());
        
    // Create relay threads
    // UAS -> UAC direction (phone to upstream)
    //relay_thread_param* param_uas = PJ_POOL_ZALLOC_T(g_pool, relay_thread_param);
    relay_thread_param* param_uas = new relay_thread_param();
    memset(param_uas, 0, sizeof(relay_thread_param));
    param_uas->src_pair = &_uasess->get_uas_media();      // Use media sockets from call_map
    param_uas->dst_pair = &_uasess->get_uac_media();
    pj_ansi_strncpy(param_uas->dst_rtp_addr, uac_remote_ip, sizeof(param_uas->dst_rtp_addr));
    param_uas->dst_rtp_port = uac_rtp_port;
    pj_ansi_strncpy(param_uas->dst_rtcp_addr, uac_remote_ip, sizeof(param_uas->dst_rtcp_addr));
    param_uas->dst_rtcp_port = uac_rtcp_port;
    //param_uas->is_active = _uasess->active();
    param_uas->_uasess = _uasess;

    // UAC -> UAS direction (upstream to phone)
    //relay_thread_param* param_uac = PJ_POOL_ZALLOC_T(g_pool, relay_thread_param);
    relay_thread_param* param_uac = new relay_thread_param();
    memset(param_uac, 0, sizeof(relay_thread_param));
    param_uac->src_pair = &_uasess->get_uac_media();      // Use media sockets from call_map
    param_uac->dst_pair = &_uasess->get_uas_media();
    pj_ansi_strncpy(param_uac->dst_rtp_addr, uas_remote_ip, sizeof(param_uac->dst_rtp_addr));
    
    param_uac->dst_rtp_port = uas_rtp_port;
    pj_ansi_strncpy(param_uac->dst_rtcp_addr, uas_remote_ip, sizeof(param_uac->dst_rtcp_addr));
    param_uac->dst_rtcp_port = uas_rtcp_port;
    //param_uac->is_active = _uasess->active();
    param_uac->_uasess = _uasess;

    // Create and start relay threads
    pj_status_t status;
    /* 呼叫方是内端: UAS侧是接收后加密转发; UAC侧是接收后解密转发
    * 呼叫方是外端: UAS侧是接收后解密转发; UAC侧是接收后加密转发
    * 明通: 一方无法加密时使用明通
    */
    if (_uasess->is_remote_can_enc()) {
        if (_uasess->caller_s_isinner()) {
            param_uas->body_process = E_ENCRYPT_TRANS;
            param_uac->body_process = E_DECRYPT_TRANS;
        }
        else {
            param_uas->body_process = E_DECRYPT_TRANS;
            param_uac->body_process = E_ENCRYPT_TRANS;
        }
    }
    else {  //  明通一定是要得到确认才行，不然不能建立。
        //  先设置成明通，加密参数还没有协商出来
        param_uas->body_process = E_PASSTHROU;
        param_uac->body_process = E_PASSTHROU;
    }
    
    status = start_media_relay_thread(g_pool, param_uas, &_uasess->uas_thread);
    if (status != PJ_SUCCESS) {
        PJ_LOG(1, (THIS_FILE, "Failed creating UAS relay thread"));
        return PJ_FALSE;
    }

    status = start_media_relay_thread(g_pool, param_uac, &_uasess->uac_thread);
    if (status != PJ_SUCCESS) {
        PJ_LOG(1, (THIS_FILE, "Failed creating UAC relay thread"));
        if (_uasess->uas_thread) {
            _uasess->stop_running();
            pj_thread_join(_uasess->uas_thread);
        }
        return PJ_FALSE;
    }

    _uasess->set_running();


    PJ_LOG(2, (THIS_FILE, "Media bridge established: "
        "UAS RTP %d->%s:%d RTCP %d->%s:%d, "
        "UAC RTP %d->%s:%d RTCP %d->%s:%d",
        _uasess->get_uas_rtp_port(), uac_remote_ip, uac_rtp_port,
        _uasess->get_uas_rtcp_port(), uac_remote_ip, uac_rtcp_port,
        _uasess->get_uac_rtp_port(), uas_remote_ip, uas_rtp_port,
        _uasess->get_uas_rtcp_port(), uas_remote_ip, uas_rtcp_port));

    return PJ_TRUE;
}

/* ====== REGISTER server-side (401 + digest check) ====== */
static pj_bool_t handle_register_server(pjsip_rx_data* rdata) {

    pjsip_transaction *regtsx = pjsip_rdata_get_tsx(rdata);
    
    if (rdata->msg_info.msg->line.req.method.id != PJSIP_REGISTER_METHOD) return PJ_FALSE;
    pj_pool_t* pool = rdata->tp_info.pool;
    pjsip_tx_data* tdata;
    char aor[128] = { 0 }, contact[256] = { 0 };
    if (rdata->msg_info.from && rdata->msg_info.from->uri) {
        pj_str_t s; s.ptr = (char *)pj_pool_alloc(pool, 256); s.slen = 256;
        s.slen = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, rdata->msg_info.from->uri, s.ptr, 256);
        pj_ansi_snprintf(aor, sizeof(aor), "%s", s.ptr);
    }
    //  wg. 20251018, contact需要从头部中获取,而不是从msg_info.msg->contact中获取，因为msg_info.msg->contact可能为空
	pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
    pjsip_expires_hdr *expi_hdr = (pjsip_expires_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_EXPIRES, NULL);
    
    //if (rdata->msg_info.msg->contact && rdata->msg_info.msg->contact->count > 0 && rdata->msg_info.msg->contact->m[0].uri) {    
    if (contact_hdr && contact_hdr->uri) {
        pj_str_t s; s.ptr = (char *)pj_pool_alloc(pool, 256); s.slen = 256;
        s.slen = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, contact_hdr->uri, s.ptr, 256);
        pj_ansi_snprintf(contact, sizeof(contact), "%s", s.ptr);
    }
    char* auth_raw = get_hdr_value_raw(rdata->msg_info.msg, "Authorization");
    pj_str_t wwwauth_str = pj_str((char*)"WWW-Authenticate");
    if (!auth_raw) {
        char nonce[33]; gen_nonce(nonce);
        char www[512]; pj_ansi_snprintf(www, sizeof(www), "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"", REALM_DEFAULT, nonce);
        if (pjsip_endpt_create_response(g_endpt, rdata, 401, NULL, &tdata) == PJ_SUCCESS) {
			
			pj_str_t www_str = pj_str(www);
            pjsip_generic_string_hdr* gh = pjsip_generic_string_hdr_create(pool, &wwwauth_str, &www_str);
            pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)gh);
            pjsip_endpt_send_response2(g_endpt, rdata, tdata, 0, NULL);
            PJ_LOG(3, (THIS_FILE, "Sent 401 to %s", aor));
            return PJ_TRUE;
        }
    }
    else {
        const char* p = auth_raw; while (*p == ' ') p++;
        if (strncasecmp(p, "Digest ", 7) == 0) p += 7;
        auth_kv_t* kv = parse_auth_params(p);
        const char* username = auth_kv_get(kv, "username");
        const char* realm = auth_kv_get(kv, "realm");
        const char* uri = auth_kv_get(kv, "uri");
        pj_bool_t ok = PJ_FALSE;
        if (username && strcmp(username, LOCAL_REG_USER) == 0) {
            ok = validate_digest(username, realm ? realm : REALM_DEFAULT, LOCAL_REG_PASS, rdata->msg_info.msg->line.req.method.name.ptr, uri, kv);
        }
        if (!ok) {
            char nonce[33]; gen_nonce(nonce);
            char www[512]; pj_ansi_snprintf(www, sizeof(www), "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"", REALM_DEFAULT, nonce);
			pj_str_t pwww = pj_str(www);
            if (pjsip_endpt_create_response(g_endpt, rdata, 401, NULL, &tdata) == PJ_SUCCESS) {
                pjsip_generic_string_hdr* gh = pjsip_generic_string_hdr_create(pool, &wwwauth_str, &pwww);
                pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)gh);
                pjsip_endpt_send_response2(g_endpt, rdata, tdata, 0, NULL);
            }
            PJ_LOG(3, (THIS_FILE, "REGISTER auth failed for %s", aor));
            return PJ_TRUE;
        }
        else {
            if (pjsip_endpt_create_response(g_endpt, rdata, 200, NULL, &tdata) == PJ_SUCCESS) {
                if (contact[0]) {
                    pj_str_t pcontact = pj_str((char*)"Contact");
                    pj_str_t pcontactvalue = pj_str(contact);
                    pjsip_generic_string_hdr* ch = pjsip_generic_string_hdr_create(pool, &pcontact, &pcontactvalue);
                    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)ch);
                }
                pjsip_endpt_send_response2(g_endpt, rdata, tdata, 0, NULL);
            }

            //  如果 expi 值为0,则为删除注册信息
            if (NULL != expi_hdr && expi_hdr->ivalue == 0) {
                g_routemap.remove_clt_reg(rdata);
            }
            else {
                //  当成注册用户处理
                g_routemap.save_clt_reg(rdata);
            }
            //  根据请求中的Expired判断是新注册还是删除,并且需要保留注册的时间
            //if (aor[0] && contact[0]) save_contact(aor, contact);
            PJ_LOG(3, (THIS_FILE, "REGISTER OK %s => %s", aor, contact));
            return PJ_TRUE;
        }
    }
    return PJ_FALSE;
}

/* ====== Upstream REGISTER (UAC) - minimal: send REGISTER, on 401 compute Authorization and resend ====== */
typedef struct reg_uac_state {
    pjsip_transaction* tsx;
    int stage;
} reg_uac_state_t;
static reg_uac_state_t g_reg_uac = { NULL, 0 };

static pjsip_tx_data* build_register_tx(const char* from_uri, const char* to_uri, const char* auth_header) {
    pjsip_tx_data* tdata;
    pj_str_t fromuri = pj_str((char*)from_uri);
    pj_str_t touri = pj_str((char*)to_uri);
    //  wg. 20251018, 这个注册请求需要重新创建，和源代码提供的方法不同    
    char contact[256]; pj_ansi_snprintf(contact, sizeof(contact), "<sip:%s@%s;transport=udp>", UPSTREAM_USER, LOCAL_IP_UPSTREAM);
    pj_str_t ppcontactvalue = pj_str(contact);
    char _callid[33], callid_in[64];
    memset(_callid, 0, sizeof(_callid));
    memset(callid_in, 0, sizeof(callid_in));
    snprintf(callid_in, sizeof(callid_in), "%s,%d", contact, (int)time(NULL));
    md5_hex(callid_in, _callid);
    //  _callid 取16个字符
    _callid[16] = 0x00;    
    g_pcallid = pj_strdup3(g_pool, _callid);
    if (pjsip_endpt_create_request(g_endpt, 
        &pjsip_register_method, //  method
        &touri, //NULL, //    target
		&fromuri, //    from
        &touri, //    to
        &ppcontactvalue, //    contact
		&g_pcallid, //    call_id
        ccsua::sessman::next_cseq(),
		NULL,//   text
		&tdata  //  out_tdata
    ) != PJ_SUCCESS) return NULL;
    pj_pool_t* pool = g_pool;

    /* Authorization if provided */
    if (auth_header && auth_header[0]) {
		pj_str_t pauthvalue = pj_str((char*)auth_header);
		pj_str_t pauth = pj_str((char*)"Authorization");
        pjsip_generic_string_hdr* ah = pjsip_generic_string_hdr_create(pool, &pauth, &pauthvalue);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)ah);
    }
    //  wg. 20251031, expires似乎没有生成,不然flexip报invalid request.
    pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(tdata->pool, g_expired);
    expires_hdr->ivalue = g_expired;
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)expires_hdr);

    return tdata;
}

static pj_status_t start_upstream_register(void) {
    pj_status_t status = PJ_SUCCESS;
    //  wg. 20251027, 联系地址是本地向sip注册的IP    
    char from_uri[128]; pj_ansi_snprintf(from_uri, sizeof(from_uri), "sip:%s@%s", UPSTREAM_USER, SIP_SERVER);
    char to_uri[128]; pj_ansi_snprintf(to_uri, sizeof(to_uri), "sip:%s", SIP_SERVER);
    pjsip_tx_data* tdata = build_register_tx(from_uri, to_uri, NULL);
    if (!tdata) return PJ_EINVAL;
    pjsip_transaction* tsx = NULL;
    status = pjsip_tsx_create_uac(&mod_b2b, tdata, &tsx);
	pj_assert(status == PJ_SUCCESS);
    if (!tsx) { pjsip_tx_data_dec_ref(tdata); return PJ_EINVAL; }
    g_reg_uac.tsx = tsx; g_reg_uac.stage = 0;
    pj_status_t st = pjsip_tsx_send_msg(tsx, tdata);
    PJ_LOG(3, (THIS_FILE, "Sent upstream REGISTER (initial)"));
    return st;
}

/* compute Authorization header for given WWW-Authenticate */
static char* compute_auth_header_for_www(const char* www_val, const char* username, const char* password, const char* method, const char* uri) {
    auth_kv_t* kv = parse_auth_params(www_val);
    const char* realm = auth_kv_get(kv, "Digest realm");
    const char* nonce = auth_kv_get(kv, "nonce");
    const char* qop = auth_kv_get(kv, "qop");
    const char* opaque = auth_kv_get(kv, "opaque");
    if (!realm || !nonce) return NULL;
    char ha1_in[512]; pj_ansi_snprintf(ha1_in, sizeof(ha1_in), "%s:%s:%s", username, realm, password);
    char ha1[33]; md5_hex(ha1_in, ha1);
    char ha2_in[512]; pj_ansi_snprintf(ha2_in, sizeof(ha2_in), "%s:%s", method, uri);
    char ha2[33]; md5_hex(ha2_in, ha2);
    char resp_in[1024];
    char cnonce[33]; gen_nonce(cnonce);
    const char* nc = "00000001";
    //  wg. 20251021, qop加入后似乎验证有问题,先暂时去掉试试
    if (qop && strstr(qop, "auth")) pj_ansi_snprintf(resp_in, sizeof(resp_in), "%s:%s:%s:%s:auth:%s", ha1, nonce, nc, cnonce, ha2);
    else pj_ansi_snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce, ha2);
    char response[33]; md5_hex(resp_in, response);
    char* hdr = (char*)pj_pool_alloc(g_pool, 1024);
    pj_ansi_snprintf(hdr, 1024, "Digest realm=\"%s\", username=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=MD5",
        realm, username, nonce, uri, response);
    if (qop && strstr(qop, "auth")) pj_ansi_snprintf(hdr + strlen(hdr), 1024 - strlen(hdr), ", qop=auth, nc=00000001, cnonce=\"%s\"", cnonce);
    //  wg. 20251021, opaque也需要添加进去,不然导致认证不通过.
    if (opaque) {
        pj_ansi_snprintf(hdr + strlen(hdr), 1024 - strlen(hdr), ", opaque=\"%s\"", opaque);
    }
    return hdr;
}

/* send outgoing INVITE and create mapping */
//  返回的是错误码，错误码直接响应给请求方
static pj_status_t send_out_invite_and_map(pjsip_rx_data* rdata) {
	pj_status_t status = PJ_SUCCESS;

	//  使用uasess方式实现..
	std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_sess_by_invite(rdata);
	if (!_uasess) {
		pj_assert(false);
		return PJSIP_SC_NOT_FOUND;
	}

	char* pconnaddr = NULL, poriguser[64];
	char* puasaddr = NULL, * puacaddr = NULL;
	memset(poriguser, 0, sizeof(poriguser));
	bool is_callout = _uasess->caller_s_isinner();
	if (is_callout) {
		pconnaddr = (char*)LOCAL_IP_UPSTREAM;
		memcpy(poriguser, UPSTREAM_USER, strlen(UPSTREAM_USER));

		puasaddr = (char*)LOCAL_IP_PHONE;
		puacaddr = (char*)LOCAL_IP_UPSTREAM;
	}
	else {
		pconnaddr = (char*)LOCAL_IP_PHONE;
		pjsip_from_hdr* pfrom = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);
		pjsip_sip_uri* psuri = (pjsip_sip_uri*)pjsip_uri_get_uri(pfrom->uri);
		memcpy(poriguser, psuri->user.ptr, psuri->user.slen);

		puasaddr = (char*)LOCAL_IP_UPSTREAM;
		puacaddr = (char*)LOCAL_IP_PHONE;

        //  外部呼入的，解析 INVITE 中是否有感兴趣的密钥协商
        //printf("Check INVITE REQUEST is our B2BUA???\n");
        //ccsua::sesscipher::create_by_rx_data(rdata);
	}

	/* Create media sockets early */
	media_sock_pair_t uas_media, uac_media;
	memset(&uas_media, 0, sizeof(media_sock_pair_t));
	memset(&uac_media, 0, sizeof(media_sock_pair_t));
	status = create_media_transport(puasaddr, &uas_media);
	if (status != PJ_SUCCESS) {
		//cleanup_call_map(m);
        g_sess.removesess(_uasess);
		return PJSIP_SC_NOT_ACCEPTABLE_ANYWHERE;
	}

	status = create_media_transport(puacaddr, &uac_media);
	if (status != PJ_SUCCESS) {
		//cleanup_call_map(m);
        g_sess.removesess(_uasess);
        close_media_transport(&uas_media);
		return PJSIP_SC_NOT_ACCEPTABLE_ANYWHERE;
	}

	//  根据创建的媒体端口，设置 uasess 实例的媒体端口
	_uasess->set_uac_rtp_port(uac_media.rtp_port);
	_uasess->set_uac_rtcp_port(uac_media.rtcp_port);
	_uasess->set_uas_rtp_port(uas_media.rtp_port);
	_uasess->set_uas_rtcp_port(uas_media.rtcp_port);
	_uasess->set_uac_media(uac_media);
	_uasess->set_uas_media(uas_media);

	//  当接收到invite后，需要将invite转发
	_uasess->set_last_uas_request(rdata); //    保存最后一次接收到的UAS侧请求
	//  创建UAC侧的请求并等待转发
	pjsip_tx_data* puac_invite = _uasess->create_uac_invite();
    if (nullptr == puac_invite) {        
        close_media_transport(&uas_media);
        close_media_transport(&uac_media);
        return PJSIP_SC_NOT_ACCEPTABLE_ANYWHERE;
    }

	//  创建完成UAC INVITE后一定要更新它的SDP，避免媒体端口异常
	_uasess->update_uac_invite_sdp();

	//  wg. 20251029, 生成的 request data 需要根据方向手动指定传输端点
	pjsip_transaction* tsx = NULL;

	status = pjsip_tsx_create_uac(&mod_b2b, puac_invite, &tsx);
	pj_assert(PJ_SUCCESS == status);
    if (PJ_SUCCESS != status) {
        close_media_transport(&uas_media);
        close_media_transport(&uac_media);
        return PJSIP_SC_NOT_ACCEPTABLE_ANYWHERE;
    }

	pjsip_tpselector tpsel;
	tpsel.type = PJSIP_TPSELECTOR_TRANSPORT;

	if (is_callout) {   //  如果是内部打出去的，创建的请求需要使用外发端口
		tpsel.u.transport = g_transport_outer;
	}
	else {
		tpsel.u.transport = g_transport_inner;
	}
	status = pjsip_tx_data_set_transport(puac_invite, &tpsel);
	pj_assert(status == PJ_SUCCESS);
	status = pjsip_tsx_set_transport(tsx, &tpsel);
	pj_assert(status == PJ_SUCCESS);

	pj_status_t st = pjsip_tsx_send_msg(tsx, puac_invite);
    if (PJ_SUCCESS != st) {
        pj_assert(false);
        close_media_transport(&uas_media);
        close_media_transport(&uac_media);
        return PJSIP_SC_NOT_ACCEPTABLE_ANYWHERE;
    }
	return st;

}

/* forward response from UAC to UAS and create media bridge on 2xx */
static pj_bool_t forward_response_to_uas(pjsip_rx_data* rdata) {

	std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_by_response(rdata);
	if (!_uasess) {
		return PJ_FALSE;
	}
    if (_uasess->caller_s_isinner() && rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD) {
        //  内部呼出的，解析 INVITE 响应中 中是否有感兴趣的密钥协商
        //printf("Check response is our B2BUA???\n");
        //ccsua::sesscipher::create_by_rx_data(rdata);
    }
	_uasess->set_last_uac_response(rdata);

	pjsip_tx_data* uas_response = _uasess->create_uas_response(rdata);
    int code = rdata->msg_info.msg->line.status.code;
    //  如果是 180 INVITE, 检测对端的User-Agent
    if (180 == code && rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD) {
        //  获取User-Agent
        pjsip_user_agent_hdr* uac_user_agent_hdr = (pjsip_user_agent_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_USER_AGENT_UNIMP, NULL);
        const pj_str_t _ua_name = { (char*)"User-Agent", 10 };
        uac_user_agent_hdr = (pjsip_user_agent_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &_ua_name, NULL);
        if (nullptr == uac_user_agent_hdr) {
            //  无User-Agent头，对端可能为普通话机，对端可能为ccs securit voip,但是sip服务或者其它代理把user-agent给漏掉了
            //  因此这个判断并不一定合适，可能需要在接通的时候验证SDP信息更好
        }
        else {
            //std::cout << "Remote User agent: " << std::string(uac_user_agent_hdr->hvalue.ptr, uac_user_agent_hdr->hvalue.slen) << std::endl;
        }
    }
    
	//  如果是200 INVITE,需要搭建通话转发桥--等自动语音播放完成后再创建媒体桥

	pjsip_endpt_send_response2(g_endpt, _uasess->get_last_uas_request(), uas_response, 0, NULL);

	/* 清除会话uasess */
	if (code >= 300 || (code >= 200 && code < 300 && rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD)) {
		PJ_LOG(1, (THIS_FILE, "Call terminated (code=%d), cleaning up, Need todo", code));
		//cleanup_call_map(m);
        g_sess.removesess(_uasess);
	}

	return PJ_TRUE;    
}

/* ====== module request/response handlers ====== */
static pj_bool_t module_on_rx_request(pjsip_rx_data* rdata) {
    pj_status_t status = PJ_SUCCESS;
    pjsip_method method = rdata->msg_info.msg->line.req.method;
    if (method.id == PJSIP_REGISTER_METHOD) {
        return handle_register_server(rdata);
    }
    else if (method.id == PJSIP_INVITE_METHOD) {
        //  wg. 20251022, 请求处理完成后立即回复100,避免它再次呼叫
        pjsip_tx_data* tx100 = NULL;
        if (pjsip_endpt_create_response(g_endpt, rdata, 100, NULL, &tx100) == PJ_SUCCESS) {
            PJ_LOG(3, (THIS_FILE, "Sent 100 Trying to incoming INVITE Immedily."));
            pjsip_endpt_send_response2(g_endpt, rdata, tx100, 0, NULL);
        }

        status = send_out_invite_and_map(rdata);
        if (PJ_SUCCESS != status) {
            pjsip_tx_data* txerr = NULL;
            if (pjsip_endpt_create_response(g_endpt, rdata, status, NULL, &txerr) == PJ_SUCCESS) {
                PJ_LOG(3, (THIS_FILE, "Sent 100 Trying to incoming INVITE Immedily."));
                pjsip_endpt_send_response2(g_endpt, rdata, txerr, 0, NULL);
            }
        }
        
        return PJ_TRUE;
    }
    else if (method.id == PJSIP_BYE_METHOD /* || method.id == PJSIP_INFO_METHOD || method.id == PJSIP_UPDATE_METHOD || method.id == PJSIP_REFER_METHOD*/) {
        /* transparent forwarding TODO: simplified - let stack default */
        /* Forward BYE to upstream and cleanup resources */
        //  BYE是双向可发送的...
		std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_by_request(rdata);
		if (!_uasess) {
			return PJ_FALSE;
		}
        _uasess->hung_up(); //  接收到bye时可能语音还未播放完成，通话桥未建立
		_uasess->set_last_uas_request(rdata);
		pjsip_tx_data* bye = _uasess->create_uac_bye();

		pjsip_transaction* tsx = NULL; // pjsip_tsx_create_uac(tdata->tp_info.pool, tdata, NULL);
		status = pjsip_tsx_create_uac(&mod_b2b, bye, &tsx);
		if (!tsx)
		{
            return PJ_FALSE;
		}
        pjsip_tpselector tpsel;
        tpsel.type = PJSIP_TPSELECTOR_TRANSPORT;
        tpsel.u.transport = g_transport_inner;
        //  获取请求的发起方
        if (_uasess->last_uas_is_inner()) { //  如果是内网接收到的BYE，则需要转发到外网 
            tpsel.u.transport = g_transport_outer;
        }
        else {
            tpsel.u.transport = g_transport_inner;
        }
        //  需要设置传输端点
        status = pjsip_tx_data_set_transport(bye, &tpsel);
        pj_assert(status == PJ_SUCCESS);
        status = pjsip_tsx_set_transport(tsx, &tpsel);
        pj_assert(status == PJ_SUCCESS);

        pjsip_tsx_send_msg(tsx, bye);
		//  BYE的请求处理完成后需要清理掉会话
		g_sess.removesess(_uasess);

        //  接收到BYE后立即给它回确认.
        pjsip_tx_data* txbye = NULL;
        if (pjsip_endpt_create_response(g_endpt, rdata, 200, NULL, &txbye) == PJ_SUCCESS) {
            PJ_LOG(3, (THIS_FILE, "Sent 100 Trying to incoming INVITE Immedily."));
            pjsip_endpt_send_response2(g_endpt, rdata, txbye, 0, NULL);
        }
		return PJ_TRUE;

    }
    else if (method.id == PJSIP_ACK_METHOD) {
        /* ACK forwarding TODO - for 2xx ACK require mapping */
        /* Find call map by Call-ID and, if present, send stored ACK to upstream if any.
           Also ACKs for non-2xx can be ignored (stateless). */
        if (!rdata->msg_info.cid) return PJ_FALSE;

		//  使用 uasess 的方式实现
		std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_by_request(rdata);
		if (!_uasess) {
			return PJ_FALSE;
		}
		pjsip_tx_data* ack = _uasess->create_uac_ack();

		//  wg. 20251029, 生成的 request data 需要根据方向手动指定传输端点
		pjsip_tpselector tpsel;
		tpsel.type = PJSIP_TPSELECTOR_TRANSPORT;
		//  如果是内部打出去的，创建的请求需要使用外发端口传出
		if (_uasess->caller_s_isinner()) {
			tpsel.u.transport = g_transport_outer;
		}
		else {
			tpsel.u.transport = g_transport_inner;
		}
		pj_status_t status = pjsip_tx_data_set_transport(ack, &tpsel);
		pj_assert(PJ_SUCCESS == status);
		status = pjsip_endpt_send_request_stateless(g_endpt, ack, NULL, NULL);
		if (status != PJ_SUCCESS) {
			PJ_LOG(1, (THIS_FILE, "Failed to send stored ACK to upstream (err=%d)", status));
		}
		else {
			PJ_LOG(2, (THIS_FILE, "Sent ACK to upstream for call"));
		}

        //  wg. 20251107, 自动语音在接收到ACK后再触发，避免话机端可能没准备好无法接收到语音信息
        //  ACK可能在多种场景下会发送，语音提示只在通话接通的INVITE 200成功后的ACK发起
        //  现在只处理以下同时满足的情况: INVITE 200接收到; 对端无法加密; 会话媒体未建立起
        if (_uasess->is_invite_ok() && !_uasess->is_running()) {
            //  对端不能进行加密通话时，先回复 200 OK并且自动播放提示语单，转发桥暂不创建，等待话机确认后再创建转发桥
            //  当前 media_stream 已经和内网话机建立了连接，应该可以播放语音
            //  wg. 20251111, 语音播放需要移到单独的播放线程，避免主线程阻塞而不响应挂机请求，需要定义一个播放任务，任务中
            //  至少要有待播放的音频、播放完成操作、取消时操作。在这个位置播放完成时需要建立通话媒体桥；取消时不建立通话媒体桥
            //  和做其它的一些清理。
            if (!_uasess->is_remote_can_enc()) {
                //_uasess->play_remote_is_normal();
                //  播放函数
                std::function<void(void)> _taskfunc = std::bind(&ccsua::uasess::play_remote_is_normal, _uasess->shared_from_this());
                //  播放完成函数
                std::function<void(std::shared_ptr<ccsua::uasess>)> _okfunc = std::bind(setup_media_bridge_for_map, std::placeholders::_1);
                //  提示语音播放完毕后建立通话转发桥
                //setup_media_bridge_for_map(_uasess);
                g_mediathread.add_task(_uasess, _taskfunc, _okfunc);
            }
            
            return PJ_TRUE;
        }
        
		return PJ_TRUE;
    }
	else if (method.id == PJSIP_CANCEL_METHOD) {
	    //  cancel释放uasess
	    if (!rdata->msg_info.cid) return PJ_FALSE;

	    //  使用 uasess 的方式实现
	    std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_by_request(rdata);
	    if (!_uasess) {
		    return PJ_FALSE;
	    }
        _uasess->hung_up();
        g_sess.removesess(_uasess);
    }
    return PJ_FALSE;
}
static pj_bool_t module_on_rx_response(pjsip_rx_data* rdata) {
	pjsip_msg* msg = rdata->msg_info.msg;
	int code = msg->line.status.code;
	pj_status_t status = PJ_SUCCESS;
	//  INVITE 的100的是否可以不用处理?
	if (100 == code && PJSIP_INVITE_METHOD == rdata->msg_info.cseq->method.id) {
		return PJ_TRUE;
	}

	/* Handle 401/407 challenges */
	if ((code == 401 || code == 407) &&
		rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD)
	{
		//  使用 uasess 完成
		std::shared_ptr<ccsua::uasess> _uasess = g_sess.get_by_response(rdata);
		if (!_uasess) {
			return PJ_FALSE;
		}
		/* Initialize auth session if not yet */
		if (!g_auth.auth_initialized) {
			pj_status_t status = init_auth_sess();
			if (status != PJ_SUCCESS) {
				PJ_LOG(1, (THIS_FILE, "Failed to initialize auth session"));
				return PJ_TRUE;
			}
		}

		/* Create new request with auth headers */
		pjsip_tx_data* new_request = NULL;
		pj_status_t status;

		//  wg. 20251021, 如果是INVITE，它根据rdata中的信息来生成重认证消息, 里面的url可能是被叫方的
		//  wg. 20251022, 新生成的request的cseq是否需要更新? 在asterisk中测试发现需要更新，否则会被拒绝

		status = pjsip_auth_clt_reinit_req(&g_auth.auth_sess,
			rdata,
			_uasess->get_last_uac_request(),
			&new_request);
		if (PJSIP_EAUTHSTALECOUNT == status) {
			printf("-------------------\n\n");
			printf("    Too may reinit auth.\n");
			printf("-------------------\n\n");
			return PJ_FALSE;
		}

		pj_assert(PJ_SUCCESS == status);
		//  重置sess中最后一次向UAC发送的响应
		_uasess->set_last_uac_request(new_request);
		//  同时session中uac的cseq递增
		_uasess->increase_cseq();
		//  wg. 20251022, 强制更新cseq, 每发送一次请求都需要更新一次cseq
		PJSIP_MSG_CSEQ_HDR(new_request->msg)->cseq++;

		pj_assert(PJSIP_MSG_CSEQ_HDR(new_request->msg)->cseq == _uasess->cseq());

		//  contact
		pjsip_transaction* tsx = nullptr;
		if (status == PJ_SUCCESS) {
			/* Update transaction */
			status = pjsip_tsx_create_uac(&mod_b2b, new_request, &tsx);
			pj_assert(status == PJ_SUCCESS);
			if (tsx) {
				status = pjsip_tsx_send_msg(tsx, new_request);
				PJ_LOG(3, (THIS_FILE, "Resent INVITE with %s auth",
					(code == 401 ? "WWW" : "Proxy")));
				return PJ_TRUE;
			}
		}
		else {
			pj_assert(false);
			return PJ_FALSE;
		}
		return PJ_TRUE;
	}

	/* Upstream REGISTER handling: if 401, compute Authorization and resend REGISTER */
	if (rdata->msg_info.cseq->method.id == PJSIP_REGISTER_METHOD && code == 401) {
		char* www_val = get_hdr_value_raw(msg, "WWW-Authenticate");
		if (www_val) {
			//  wg. 20251027, 联系地址是本地向SIP注册的地址
			char from_uri[128]; pj_ansi_snprintf(from_uri, sizeof(from_uri), "sip:%s@%s", UPSTREAM_USER, SIP_SERVER);
			char reg_uri[128]; pj_ansi_snprintf(reg_uri, sizeof(reg_uri), "sip:%s@%s", UPSTREAM_USER, SIP_SERVER);
			char* auth_hdr = compute_auth_header_for_www(www_val, UPSTREAM_USER, UPSTREAM_PASS, "REGISTER", reg_uri);
			if (auth_hdr) {
				pjsip_tx_data* tdata = build_register_tx(from_uri, reg_uri, auth_hdr);
				if (tdata) {
					//pjsip_transaction* tsx = pjsip_tsx_create_uac(tdata->tp_info.pool, tdata, NULL);
					pjsip_transaction* tsx = NULL;
					status = pjsip_tsx_create_uac(&mod_b2b, tdata, &tsx);
					pj_assert(PJ_SUCCESS == status);
					if (tsx) { g_reg_uac.tsx = tsx; g_reg_uac.stage = 1; pjsip_tsx_send_msg(tsx, tdata); PJ_LOG(3, (THIS_FILE, "Resent REGISTER with Authorization")); }
					else pjsip_tx_data_dec_ref(tdata);
				}
			}
		}
		return PJ_TRUE;
	}
	/* Process other responses... */
	return forward_response_to_uas(rdata);
}

/* ====== init and main ====== */
static int init_stack(void) {
    pj_status_t status;
    pj_init();
    pj_caching_pool_init(&g_cp, &pj_pool_factory_default_policy, 0);
    g_pool = pj_pool_create(&g_cp.factory, "b2bua-pool", 4000, 4000, NULL);
    status = pjsip_endpt_create(&g_cp.factory, NULL, &g_endpt);
    if (status != PJ_SUCCESS) { fprintf(stderr, "pjsip_endpt_create failed\n"); return -1; }

    /* 初始化事务层 */
    status = pjsip_tsx_layer_init_module(g_endpt);
    if (status != PJ_SUCCESS) {
        fprintf(stderr, "pjsip_tsx_layer_init_module failed\n"); return -1;
        return status;
    }

    //  wg. 20251025, 如果不初始化UA层,会怎么样, 初始化UA层后需要有传输对话 dialog, 现在好像没有做.
    /* 初始化UA层 */
#ifdef AI
    status = pjsip_ua_init_module(g_endpt, NULL);
    if (status != PJ_SUCCESS) {
        fprintf(stderr, "pjsip_ua_init_module failed\n"); return -1;
        return status;
    }
#endif

    /* create UDP transports bound to local IPs */
    {
        pjsip_transport* tp;
        pj_sockaddr_in addr;
        pj_bzero(&addr, sizeof(addr));
        addr.sin_family = pj_AF_INET();
        addr.sin_addr = pj_inet_addr2(LOCAL_IP_UPSTREAM);
        addr.sin_port = pj_htons(SIP_PORT);
        status = pjsip_udp_transport_start(g_endpt, &addr, NULL, 1, &tp);
        if (status != PJ_SUCCESS) { fprintf(stderr, "failed create upstream transport\n"); return -1; }
        g_transport_outer = tp;
        pj_bzero(&addr, sizeof(addr));
        addr.sin_family = pj_AF_INET();
        addr.sin_addr = pj_inet_addr2(LOCAL_IP_PHONE);
        addr.sin_port = pj_htons(SIP_PORT);
        status = pjsip_udp_transport_start(g_endpt, &addr, NULL, 1, &tp);
        if (status != PJ_SUCCESS) { fprintf(stderr, "failed create phone transport\n"); return -1; }
        g_transport_inner = tp;
    }
    pjsip_endpt_register_module(g_endpt, &mod_b2b);
    /*
     * Register message logger module.
     */
    status = pjsip_endpt_register_module(g_endpt, &msg_logger);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    status = pjmedia_endpt_create(&g_cp.factory, NULL, 1, &g_med_endpt);
    if (status != PJ_SUCCESS) { fprintf(stderr, "pjmedia_endpt_create failed\n"); return -1; }
    //  wg. 20251106, b2bua需要有媒体播放，因此需要注册一系列编解码器用于媒体播放..

    pjmedia_audio_codec_config _codecfg;
    pjmedia_audio_codec_config_default(&_codecfg);
    status = pjmedia_codec_register_audio_codecs(g_med_endpt, &_codecfg);
    //status = pjmedia_codec_opus_init(g_med_endpt);
    pj_assert(PJ_SUCCESS == status);
    //status = pjmedia_codec_gsm_init(g_med_endpt);
    //pj_assert(PJ_SUCCESS == status);
    //pjmedia_codec_speex_init(g_med_endpt);

    //  wg. 20251106, media_event_mgr 需要创建.
    
    status = pjmedia_event_mgr_create(g_pool, PJMEDIA_EVENT_MGR_NO_THREAD, &g_media_event_mgr);
    pj_assert(PJ_SUCCESS == status);
    
    return 0;
}

int main(int argc, char* argv[]) {
    srand((unsigned int)time(NULL));
    //  加载配置信息
    ccsua::config::get().load();
    //  加载加解密信息、证书、私钥等
    ccsua::sesscipher::load_self();

    ccsua::sessman::init_cseq();

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    pj_thread_init();

    pj_status_t st;
    pj_log_set_level(2);
    PJ_LOG(3, (THIS_FILE, "Starting B2BUA (low-level pjsip + UDP media relay)"));
    if (init_stack() != 0) return 1;

    /* Initialize authentication */
    if (init_auth_sess() != PJ_SUCCESS) {
        PJ_LOG(1, (THIS_FILE, "Failed to initialize authentication"));
        return 1;
    }

    PJ_LOG(3, (THIS_FILE, "B2BUA listening on %s and %s:%d", LOCAL_IP_UPSTREAM, LOCAL_IP_PHONE, SIP_PORT));
    PJ_LOG(3, (THIS_FILE, "Local REGISTER accept user: %s/%s", LOCAL_REG_USER, LOCAL_REG_PASS));
    PJ_LOG(3, (THIS_FILE, "Will register upstream user: %s/%s to server %s", UPSTREAM_USER, UPSTREAM_PASS, SIP_SERVER));
    /* start upstream register */
    start_upstream_register();

    g_mediathread.start();
    unsigned int reg_time = time(NULL);
    for (;;) {
        pj_time_val poll_delay = { 0, 100 };
        pjsip_endpt_handle_events(g_endpt, &poll_delay);
        pj_thread_sleep(50);
        unsigned int now_time = time(NULL);
        pj_assert(g_expired > 500);
        if (now_time - reg_time > (g_expired - 500)) {
            start_upstream_register();//    注册快超时了重新注册
            reg_time = time(NULL);
        }
    }

    g_mediathread.stop();
    //  退时时需要向SIP取消注册，取消注册与注册相同，只是 expired 设置成0
    g_expired = 0;
    start_upstream_register();

#ifdef _WIN32
    WSACleanup();
#endif
    /* cleanup (never reached in demo) */
    pjmedia_event_mgr_destroy(g_media_event_mgr);
    pjmedia_endpt_destroy(g_med_endpt);
    pjsip_endpt_unregister_module(g_endpt, &mod_b2b);
    pjsip_endpt_destroy(g_endpt);
    pj_pool_release(g_pool);
    pj_caching_pool_destroy(&g_cp);
    pj_shutdown();
    return 0;
}
