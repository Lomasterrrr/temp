#ifndef NESCAOPTS_HEADER
#define NESCAOPTS_HEADER

#include <iostream>
#include <unordered_map>
#include <vector>

#include "../ncbase/include/getopt.h"
#include "../ncsock/include/sys/types.h"
#include "../ncsock/include/http.h"
#include "nescadata.h"

#define DEFAULT_CFG "templates/default.cfg"
#define DEFAULT_DATABASE "resources/nesca-database"

#define INDEX_RANDOM_IP     1
#define INDEX_IMPORT        2
#define INDEX_TTL           3
#define INDEX_SRCPORT       4
#define INDEX_MTU           5
#define INDEX_TCPSYNSCAN    6
#define INDEX_TCPXMASSCAN   7
#define INDEX_TCPNULLSCAN   8
#define INDEX_TCPWINDOWSCAN 9
#define INDEX_TCPMAIMONSCAN 10
#define INDEX_TCPPSHSCAN    11
#define INDEX_TCPACKSCAN    12
#define INDEX_TCPFINSCAN    13
#define INDEX_BADSUM        14
#define INDEX_TCPACKPING    15
#define INDEX_TCPSYNPING    16
#define INDEX_ICMPECHOPING  17
#define INDEX_ICMPINFOPING  18
#define INDEX_ICMPTIMEPING  19
#define INDEX_UDPPING       20
#define INDEX_SCTPINITPING  21
#define INDEX_MAXPING       22
#define INDEX_ADLER32       23
#define INDEX_SRC           24
#define INDEX_WINDOW        25
#define INDEX_ACKNUM        26
#define INDEX_IPOPT         27
#define INDEX_DATA          28
#define INDEX_DATALEN       29
#define INDEX_DATASTRING    30
#define INDEX_PRINTARGS     31
#define INDEX_NOPINGSCAN    32
#define INDEX_PINGTIMEOUT   33
#define INDEX_SCANFLAGS     34
#define INDEX_SAVETXT       35
#define INDEX_USAGE         36
#define INDEX_UDPSCAN       37
#define INDEX_SCTPINITSCAN  38
#define INDEX_SCTPCOOKSCAN  39
#define INDEX_PORT          40
#define INDEX_FAILED        41
#define INDEX_SCANTIMEOUT   42
// #define INDEX_SPEED         43
#define INDEX_NORESOLV      44
#define INDEX_NOSCAN        45
#define INDEX_NOPROC        46
#define INDEX_PINGMAXGLEN   47
#define INDEX_SCANMAXGLEN   48
#define INDEX_GROUPPLUS     49
#define INDEX_SCANGROUPPLUS 50
#define INDEX_PINGMINGLEN   51
#define INDEX_SCANMINGLEN   52
#define INDEX_RESOLVSRCPORT 53
#define INDEX_RESOLVDELAY   54
#define INDEX_PROCDATAPATH  55
#define INDEX_DISPLAYHTML   56
#define INDEX_VERBOSE1      57
#define INDEX_VERBOSE2      58
#define INDEX_VERBOSE3      59
#define INDEX_RESOLVTIME    60
#define INDEX_NODBCHECK     61
#define INDEX_PKTTRACE      62
#define INDEX_SERVICESPATH  63
#define INDEX_CONFIGPATH    64
#define INDEX_HTTPTIME      65
#define INDEX_HTTPREPLYTIME 66
#define INDEX_HTTPHEADER    67
#define INDEX_HTTPNOREDIR   68
#define INDEX_HTTPPORTS     69
#define INDEX_SCANTIMEMULT  70
//#define INDEX_DEVICE      71

struct cfgblock { std::string keyword; std::string value; };
#define FIND_REDIRECT 0
#define FIND_TITLE    1
#define FIND_HTML     2
struct prcblock { std::string keyword; int find; int brute; bool check; };
struct preprocblock { std::string keyword; std::string value, macroname; };
extern struct option longopts[];
extern const char *shortopts;
typedef long long nescadelay_t;
void nanodelay(nescadelay_t nanosec);

class NESCAOPTS {
  std::string importpath;
  std::string txtpath;
  std::string procdatapath;
  size_t pingmaxg, pingming;
  size_t scanmaxg, scanming;
  size_t groupplus, scangroupplus;  
  u32 src;
  size_t randomips;
  u16 ttl;
  u16 srcport, resolvsrcport;
  u16 window;
  u32 acknum;
  u8 tcpflags;
  int mtu;
  int pkttrace;
  bool badsum;
  bool nodbcheck;
  bool echoping, infoping, timeping, maxping;
  bool adler32;
  bool noping, noresolv, noscan, noproc;
  bool synscan, ackscan, windowscan, xmasscan,
    nullscan, pshscan, maimonscan, finscan;
  int scantimemult;
  bool failed;
  bool displayhtml;
  u8 ip_options[256];
  int ipopts_first_hop_offset,
    ipopts_last_hop_offset, ipoptslen;
  std::vector<u16> udpping_ports;
  std::vector<u16> http_ports;  
  std::vector<u16> tcpackping_ports;
  std::vector<u16> tcpsynping_ports;
  std::vector<u16> sctpinitping_ports;
  std::string data;
  u32 datalen;
  bool printargs;
  bool udpscan, sctpcookiescan, sctpinitscan;
  nescadelay_t pingtimeout, scantimeout,
    resolvtimeout, resolvdelay, httptime, httpreplytime;
  std::vector<NESCAPORT> ports;
  int verbose;
  std::string servicespath;
  std::string configpath;
  std::unordered_map<std::string, std::string> httpheader;
  bool httpnoredir;
  std::string device;
  
  void                     printarg(const std::string& name, const std::string& value, bool status);
  std::vector<std::string> parse_statement(const std::string& line);
  std::vector<std::string> parse_all_statement(const std::vector<std::string>& filebuf);
  struct cfgblock          statement_prc(std::string &statement);
  std::vector<cfgblock>    statement_all_prc(const std::vector<std::string>& statements);
  bool                     filestatus(const std::string& path);
  std::vector<NESCAPORT>   parseports(const std::string &node);
  struct prcblock          prcblock_prc(struct cfgblock *b);
  struct preprocblock      parsepreproc(std::string &command);

#define INDEX_INCLUDE_PREPROC "include"
#define INDEX_DEFINE_PREPROC "define"
  std::vector<std::string> preproc_prc(std::vector<std::string> *file, const std::string &lastapath);

public:
  void             args_init(void);
  void             config_parse(const std::string &path);
  struct prcblock  procprobe(const std::string &node, int find);
  std::string      serviceprobe(u16 port, u8 proto);
  void             args_parse(int argc, char **argv);
  void             args_print(void);
  void             args_proc(void);

  void             set_device(const std::string& device);
  void             set_scantimemult(int num);
  void             set_synscan(bool status);
  void             set_ackscan(bool status);
  void             set_maimonscan(bool status);
  void             set_finscan(bool status);
  void             set_nullscan(bool status);
  void             set_xmasscan(bool status);
  void             set_windowscan(bool status);
  void             set_pshscan(bool status);
  void             set_httpports(const std::string &node);
  void             set_httpnoredir(bool status);
  void             set_httpheader(const std::string &node);
  void             set_httpreplytimeout(const std::string &time);
  void             set_orighttpreplytimeout(nescadelay_t time);  
  void             set_htttimeout(const std::string &time);
  void             set_orightttimeout(nescadelay_t time);  
  void             set_configpath(const std::string &path);
  void             set_servicespath(const std::string &path);
  void             set_pkttrace(int level);
  void             set_nodbcheck(bool status);
  void             set_resolvtimeout(const std::string &time);
  void             set_origresolvtimeout(nescadelay_t time);
  void             set_verbose(int level);
  void             set_displayhtml(bool status);
  void             set_prodatapath(const std::string &path);
  void             set_resolvdelay(const std::string &time);
  void             set_resolvsrcport(int resolvsrcport);
  void             set_pingmaxg(size_t num);
  void             set_scanmaxg(size_t num);
  void             set_pingming(size_t num);
  void             set_scanming(size_t num);  
  void             set_groupplus(size_t num);
  void             set_scangroupplus(size_t num);
  void             set_scantimeout(const std::string &time);
  void             set_failed(bool status);
  void             set_ports(const std::string &node);
  void             set_sctpinitscan(bool status);
  void             set_sctpcookiescan(bool status);
  void             set_udpscan(bool status);
  void             set_txtsave(const std::string &path);
  void             set_strscanflags(const std::string& flags);
  void             set_pingtimeout(const std::string& time);
  void             set_origpingtimeout(nescadelay_t time);  
  void             set_noping(bool status);
  void             set_noresolv(bool status);
  void             set_noproc(bool status);  
  void             set_noscan(bool status);  
  void             set_payloadrandom(u32 len);
  void             set_payloadhex(const std::string& hex);
  void             set_payload(const std::string& data);
  void             set_echoping(bool status);
  void             set_infoping(bool status);
  void             set_timeping(bool status);
  void             set_maxping(bool status);  
  void             set_badsum(bool status);
  void             set_randomip(size_t randomips);
  void             set_ttl(int ttl);
  void             set_srcport(int srcport);
  void             set_import(const std::string& importpath);
  void             set_window(int window);
  void             set_src(const std::string& src);
  void             set_acknum(size_t acknum);
  void             set_adler32(bool status);
  void             set_ackping(const std::vector<u16>& ports);
  void             set_synping(const std::vector<u16>& ports);
  void             set_udpping(const std::vector<u16>& ports);
  void             set_initping(const std::vector<u16>& ports);
  void             set_printargs(bool status);
  void             set_ipopt(const std::string& ipopt); 
  void             set_mtu(int mtu);

  bool             check_device(void);
  bool             check_scantimemult(void);
  bool             check_synscan(void);
  bool             check_ackscan(void);
  bool             check_maimonscan(void);
  bool             check_finscan(void);
  bool             check_nullscan(void);
  bool             check_xmasscan(void);
  bool             check_windowscan(void);
  bool             check_pshscan(void);
  bool             check_httpports(void);
  bool             check_httpnoredir(void);
  bool             check_httpheader(void);
  bool             check_httpreplytimeout(void);
  bool             check_httptimeout(void);
  bool             check_configpath(void);
  bool             check_servicespath(void);
  bool             check_pkttrace(int level);
  bool             check_nodbcheck(void);
  bool             check_resolvtimeout(void);
  bool             check_verbose(int level);
  bool             check_displayhtml(void);
  bool             check_procdatapath(void);
  bool             check_resolvdelay(void);
  bool             check_resolvsrcport(void);
  bool             check_pingmaxg(void);
  bool             check_scanmaxg(void);
  bool             check_pingming(void);
  bool             check_scanming(void);  
  bool             check_groupplus(void);
  bool             check_scangroupplus(void);  
  bool             check_scantimeout(void);
  bool             check_failed(void);
  bool             check_ports(void);
  bool             check_sctpinitscan(void);
  bool             check_sctpcookiescan(void);
  bool             check_udpscan(void);    
  bool             check_txtsave(void);
  bool             check_scanflags(void);
  bool             check_pingtimeout(void);  
  bool             check_noping(void);
  bool             check_printargs(void);
  bool             check_payload(void); 
  bool             check_udpping(void);
  bool             check_initping(void);
  bool             check_synping(void);
  bool             check_ackping(void);
  bool             check_timeping(void);
  bool             check_noresolv(void);
  bool             check_noproc(void);
  bool             check_noscan(void);  
  bool             check_infoping(void);
  bool             check_echoping(void);
  bool             check_maxping(void);
  bool             check_badsum(void);
  bool             check_src(void);
  bool             check_window(void);
  bool             check_acknum(void);
  bool             check_ipopt(void);
  bool             check_randomip(void);
  bool             check_srcport(void);
  bool             check_mtu(void);
  bool             check_ttl(void);
  bool             check_import(void);
  bool             check_adler32(void);

  std::string      get_device(void);
  int              get_scantimemult(void);
  u8               get_tcpflags(u8 method);
  std::string      get_strhttpports(void);
  std::vector<u16> get_httpports(void);
  void get_httpheader(struct http_request *r);
  nescadelay_t     get_httpreplytimeout(void);
  nescadelay_t     get_httptimeout(void);
  std::string      get_configpath(void);
  std::string      get_servicespath(void);
  int              get_pkttrace(void);
  nescadelay_t     get_resolvtimeout(void);
  int              get_verbose(void);
  std::string      get_procdatapath(void);
  nescadelay_t     get_resolvdelay(void);
  u16              get_resolvsrcport(void);
  size_t           get_scangroupplus(void);
  size_t           get_pingmaxg(void);
  size_t           get_scanmaxg(void);
  size_t           get_pingming(void);
  size_t           get_scanming(void);  
  size_t           get_groupplus(void);  
  nescadelay_t     get_speedscantime(double rtt);  
  std::vector<NESCAPORT> get_ports(void);
  std::string      get_strports(void);
  const char      *get_txtsave(void);
  std::string      get_strtxtsave(void);
  u8               get_scanflags(void);
  std::string      get_strscanflags(void);
  nescadelay_t     get_pingtimeout(void);
  nescadelay_t     get_scantimeout(void);
  u32              get_payloadlen(void);
  u8              *get_ipopt(void);
  int              get_ipoptlen(void);
  u32              get_acknum(void);
  u16              get_window(void);
  u32              get_src(void);
  std::string      get_payload(void);
  std::string      get_strsrc(void);
  std::vector<u16> get_ackports(void);
  std::vector<u16> get_synports(void);
  std::vector<u16> get_initports(void);
  std::vector<u16> get_udpports(void);
  std::string      get_strackports(void);
  std::string      get_strsynports(void);
  std::string      get_strinitports(void);
  std::string      get_strudpports(void);
  std::string      get_import(void);
  size_t           get_randomip(void);
  u16              get_srcport(void);
  int              get_mtu(void);
  u16              get_ttl(void);

  std::vector<u16> split_string_u16(const std::string &str, char del);
  std::string      split_vector_u16(const std::vector<u16>& vec);
};

#endif
