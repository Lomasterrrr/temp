#include "../include/nescaopts.h"
#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "../include/nescaengine.h"
#include "../include/nescalog.h"
#include "../ncsock/include/utils.h"

#ifndef NELEMS
#  define NELEMS(x) (sizeof(x) / sizeof((x)[0]))
#endif

const char *shortopts = "";
struct option longopts[] = {
    {"random-ip", required_argument, 0, INDEX_RANDOM_IP},
    {"ttl", required_argument, 0, INDEX_TTL},
    {"mtu", required_argument, 0, INDEX_MTU},
    {"srcport", required_argument, 0, INDEX_SRCPORT},
    {"fin", no_argument, 0, INDEX_TCPFINSCAN},
    {"syn", no_argument, 0, INDEX_TCPSYNSCAN},
    {"xmas", no_argument, 0, INDEX_TCPXMASSCAN},
    {"null", no_argument, 0, INDEX_TCPNULLSCAN},
    {"psh", no_argument, 0, INDEX_TCPPSHSCAN},
    {"ack", no_argument, 0, INDEX_TCPACKSCAN},
    {"window", no_argument, 0, INDEX_TCPWINDOWSCAN},
    {"maimon", no_argument, 0, INDEX_TCPMAIMONSCAN},
    {"badsum", no_argument, 0, INDEX_BADSUM},
    {"PE", no_argument, 0, INDEX_ICMPECHOPING},
    {"PI", no_argument, 0, INDEX_ICMPINFOPING},
    {"PM", no_argument, 0, INDEX_ICMPTIMEPING},
    {"PS", required_argument, 0, INDEX_TCPSYNPING},
    {"PA", required_argument, 0, INDEX_TCPACKPING},
    {"PY", required_argument, 0, INDEX_SCTPINITPING},
    {"PU", required_argument, 0, INDEX_UDPPING},
    {"maxping", no_argument, 0, INDEX_MAXPING},
      {"help", no_argument, 0, INDEX_USAGE},    
    {"adler32", no_argument, 0, INDEX_ADLER32},
    {"src", required_argument, 0, INDEX_SRC},
    {"win", required_argument, 0, INDEX_WINDOW},
    {"acknum", required_argument, 0, INDEX_ACKNUM},
    {"ipopt", required_argument, 0, INDEX_IPOPT},
    {"data", required_argument, 0, INDEX_DATA},
    {"data-len", required_argument, 0, INDEX_DATALEN},
    {"data-string", required_argument, 0, INDEX_DATASTRING},
    {"printargs", no_argument, 0, INDEX_PRINTARGS},
    {"noping", no_argument, 0, INDEX_NOPINGSCAN},
    {"pingtime", required_argument, 0, INDEX_PINGTIMEOUT},
    {"scanflags", required_argument, 0, INDEX_SCANFLAGS},
    {"txt", required_argument, 0, INDEX_SAVETXT},
    {"udp", no_argument, 0, INDEX_UDPSCAN},
    {"init", no_argument, 0, INDEX_SCTPINITSCAN},
    {"cookie", no_argument, 0, INDEX_SCTPCOOKSCAN},
    {"p", required_argument, 0, INDEX_PORT},
    {"failed", no_argument, 0, INDEX_FAILED},
    {"scantime", required_argument, 0, INDEX_SCANTIMEOUT},
    //    {"speed", required_argument, 0, INDEX_SPEED},
    {"noscan", no_argument, 0, INDEX_NOSCAN},
    {"noresolv", no_argument, 0, INDEX_NORESOLV},
    {"html", no_argument, 0, INDEX_DISPLAYHTML},    
    {"noproc", no_argument, 0, INDEX_NOPROC},
    {"ping-maxg", required_argument, 0, INDEX_PINGMAXGLEN},
    {"scan-maxg", required_argument, 0, INDEX_SCANMAXGLEN},
    {"ping-ming", required_argument, 0, INDEX_PINGMINGLEN},
    {"scan-ming", required_argument, 0, INDEX_SCANMINGLEN},    
    {"ping-pg", required_argument, 0, INDEX_GROUPPLUS},
    {"scan-pg", required_argument, 0, INDEX_SCANGROUPPLUS},
    {"resolv-srcport", required_argument, 0, INDEX_RESOLVSRCPORT},
    {"resolv-delay", required_argument, 0, INDEX_RESOLVDELAY},
    {"database-prc", required_argument, 0, INDEX_PROCDATAPATH},
    {"v", no_argument, 0, INDEX_VERBOSE1},
    {"vv", no_argument, 0, INDEX_VERBOSE2},
    {"vvv", no_argument, 0, INDEX_VERBOSE3},
    {"resolvtime", required_argument, 0, INDEX_RESOLVTIME},
    {"nodbcheck", no_argument, 0, INDEX_NODBCHECK},
    {"packet-trace", required_argument, 0, INDEX_PKTTRACE},
    {"services", required_argument, 0, INDEX_SERVICESPATH},
    {"cfg", required_argument, 0, INDEX_CONFIGPATH},
    {"httptime", required_argument, 0, INDEX_HTTPTIME},
    {"httptimeretry", required_argument, 0, INDEX_HTTPREPLYTIME},
    {"httpf", required_argument, 0, INDEX_HTTPHEADER},
    {"nohttpretry", no_argument, 0, INDEX_HTTPNOREDIR},
    {"http-ports", required_argument, 0, INDEX_HTTPPORTS},
    {"scantimemult", required_argument, 0, INDEX_SCANTIMEMULT},    
    {"import", required_argument, 0, INDEX_IMPORT}};

static std::vector<std::string> readfile(const std::string &filename);
static void cleanstr(std::string &str);
static void cleanquotes(std::string &str);
static const char *find_option_name(int val, struct option *longopts);
static ssize_t str_ssize_t(const std::string &str);
static std::string tcp_util_str_getflags(const struct tcp_flags &tf);
static char *string_to_char(const std::string &str);
static nescadelay_t delayconv(const std::string& delay);
static std::string randomstr(int len);
static u8 getproto(const std::string &proto);
static std::vector<std::string> oldreadfile(const std::string& filename);
static std::string removelastpath(const std::string &path);

void NESCAOPTS::args_init(void)
{
  randomips = 0;
  importpath = "";
  ttl = 0;
  srcport = 0;
  mtu = 0;
  data = "";
  datalen = 0;
  scantimemult = 0;
  nodbcheck = false;
  resolvsrcport = 0;
  procdatapath =  "";
  servicespath = "";
  resolvtimeout = 0;
  httpheader.clear();
  resolvdelay = 0;
  httpreplytime = 0;
  httpnoredir = false;
  pkttrace = 0;
  ports.clear();
  configpath = "";
  verbose = 0;
  pingming = scanming = 0;
  pingmaxg = scanmaxg =
    groupplus = scangroupplus = 0;
  noresolv = false;
  noscan = false;
  noproc = false;
  synscan = ackscan = finscan = xmasscan = windowscan
    = maimonscan = nullscan = pshscan = false;
  http_ports.clear();
  src = 0;
  window = 0;
  noping = false;
  ipopts_first_hop_offset = 0;
  printargs = false;
  txtpath = "";
  ipopts_last_hop_offset = 0;
  httptime = 0;
  ipoptslen = 0;
  memset(ip_options, 0, sizeof(ip_options));
  acknum = 0;
  pingtimeout = 0;
  tcpflags = 0;
  displayhtml = false;
  failed = false;
  scantimeout = 0;
  badsum = false;
  echoping = infoping = timeping = maxping = false;
  udpscan = sctpinitscan = sctpcookiescan = false;
  adler32 = false;
  udpping_ports.clear();
  tcpackping_ports.clear();
  tcpsynping_ports.clear();
  sctpinitping_ports.clear();
}

void NESCAOPTS::args_print(void)
{
  size_t i;
#define C(key) longopts[i].val == (key)
  for (i = 0; i < NELEMS(longopts); i++) {
    if (C(INDEX_RANDOM_IP))
      printarg(longopts[i].name, std::to_string(get_randomip()), check_randomip());
    if (C(INDEX_IMPORT))
      printarg(longopts[i].name, get_import(), check_import());
    if (C(INDEX_TTL))
      printarg(longopts[i].name, std::to_string(get_ttl()), check_ttl());
    if (C(INDEX_MTU))
      printarg(longopts[i].name, std::to_string(get_mtu()), check_mtu());
    if (C(INDEX_SRCPORT))
      printarg(longopts[i].name, std::to_string(get_srcport()), check_srcport());
    if (C(INDEX_TCPSYNSCAN))
      printarg(longopts[i].name, "", check_synscan());
    if (C(INDEX_TCPXMASSCAN))
      printarg(longopts[i].name, "", check_xmasscan());
    if (C(INDEX_TCPNULLSCAN))
      printarg(longopts[i].name, "", check_nullscan());
    if (C(INDEX_TCPWINDOWSCAN))
      printarg(longopts[i].name, "", check_windowscan());
    if (C(INDEX_TCPMAIMONSCAN))
      printarg(longopts[i].name, "", check_maimonscan());
    if (C(INDEX_TCPPSHSCAN))
      printarg(longopts[i].name, "", check_pshscan());
    if (C(INDEX_TCPACKSCAN))
      printarg(longopts[i].name, "", check_ackscan());
    if (C(INDEX_TCPFINSCAN))
      printarg(longopts[i].name, "", check_finscan());
    if (C(INDEX_BADSUM))
      printarg(longopts[i].name, "", check_badsum());
    if (C(INDEX_TCPACKPING))
      printarg(longopts[i].name, get_strackports(), check_ackping());
    if (C(INDEX_TCPSYNPING))
      printarg(longopts[i].name, get_strsynports(), check_synping());
    if (C(INDEX_SCTPINITPING))
      printarg(longopts[i].name, get_strinitports(), check_initping());
    if (C(INDEX_UDPPING))
      printarg(longopts[i].name, get_strudpports(), check_udpping());
    if (C(INDEX_ICMPECHOPING))
      printarg(longopts[i].name, "", check_echoping());
    if (C(INDEX_ICMPINFOPING))
      printarg(longopts[i].name, "", check_infoping());
    if (C(INDEX_ICMPTIMEPING))
      printarg(longopts[i].name, "", check_timeping());
    if (C(INDEX_MAXPING))
      printarg(longopts[i].name, "", check_maxping());
    if (C(INDEX_ADLER32))
      printarg(longopts[i].name, "", check_adler32());
    if (C(INDEX_SRC))
      printarg(longopts[i].name, get_strsrc(), check_src());
    if (C(INDEX_WINDOW))
      printarg(longopts[i].name, std::to_string(get_window()), check_window());
    if (C(INDEX_ACKNUM))
      printarg(longopts[i].name, std::to_string(get_acknum()), check_acknum());
    if (C(INDEX_IPOPT))
      printarg(longopts[i].name, "", check_ipopt());
    if (C(INDEX_DATA))
      printarg(longopts[i].name, get_payload(), check_payload());
    if (C(INDEX_DATALEN))
      printarg(longopts[i].name, get_payload(), check_payload());
    if (C(INDEX_DATASTRING))
      printarg(longopts[i].name, get_payload(), check_payload());
    if (C(INDEX_PRINTARGS))
      printarg(longopts[i].name, "", check_printargs());
    if (C(INDEX_NOPINGSCAN))
      printarg(longopts[i].name, "", check_noping());
    if (C(INDEX_PINGTIMEOUT))
      printarg(longopts[i].name, std::to_string(get_pingtimeout()), check_pingtimeout());
    if (C(INDEX_SCANFLAGS))
      printarg(longopts[i].name, get_strscanflags(), check_scanflags());
    if (C(INDEX_SAVETXT))
      printarg(longopts[i].name, get_strtxtsave(), check_txtsave());
    if (C(INDEX_UDPSCAN))
      printarg(longopts[i].name, "", check_udpscan());
    if (C(INDEX_SCTPINITSCAN))
      printarg(longopts[i].name, "", check_sctpinitscan());
    if (C(INDEX_SCTPCOOKSCAN))
      printarg(longopts[i].name, "", check_sctpcookiescan());
    if (C(INDEX_PORT))
      printarg(longopts[i].name, get_strports(), check_ports());
    if (C(INDEX_FAILED))
      printarg(longopts[i].name, "", check_failed());
    if (C(INDEX_SCANTIMEOUT))
      printarg(longopts[i].name, std::to_string(get_scantimeout()), check_scantimeout());
    if (C(INDEX_NOSCAN))
      printarg(longopts[i].name, "", check_noscan());
    if (C(INDEX_NOPROC))
      printarg(longopts[i].name, "", check_noproc());
    if (C(INDEX_NORESOLV))
      printarg(longopts[i].name, "", check_noresolv());
    if (C(INDEX_SCANMAXGLEN))
      printarg(longopts[i].name, std::to_string(get_scanmaxg()), check_scanmaxg());
    if (C(INDEX_PINGMAXGLEN))
      printarg(longopts[i].name, std::to_string(get_pingmaxg()), check_pingmaxg());
    if (C(INDEX_GROUPPLUS))
      printarg(longopts[i].name, std::to_string(get_groupplus()), check_groupplus());
    if (C(INDEX_SCANGROUPPLUS))
      printarg(longopts[i].name, std::to_string(get_scangroupplus()), check_scangroupplus());
    if (C(INDEX_SCANMINGLEN))
      printarg(longopts[i].name, std::to_string(get_scanming()), check_scanming());
    if (C(INDEX_PINGMINGLEN))
      printarg(longopts[i].name, std::to_string(get_pingming()), check_pingming());
    if (C(INDEX_RESOLVSRCPORT))
      printarg(longopts[i].name, std::to_string(get_resolvsrcport()), check_resolvsrcport());
    if (C(INDEX_RESOLVDELAY))
      printarg(longopts[i].name, std::to_string(get_resolvdelay()), check_resolvdelay());
    if (C(INDEX_PROCDATAPATH))
      printarg(longopts[i].name, get_procdatapath(), check_procdatapath());
    if (C(INDEX_DISPLAYHTML))
      printarg(longopts[i].name, "", check_displayhtml());
    if (C(INDEX_VERBOSE1))
      printarg(longopts[i].name, "", check_verbose(1));
    if (C(INDEX_VERBOSE2))
      printarg(longopts[i].name, "", check_verbose(2));
    if (C(INDEX_VERBOSE3))
      printarg(longopts[i].name, "", check_verbose(3));
    if (C(INDEX_RESOLVTIME))
      printarg(longopts[i].name, std::to_string(get_resolvtimeout()), check_resolvtimeout());
    if (C(INDEX_NODBCHECK))
      printarg(longopts[i].name, "", check_nodbcheck());
    if (C(INDEX_PKTTRACE))
      printarg(longopts[i].name, std::to_string(get_pkttrace()), check_pkttrace(get_pkttrace()));
    if (C(INDEX_SERVICESPATH))
      printarg(longopts[i].name, get_servicespath(), check_servicespath());
    if (C(INDEX_CONFIGPATH))
      printarg(longopts[i].name, get_configpath(), check_configpath());
    if (C(INDEX_HTTPTIME))
      printarg(longopts[i].name, std::to_string(get_httptimeout()), check_httptimeout());
    if (C(INDEX_HTTPREPLYTIME))
      printarg(longopts[i].name, std::to_string(get_httpreplytimeout()), check_httpreplytimeout());
    if (C(INDEX_HTTPHEADER))
      printarg(longopts[i].name, "", check_httpheader());
    if (C(INDEX_HTTPNOREDIR))
      printarg(longopts[i].name, "", check_httpnoredir());
    if (C(INDEX_HTTPPORTS))
      printarg(longopts[i].name, get_strhttpports(), check_httpports());
    if (C(INDEX_SCANTIMEMULT))
      printarg(longopts[i].name, std::to_string(get_scantimemult()), check_scantimemult());
  }
  exit(0);
#undef C
}

struct prcblock NESCAOPTS::prcblock_prc(struct cfgblock *b)
{
  struct prcblock res;
  std::string val, token;
  val = b->value;

  std::istringstream iss(val);
  std::getline(iss, res.keyword, ',');
  iss >> res.find;
  iss.ignore();
  iss >> res.brute;
  res.check = true;

  return res;
}

void NESCAOPTS::config_parse(const std::string &path)
{
  std::vector<std::string> filebuf;
  std::vector<cfgblock> blocks;

  filebuf = readfile(path);
  if (filebuf.empty())
    return;
  preproc_prc(&filebuf, removelastpath(path));
  blocks = statement_all_prc(parse_all_statement(filebuf));

#define C(key) b.keyword == find_option_name((key), longopts)
#define CB(key) b.keyword == find_option_name((key), longopts) && (b.value == "true" || b.value == "1")
  for (const auto& b : blocks) {
    if (b.value.empty() || b.value == "NULL" || b.value == "n/a" || b.value == "none")
      continue;
    
    if (C(INDEX_RANDOM_IP))
      set_randomip(str_ssize_t(b.value));
    if (C(INDEX_IMPORT))
      set_import(b.value);
    if (C(INDEX_TTL))
      set_ttl(atoi(b.value.c_str()));
    if (C(INDEX_MTU))
      set_mtu(atoi(b.value.c_str()));
    if (C(INDEX_SRCPORT))
      set_srcport(atoi(b.value.c_str()));
    if (C(INDEX_TCPSYNPING))
      set_synping(split_string_u16(b.value, ','));
    if (C(INDEX_TCPACKPING))
      set_ackping(split_string_u16(b.value, ','));
    if (C(INDEX_UDPPING))
      set_udpping(split_string_u16(b.value, ','));
    if (C(INDEX_SCTPINITPING))
      set_initping(split_string_u16(b.value, ','));
    if (C(INDEX_SRC))
      set_src(b.value);
    if (C(INDEX_WINDOW))
      set_window(atoi(b.value.c_str()));
    if (C(INDEX_ACKNUM))
      set_acknum(atoi(b.value.c_str()));
    if (C(INDEX_IPOPT))
      set_ipopt(b.value);
    if (C(INDEX_DATA))
      set_payloadhex(b.value);
    if (C(INDEX_DATALEN))
      set_payloadrandom(atoi(b.value.c_str()));
    if (C(INDEX_DATASTRING))
      set_payload(b.value);
    if (C(INDEX_PINGTIMEOUT))
      set_pingtimeout(b.value);
    if (C(INDEX_SCANFLAGS))
      set_strscanflags(b.value);
    if (C(INDEX_SAVETXT))
      set_txtsave(b.value);
    if (C(INDEX_PORT))
      set_ports(b.value);
    if (C(INDEX_SCANTIMEOUT))
      set_scantimeout(b.value);
    if (C(INDEX_SCANMAXGLEN))
      set_scanmaxg(str_ssize_t(b.value));
    if (C(INDEX_PINGMAXGLEN))
      set_pingmaxg(str_ssize_t(b.value));
    if (C(INDEX_GROUPPLUS))
      set_groupplus(str_ssize_t(b.value));
    if (C(INDEX_SCANGROUPPLUS))
      set_scangroupplus(str_ssize_t(b.value));
    if (C(INDEX_SCANMINGLEN))
      set_scanming(str_ssize_t(b.value));
    if (C(INDEX_PINGMINGLEN))
      set_pingming(str_ssize_t(b.value));
    if (C(INDEX_RESOLVSRCPORT))
      set_resolvsrcport(atoi(b.value.c_str()));
    if (C(INDEX_RESOLVDELAY))
      set_resolvdelay(b.value);
    if (C(INDEX_PROCDATAPATH))
      set_prodatapath(b.value);
    if (C(INDEX_RESOLVTIME))
      set_resolvtimeout(b.value);
    if (C(INDEX_PKTTRACE))
      set_pkttrace(atoi(b.value.c_str()));
    if (C(INDEX_SERVICESPATH))
      set_servicespath(b.value.c_str());
    if (C(INDEX_CONFIGPATH))
      set_configpath(b.value.c_str());
    if (C(INDEX_HTTPTIME))
      set_htttimeout(b.value);
    if (C(INDEX_HTTPREPLYTIME))
      set_httpreplytimeout(b.value);
    if (C(INDEX_HTTPHEADER))
      set_httpheader(b.value);
    if (C(INDEX_HTTPPORTS))
      set_httpports(b.value);
    if (C(INDEX_SCANTIMEMULT))
      set_scantimemult(atoi(b.value.c_str()));
    if (CB(INDEX_TCPSYNSCAN))
      set_synscan(true);
    if (CB(INDEX_TCPXMASSCAN))
      set_xmasscan(true);
    if (CB(INDEX_TCPNULLSCAN))
      set_nullscan(true);
    if (CB(INDEX_TCPWINDOWSCAN))
      set_windowscan(true);
    if (CB(INDEX_TCPMAIMONSCAN))	
      set_maimonscan(true);
    if (CB(INDEX_TCPPSHSCAN))
      set_pshscan(true);
    if (CB(INDEX_TCPACKSCAN))
      set_ackscan(true);
    if (CB(INDEX_TCPFINSCAN))
      set_finscan(true);
    if (CB(INDEX_BADSUM))	    
      set_badsum(true);
    if (CB(INDEX_ICMPECHOPING))
      set_echoping(true);
    if (CB(INDEX_ICMPINFOPING))
      set_infoping(true);
    if (CB(INDEX_ICMPTIMEPING))
      set_timeping(true);
    if (CB(INDEX_MAXPING))
      set_maxping(true);
    if (CB(INDEX_ADLER32))
      set_adler32(true);
    if (CB(INDEX_PRINTARGS))
      set_printargs(true);
    if (CB(INDEX_NOPINGSCAN))
      set_noping(true);
    if (CB(INDEX_UDPSCAN))
      set_udpscan(true);
    if (CB(INDEX_SCTPINITSCAN))
      set_sctpinitscan(true);
    if (CB(INDEX_SCTPCOOKSCAN))
      set_sctpcookiescan(true);
    if (CB(INDEX_FAILED))
      set_failed(true);
    if (CB(INDEX_NORESOLV))
      set_noresolv(true);
    if (CB(INDEX_NOPROC))
      set_noproc(true);
    if (CB(INDEX_NOSCAN))
      set_noscan(true);
    if (CB(INDEX_DISPLAYHTML))
      set_displayhtml(true);
    if (CB(INDEX_VERBOSE1))
      set_verbose(1);
    if (CB(INDEX_VERBOSE2))
      set_verbose(2);
    if (CB(INDEX_VERBOSE3))
      set_verbose(3);
    if (CB(INDEX_NODBCHECK))
      set_nodbcheck(true);
    if (CB(INDEX_HTTPNOREDIR))
      set_httpnoredir(true);
  }
#undef C
#undef CB
}

void NESCAOPTS::args_parse(int argc, char **argv)
{
  int rez, optindex = 0;
  
  if (argc <= 1)
    nescausage(argv);

  while ((rez = getopt_long_only(argc, argv, shortopts, longopts, &optindex)) != EOF) {
    switch (rez)
    {
      case INDEX_USAGE:
	nescausage(argv);
      case INDEX_RANDOM_IP:
        set_randomip(atoi(optarg));
        break;
      case INDEX_IMPORT:
	set_import(optarg);
	break;
      case INDEX_TTL:
	set_ttl(atoi(optarg));
	break;
      case INDEX_MTU:
	set_mtu(atoi(optarg));
	break;
      case INDEX_SRCPORT:
        set_srcport(atoi(optarg));
	break;
      case INDEX_TCPSYNSCAN:
	set_synscan(true);
	break;
      case INDEX_TCPXMASSCAN:
	set_xmasscan(true);
	break;
      case INDEX_TCPNULLSCAN:
	set_nullscan(true);
	break;
      case INDEX_TCPWINDOWSCAN:
	set_windowscan(true);
	break;
      case INDEX_TCPMAIMONSCAN:
	set_maimonscan(true);
	break;
      case INDEX_TCPPSHSCAN:
	set_pshscan(true);
	break;
      case INDEX_TCPACKSCAN:
	set_ackscan(true);
	break;
      case INDEX_TCPFINSCAN:
	set_finscan(true);
	break;
      case INDEX_BADSUM:
	set_badsum(true);
	break;
      case INDEX_ICMPECHOPING:
	set_echoping(true);
	break;
      case INDEX_ICMPTIMEPING:
	set_timeping(true);
	break;
      case INDEX_ICMPINFOPING:
	set_infoping(true);
	break;
      case INDEX_MAXPING:
	set_maxping(true);
	break;	
      case INDEX_TCPACKPING:
	set_ackping(split_string_u16(optarg, ','));
	break;
      case INDEX_UDPPING:
	set_udpping(split_string_u16(optarg, ','));
	break;
      case INDEX_SCTPINITPING:
	set_initping(split_string_u16(optarg, ','));
	break;
      case INDEX_TCPSYNPING:
	set_synping(split_string_u16(optarg, ','));
	break;
      case INDEX_ADLER32:
	set_adler32(true);
	break;
      case INDEX_SRC:
	set_src(optarg);
	break;
      case INDEX_WINDOW:
	set_window(atoi(optarg));
	break;
      case INDEX_ACKNUM:
	set_acknum(atoi(optarg));
	break;
      case INDEX_IPOPT:
	set_ipopt(optarg);
	break;
      case INDEX_DATA:
	set_payloadhex(optarg);
	break;
      case INDEX_DATALEN:
	set_payloadrandom(atoi(optarg));
	break;
      case INDEX_DATASTRING:
	set_payload(optarg);
	break;
      case INDEX_PRINTARGS:
	set_printargs(true);
	break;
      case INDEX_NOPINGSCAN:
	set_noping(true);
	break;
      case INDEX_PINGTIMEOUT:
	set_pingtimeout(optarg);
	break;
      case INDEX_SCANFLAGS:
	set_strscanflags(optarg);
	break;
      case INDEX_SAVETXT:
	set_txtsave(optarg);
        break;
      case INDEX_UDPSCAN:
	set_udpscan(true);
        break;
      case INDEX_FAILED:
	set_failed(true);
        break;	
      case INDEX_SCTPINITSCAN:
	set_sctpinitscan(true);
        break;
      case INDEX_SCTPCOOKSCAN:
	set_sctpcookiescan(true);
        break;
      case INDEX_PORT:
	set_ports(optarg);
        break;
      case INDEX_SCANTIMEOUT:
	set_scantimeout(optarg);
        break;
      case INDEX_NOSCAN:
	set_noscan(true);
        break;
      case INDEX_NOPROC:
	set_noproc(true);
        break;
      case INDEX_NORESOLV:
	set_noresolv(true);
        break;
      case INDEX_SCANMAXGLEN:
	set_scanmaxg(str_ssize_t(optarg));
        break;
      case INDEX_PINGMAXGLEN:
	set_pingmaxg(str_ssize_t(optarg));
        break;
      case INDEX_GROUPPLUS:
	set_groupplus(str_ssize_t(optarg));
        break;
      case INDEX_SCANGROUPPLUS:
	set_scangroupplus(str_ssize_t(optarg));
        break;
      case INDEX_SCANMINGLEN:
	set_scanming(str_ssize_t(optarg));
        break;
      case INDEX_PINGMINGLEN:
	set_pingming(str_ssize_t(optarg));
        break;
      case INDEX_RESOLVSRCPORT:
	set_resolvsrcport(atoi(optarg));
        break;
      case INDEX_RESOLVDELAY:
	set_resolvdelay(optarg);
        break;
      case INDEX_PROCDATAPATH:
	set_prodatapath(optarg);
        break;
      case INDEX_DISPLAYHTML:
	set_displayhtml(true);
        break;
      case INDEX_VERBOSE1:
	set_verbose(1);
        break;
      case INDEX_VERBOSE2:
	set_verbose(2);
        break;
      case INDEX_VERBOSE3:
	set_verbose(3);
        break;
      case INDEX_RESOLVTIME:
	set_resolvtimeout(optarg);
        break;
      case INDEX_NODBCHECK:
	set_nodbcheck(true);
        break;
      case INDEX_PKTTRACE:
	set_pkttrace(atoi(optarg));
        break;
      case INDEX_SERVICESPATH:
	set_servicespath(optarg);
        break;
      case INDEX_CONFIGPATH:
	set_configpath(optarg);
        break;
      case INDEX_HTTPTIME:
	set_htttimeout(optarg);
        break;
      case INDEX_HTTPREPLYTIME:
	set_httpreplytimeout(optarg);
        break;
      case INDEX_HTTPHEADER:
	set_httpheader(optarg);
        break;
      case INDEX_HTTPNOREDIR:
	set_httpnoredir(true);
        break;
      case INDEX_HTTPPORTS:
	set_httpports(optarg);
        break;
      case INDEX_SCANTIMEMULT:
	set_scantimemult(atoi(optarg));
        break;																
    }
  }
}

static void cleanquotes(std::string &str)
{
  size_t i;
  for (i = 0; i < str.length(); ++i) {
    if (str[i] == '"' || str[i] == '\'') {
      str.erase(i, 1);
      --i;
    }
  }
}

static void cleanstr(std::string &str)
{
  size_t i = 0;
  bool quotes = false;
  
  while (i < str.length()) {
    if (str[i] == '"' || str[i] == '\'') {
      quotes = !quotes;
      ++i;
      continue;
    }
    if (!quotes && (str[i] == ' ' || str[i] == '\n' || str[i] == '\t' || str[i] == '\r'))
      str.erase(i, 1);
    else
      ++i;
  }
}

static const char *find_option_name(int val, struct option *longopts)
{
  while (longopts->name != NULL) {
    if (longopts->val == val)
      return longopts->name;
    longopts++;
  }
  return NULL;
}

void NESCAOPTS::set_scantimeout(const std::string &time) {
  this->scantimeout = delayconv(time);
}

bool NESCAOPTS::check_device(void)
{
  if (!this->device.empty())
    return true;
  return false;
}

std::string NESCAOPTS::get_device(void) {
  return this->device;
}

void NESCAOPTS::set_device(const std::string &device) {
  this->device = device;
}

static bool prcfind(const std::string& word, const std::string& sentence)
{
  std::string lowerWord = word;
  std::transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), [](u8 c){ return std::tolower(c); });

  std::string lowerSentence = sentence;
  std::transform(lowerSentence.begin(), lowerSentence.end(), lowerSentence.begin(), [](u8 c){ return std::tolower(c); });

  std::string::size_type pos = lowerSentence.find(lowerWord);
  while (pos != std::string::npos) {
    if ((pos > 0 && std::isalpha(lowerSentence[pos - 1])) || 
	(pos + lowerWord.length() < lowerSentence.length() && std::isalpha(lowerSentence[pos + lowerWord.length()])))
      pos = lowerSentence.find(lowerWord, pos + 1);
    else
      return 1;
  }

  return 0;
}

struct prcblock NESCAOPTS::procprobe(const std::string &node, int find)
{
  struct prcblock res;
  std::vector<std::string> filebuf;
  std::vector<cfgblock> blocks;
  
  filebuf = readfile(get_procdatapath());
  blocks = statement_all_prc(parse_all_statement(filebuf));
  
  for (auto &b : blocks) {
    res = prcblock_prc(&b);
    if (res.find == find)
      if (prcfind(b.keyword, node))
        return res;
  }
  
  return {};
}

struct preprocblock NESCAOPTS::parsepreproc(std::string &command)
{
  struct preprocblock res;
  size_t hp, aop, acp, acp2;
  
  cleanstr(command);
  hp = command.find('#');
  aop = command.find('(');
  acp = command.find(')');
  
  if (hp != std::string::npos && aop != std::string::npos && acp != std::string::npos) {
    acp2 = command.find(')', acp + 1);
    if (acp2 != std::string::npos) {
      res.keyword = command.substr(hp + 1, aop - hp - 1);
      if (aop + 1 != acp) {
        res.macroname = command.substr(aop + 1, acp - aop - 1);
        res.value = command.substr(acp + 2, acp2 - acp - 2);
      }
      else {
        res.macroname = "";
        res.value = command.substr(aop + 1, acp - aop - 1);
      }
    }
    else {
      res.keyword = command.substr(hp + 1, aop - hp - 1);
      res.macroname = "";
      res.value = command.substr(aop + 1, acp - aop - 1);
    }
  }
  return res;
}

void NESCAOPTS::set_htttimeout(const std::string &time) {
  this->httptime = delayconv(time);
}

void NESCAOPTS::set_orightttimeout(nescadelay_t time) {
  this->httptime = time;
}

bool NESCAOPTS::check_httptimeout(void)
{
  if (this->httptime > 0)
    return true;
  return false;
}

nescadelay_t NESCAOPTS::get_httptimeout(void) {
  return this->httptime;
}

std::vector<std::string> NESCAOPTS::preproc_prc(std::vector<std::string> *file, const std::string &lastpath)
{
  std::unordered_map<std::string, std::string> macros;
  std::vector<std::string> tmpvec, &res = *file;
  struct preprocblock p;
  
  for (auto it = res.begin(); it != res.end(); ) {
    if (it->at(0) == '#') {
      p = parsepreproc(*it);
      if (p.keyword == INDEX_INCLUDE_PREPROC) {
	tmpvec = readfile(lastpath + p.value);
	it = res.erase(it);
	res.insert(it, tmpvec.begin(), tmpvec.end());
	return preproc_prc(&res, lastpath);
      }
      else if (p.keyword == INDEX_DEFINE_PREPROC) {
	macros[p.macroname] = p.value;
	it = res.erase(it);
      }
      else
	++it;
    }
    else
      ++it;
  }
  auto macroprc = [&](std::string &line) {
    for (const auto &macro : macros) {
      std::string::size_type pos = 0;
      while ((pos = line.find(macro.first, pos)) != std::string::npos) {
	if ((pos == 0 || !isalnum(line[pos - 1])) && (pos + macro.first.length() == line.length() || !isalnum(line[pos + macro.first.length()]))) {
	  line.replace(pos, macro.first.length(), macro.second);
	  pos += macro.second.length();
	}
	else
	  pos += macro.first.length();
      }
    }
  };
  for (auto it = res.begin(); it != res.end(); ++it)
    macroprc(*it);
  
  return res;
}

static std::string removelastpath(const std::string &path)
{
  size_t found = path.find_last_of("/\\");
  if (found != std::string::npos)
    return path.substr(0, found + 1);
  return path; 
}

std::string NESCAOPTS::get_strtxtsave(void)
{
  if (!this->txtpath.empty())
    return this->txtpath;
  return "";
}

void NESCAOPTS::set_httpnoredir(bool status) {
  this->httpnoredir = status;
}

bool NESCAOPTS::check_httpnoredir(void) {
  return this->httpnoredir;
}

void NESCAOPTS::set_strscanflags(const std::string &flags)
{
  struct tcp_flags tf;
  memset(&tf, 0, sizeof(struct tcp_flags));
  tf = tcp_util_str_setflags(flags.c_str());
  this->tcpflags = tcp_util_setflags(&tf);
}

u32 NESCAOPTS::get_payloadlen(void) {
  return this->datalen;
}

static u8 getproto(const std::string &proto)
{
  if (proto.empty() || proto == "T" || proto == "TCP")
    return IPPROTO_TCP;
  else if (proto == "U" || proto == "UDP")
    return IPPROTO_UDP;
  else if (proto == "S" || proto == "SCTP")
    return IPPROTO_SCTP;  
  return 0;
}

void NESCAOPTS::set_failed(bool status) {
  this->failed = status;
}

void NESCAOPTS::set_resolvdelay(const std::string &time) {
  this->resolvdelay = delayconv(time);
}

bool NESCAOPTS::check_resolvdelay(void)
{
  if (resolvdelay > 0)
    return true;
  return false;
}

void NESCAOPTS::set_resolvsrcport(int resolvsrcport)
{
  if (srcport > USHRT_MAX)
    nescaerrlog("Max port is: " + std::to_string(USHRT_MAX));
  else
    this->resolvsrcport = resolvsrcport;  
}

std::string NESCAOPTS::serviceprobe(u16 port, u8 proto)
{
  std::string protostr, servicename, portproto, fileproto;
  std::vector<std::string> filebuf;
  size_t sp;
  u16 fport;
    
  if (!check_servicespath())
    return "";
  
  switch (proto) {
  case IPPROTO_TCP: protostr = "tcp"; break;
  case IPPROTO_UDP: protostr = "udp"; break;
  case IPPROTO_SCTP: protostr = "sctp"; break;
  default: return ""; }
  
  filebuf = oldreadfile(get_servicespath());

  for (const auto& line : filebuf) {
    std::istringstream iss(line);
    if (iss >> servicename >> portproto) {
      sp = portproto.find('/');
      if (sp != std::string::npos) {
	fport = static_cast<u16>(std::stoi(portproto.substr(0, sp)));
	fileproto = portproto.substr(sp + 1);
	if (fport == port && fileproto == protostr)
	  return servicename;
      }
    }
  }

  return "???";
}

nescadelay_t NESCAOPTS::get_resolvdelay(void) {
  return this->resolvdelay;
}

bool NESCAOPTS::check_httpheader(void)
{
  if (!httpheader.empty())
    return true;
  return false;
}

void NESCAOPTS::get_httpheader(struct http_request *r)
{
  for (const auto& pair : this->httpheader)
    http_add_hdr(r, pair.first.c_str(),
		 pair.second.c_str());
}

std::string NESCAOPTS::get_strhttpports(void) {
  return split_vector_u16(http_ports);
}

void NESCAOPTS::set_httpheader(const std::string &node)
{
  std::string item;
  size_t pos;
  
  std::stringstream ss(node);  
  while (std::getline(ss, item, ',')) {
    pos = item.find('=');
    if (pos != std::string::npos)
      httpheader[(item.substr(0, pos))]
	= (item.substr(pos + 1));
  }
}

void NESCAOPTS::set_pkttrace(int level)
{
  if (level > 3)
    nescaerrlog("Max level packet-trace is: 3");
  this->pkttrace = level;
}

bool NESCAOPTS::check_pkttrace(int level)
{
  if (this->pkttrace > 0 && this->pkttrace == level)
    return true;
  return false;
}

void NESCAOPTS::set_synscan(bool status) {
  this->synscan = status;
}

void NESCAOPTS::set_ackscan(bool status) {
  this->ackscan = status;
}

void NESCAOPTS::set_maimonscan(bool status) {
  this->maimonscan = status;
}

void NESCAOPTS::set_finscan(bool status) {
  this->finscan = status;
}

void NESCAOPTS::set_nullscan(bool status) {
  this->nullscan = status;
}

void NESCAOPTS::set_xmasscan(bool status){
  this->xmasscan = status;
}
  
void NESCAOPTS::set_windowscan(bool status) {
  this->windowscan = status;
}

void NESCAOPTS::set_pshscan(bool status) {
  this->pshscan = status;
}

bool NESCAOPTS::check_synscan(void) {
  return this->synscan;
}

bool NESCAOPTS::check_ackscan(void) {
  return this->ackscan;
}

bool NESCAOPTS::check_maimonscan(void) {
  return this->maimonscan;
}

bool NESCAOPTS::check_finscan(void) {
  return this->finscan;
}

bool NESCAOPTS::check_nullscan(void) {
  return this->nullscan;
}

bool NESCAOPTS::check_xmasscan(void) {
  return this->xmasscan;
}

bool NESCAOPTS::check_windowscan(void) {
  return this->windowscan;
}

bool NESCAOPTS::check_pshscan(void) {
  return this->pshscan;
}

int NESCAOPTS::get_pkttrace(void) {
  if (this->pkttrace == 0)
    return -1;
  return this->pkttrace;
}

u16 NESCAOPTS::get_resolvsrcport(void) {
  return this->resolvsrcport;
}

bool NESCAOPTS::check_resolvsrcport(void)
{
  if (this->resolvsrcport > 0)
    return true;
  return false;
}

bool NESCAOPTS::check_failed(void) {
  return this->failed;
}

void NESCAOPTS::set_displayhtml(bool status) {
  this->displayhtml = status;
}

bool NESCAOPTS::check_displayhtml(void) {
  return this->displayhtml;
}

std::vector<NESCAPORT> NESCAOPTS::parseports(const std::string &node)
{
  std::string portstr, protostr, token;
  std::vector<NESCAPORT> res;
  int start, end, i;
  size_t cp, dp;
  u8 proto;
  
  std::stringstream ss(node);
  while (std::getline(ss, token, ',')) {
    /* proto parse */
    cp = token.find(':');
    if (cp != std::string::npos) {
      protostr = token.substr(0, cp);
      portstr = token.substr(cp + 1);
    }
    else
      portstr = token;
    proto = getproto(protostr);
    
    /* range parse */
    dp = portstr.find('-');
    if (dp != std::string::npos) {
      start = std::stoi(portstr.substr(0, dp));
      end = std::stoi(portstr.substr(dp + 1));
      for (i = start; i <= end; ++i) {
	NESCAPORT tmp;
	tmp.port = static_cast<u16>(i);
	tmp.state = 0;
	tmp.proto = proto;
	res.push_back(tmp);
      }
    }
    /* simple parse */
    else {
      NESCAPORT tmp;
      tmp.port = static_cast<u16>(std::stoi(portstr));
      tmp.state = 0;
      tmp.proto = proto;
      res.push_back(tmp);
    }
  }
  
  return res;
}

void NESCAOPTS::set_ports(const std::string &node)
{
  std::vector<NESCAPORT> tmp;
  tmp = parseports(node);
  if (!tmp.empty())
    this->ports = tmp;
}

nescadelay_t NESCAOPTS::get_speedscantime(double rtt) {
  return ((rtt * get_scantimemult()) * 1000000LL);
}

bool NESCAOPTS::check_httpports(void)
{
  if (!http_ports.empty())
    return true;
  return false;
}

std::vector<u16> NESCAOPTS::get_httpports(void) {
  return this->http_ports;
}

void NESCAOPTS::set_httpports(const std::string &node) {
  http_ports = split_string_u16(node, ',');
}

bool NESCAOPTS::check_ports(void)
{
  if (!this->ports.empty())
    return true;
  return false;
}

void NESCAOPTS::set_resolvtimeout(const std::string &time) {
  this->resolvtimeout = delayconv(time);
}

void NESCAOPTS::set_origresolvtimeout(nescadelay_t time) {
  this->resolvtimeout = time;
}

std::vector<NESCAPORT> NESCAOPTS::get_ports(void) {
  return this->ports;
}

std::string NESCAOPTS::get_strports(void)
{
  std::string res = "", proto = "";
  for (const auto& p : this->ports) {
    if (p.proto == IPPROTO_TCP)
      proto = "TCP:";
    else if (p.proto == IPPROTO_UDP)
      proto = "UDP:";
    else if (p.proto == IPPROTO_SCTP)
      proto = "SCTP:";
    res += (proto + std::to_string(p.port)) + "|";
  }
  return res;
}

int NESCAOPTS::get_ipoptlen(void)
{
  if (check_ipopt())
    return this->ipoptslen;
  return 0;
}

void NESCAOPTS::set_noscan(bool status) {
  this->noscan = status;
}

void NESCAOPTS::set_noresolv(bool status) {
  this->noresolv = status;
}

void NESCAOPTS::set_noproc(bool status) {
  this->noproc = status;
}

bool NESCAOPTS::check_noproc(void) {
  return this->noproc;
}

bool NESCAOPTS::check_resolvtimeout(void) {
  if (resolvtimeout > 0)
    return true;
  return false;
}

nescadelay_t NESCAOPTS::get_resolvtimeout(void) {
  return this->resolvtimeout;
}

bool NESCAOPTS::check_noresolv(void) {
  return this->noresolv;
}

bool NESCAOPTS::check_noscan(void) {
  return this->noscan;
}

u8 *NESCAOPTS::get_ipopt(void)
{
  if (check_ipopt())
    return this->ip_options;
  return NULL;
}

u8 NESCAOPTS::get_scanflags(void) {
  return this->tcpflags;
}

bool NESCAOPTS::check_scanflags(void)
{
  if (this->tcpflags > 0)
    return true;
  return false;
}

void NESCAOPTS::set_pingmaxg(size_t num) {
  this->pingmaxg = num;
}

void NESCAOPTS::set_pingming(size_t num) {
  this->pingming = num;
}

void NESCAOPTS::set_scanming(size_t num) {
  this->scanming = num;
}

void NESCAOPTS::set_scanmaxg(size_t num) {
  this->scanmaxg = num;
}

void NESCAOPTS::set_groupplus(size_t num) {
  this->groupplus = num;
}

bool NESCAOPTS::check_pingmaxg(void)
{
  if (this->pingmaxg > 0)
    return true;
  return false;
}

bool NESCAOPTS::check_pingming(void)
{
  if (this->pingming > 0)
    return true;
  return false;
}

bool NESCAOPTS::check_scanming(void)
{
  if (this->scanming > 0)
    return true;
  return false;
}

size_t NESCAOPTS::get_pingming(void) {
  return this->pingming;
}

size_t NESCAOPTS::get_scanming(void) {
  return this->scanming;
}

bool NESCAOPTS::check_scanmaxg(void)
{
  if (this->scanmaxg > 0)
    return true;
  return false;
}

bool NESCAOPTS::check_groupplus(void)
{
  if (this->groupplus > 0)
    return true;
  return false;
}

size_t NESCAOPTS::get_pingmaxg(void) {
  return this->pingmaxg;
}

size_t NESCAOPTS::get_scanmaxg(void) {
  return this->scanmaxg;
}

size_t NESCAOPTS::get_groupplus(void) {
  return this->groupplus;
}

static std::string tcp_util_str_getflags(const struct tcp_flags &tf)
{
  std::string flags;
  
  if (tf.syn) flags += 'S';
  if (tf.ack) flags += 'A';
  if (tf.rst) flags += 'R';
  if (tf.fin) flags += 'F';
  if (tf.psh) flags += 'P';
  if (tf.urg) flags += 'U';
  if (tf.cwr) flags += 'C';
  if (tf.ece) flags += 'E';
  
  return flags;
}

void NESCAOPTS::set_src(const std::string& src)
{
  this->src = inet_addr(src.c_str());
}

u32 NESCAOPTS::get_src(void) {
  return this->src;
}

void NESCAOPTS::set_noping(bool status) {
  this->noping = status;
}

bool NESCAOPTS::check_noping(void) {
  return this->noping;
}

std::string NESCAOPTS::get_strscanflags(void)
{
  struct tcp_flags tf;
  memset(&tf, 0, sizeof(struct tcp_flags));
  tf = tcp_util_getflags(tcpflags);
  return tcp_util_str_getflags(tf);
}

static std::string randomstr(int len)
{
  const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const int chlen = characters.length();  
  std::string res;
  u32 seed;
  u8 _char;
  int i;  

  seed = random_seed_u32();
  mt19937_seed(seed);
  
  for (i = 0; i < len; ++i) {
    _char = characters[mt19937_random() % chlen];
    res += _char;
  }
  
  return res;
}

static nescadelay_t delayconv(const std::string& delay)
{
  size_t numend = 0;
  nescadelay_t res;
  std::string unit;

  if (delay.empty())
    return -1;
  if (delay == "0")
    return 1;
  
  res = std::stoll(delay, &numend);  
  if (numend == delay.size())
    return res;
  unit = delay.substr(numend);
  if (res == 0)
    return 1;
  if (unit == "ms")
    return (res * 1000000LL);
  else if (unit == "s")
    return (res * 1000000000LL);
  else if (unit == "m")
    return (res * 60000000000LL);
  else if (unit == "h")
    return (res * 3600000000000LL);
  return -1;
}

void nanodelay(nescadelay_t nanosec)
{
  struct timespec req, rem;
  
  req.tv_sec = nanosec / 1000000000;
  req.tv_nsec = nanosec % 1000000000;

  while (nanosleep(&req, &rem) == -1)
    req = rem;
}

void NESCAOPTS::set_httpreplytimeout(const std::string &time) {
  this->httpreplytime = delayconv(time);
}

void NESCAOPTS::set_orighttpreplytimeout(nescadelay_t time) {
  this->httpreplytime = time;
}

bool NESCAOPTS::check_httpreplytimeout(void)
{
  if (this->httpreplytime > 0)
    return true;
  return false;
}

nescadelay_t NESCAOPTS::get_httpreplytimeout(void) {
  return this->httpreplytime;
}

void NESCAOPTS::set_pingtimeout(const std::string &time) {
  this->pingtimeout = delayconv(time);
}

nescadelay_t NESCAOPTS::get_pingtimeout(void) {
  return this->pingtimeout;
}

nescadelay_t NESCAOPTS::get_scantimeout(void) {
  return this->scantimeout;
}

bool NESCAOPTS::check_pingtimeout(void)
{
  if (this->pingtimeout > 0)
    return true;
  return false;  
}

bool NESCAOPTS::check_scantimeout(void)
{
  if (this->scantimeout > 0)
    return true;
  return false;
}

void NESCAOPTS::set_printargs(bool status) {
  this->printargs = status;
}

bool NESCAOPTS::check_printargs(void) {
  return this->printargs;
}

void NESCAOPTS::set_scangroupplus(size_t num) {
  this->scangroupplus = num;
}

void NESCAOPTS::set_servicespath(const std::string &path) {
  this->servicespath = path;
}

bool NESCAOPTS::check_servicespath(void)
{
  if (!this->servicespath.empty())
    return true;
  return false;
}

std::string NESCAOPTS::get_servicespath(void) {
  return this->servicespath;
}

bool NESCAOPTS::check_scangroupplus(void)
{
  if (this->scangroupplus > 0)
    return true;
  return false;
}

size_t NESCAOPTS::get_scangroupplus(void) {
  return this->scangroupplus;
}

void NESCAOPTS::set_payloadrandom(u32 len)
{
  std::string tmp;
  
  if (len > 1400)
    nescaerrlog("Max payload on eth: " + std::to_string(1400));
  tmp = randomstr(len);
  this->datalen = tmp.length();
  this->data = tmp;
}

static char *string_to_char(const std::string &str)
{
  char* cstr = new char[str.length() + 1];
  strcpy(cstr, str.c_str());
  return cstr;
}

void NESCAOPTS::set_payloadhex(const std::string& hex)
{
  u8 *buf = NULL;
  size_t len = 0;

  buf = hexbin(string_to_char(hex), &len);
  if (!buf)
    nescaerrlog("Invalid hex string specification");
  this->data = reinterpret_cast<const char*>(buf);;
  this->datalen = len;
}

void NESCAOPTS::set_payload(const std::string& data)
{
  this->data = data;
  this->datalen = data.length();
}

std::string NESCAOPTS::get_payload(void)
{
  if (!this->data.empty())
    return std::string(this->data);
  return "";
}

bool NESCAOPTS::check_payload(void)
{
  if (this->datalen > 0)
    return true;
  return false;
}

std::string NESCAOPTS::get_strsrc(void)
{
  char str[INET_ADDRSTRLEN];
  struct sockaddr_in sa;

  sa.sin_addr.s_addr = this->src;
  sa.sin_family = AF_INET;
  inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
  
  return std::string(str);
}

std::vector<std::string> NESCAOPTS::parse_statement(const std::string& line)
{
  std::vector<std::string> res;
  std::string substr;
  bool inside = false;

  for (char c : line) {
    if (c == '[') {
      inside = true;
      substr.clear();
    }
    else if (c == ';') {
      if (inside) {
	res.push_back(substr);
	inside = false;
      }
    }
    else if (c == ']') {
      if (!inside)
	continue;
    }
    else
      if (inside)
	substr.push_back(c);
  }
  return res;
}

void NESCAOPTS::set_srcport(int srcport)
{
  if (srcport > USHRT_MAX || srcport == 0)
    nescaerrlog("Range ports is: (1-" + std::to_string(USHRT_MAX) + ")");
  else
    this->srcport = srcport;
}

bool NESCAOPTS::check_srcport(void)
{
  if (srcport > 0)
    return true;
  return false;
}

std::vector<std::string> NESCAOPTS::parse_all_statement(const std::vector<std::string>& filebuf)
{
  std::vector<std::string> res;
  for (const auto& line : filebuf) {
    std::vector<std::string> tmpres = parse_statement(line);
    res.insert(res.end(), tmpres.begin(), tmpres.end());
  }
  return res;
}

struct cfgblock NESCAOPTS::statement_prc(std::string &statement)
{
  struct cfgblock res;
  
  cleanstr(statement);
  std::stringstream ss(statement);
  std::getline(ss, res.keyword, '=');
  std::getline(ss, res.value);
  cleanquotes(res.value);
  cleanquotes(res.keyword);  
  
  return res;
}

static std::vector<std::string> oldreadfile(const std::string& filename)
{
  std::vector<std::string> res;
  std::ifstream file(filename);
  std::string line;
  size_t poscom;

  if (file.fail())
    return {};
  
  while (std::getline(file, line)) {
    poscom = line.find('$');
    if (poscom != std::string::npos && poscom != 0)
      line = line.substr(0, poscom);
    if (!line.empty())
      res.push_back(line);
  }

  return res;
}

static std::vector<std::string> readfile(const std::string& filename)
{
  std::vector<std::string> res;
  std::ifstream file(filename);
  std::string line;
  std::string accumulatedline;
  size_t poscom;

  if (file.fail())
    return {};

  while (std::getline(file, line)) {
    poscom = line.find("$");
    if (poscom != std::string::npos)
      line = line.substr(0, poscom);

    line.erase(0, line.find_first_not_of(" \t"));
    line.erase(line.find_last_not_of(" \t") + 1);

    if (!line.empty()) {
      if (!accumulatedline.empty())
        accumulatedline += " ";
      accumulatedline += line;
      if (line.back() == ';') {
        res.push_back(accumulatedline);
        accumulatedline.clear();
      }
    }
  }
  if (!accumulatedline.empty())
    res.push_back(accumulatedline);

  return res;
}

std::vector<cfgblock> NESCAOPTS::statement_all_prc(const std::vector<std::string>& statements)
{
  std::vector<cfgblock> res;
  std::string tmp;
  
  for (const auto& statement : statements) {
    tmp = statement;
    res.push_back(statement_prc(tmp));
  }
  
  return res;
}

static ssize_t str_ssize_t(const std::string &str)
{
  std::istringstream iss(str);
  ssize_t result;
  iss >> result;
  return result;
}

std::vector<u16> NESCAOPTS::split_string_u16(const std::string& str, char del)
{
  std::vector<u16> res;
  std::stringstream ss(str);
  std::string token;

  while (std::getline(ss, token, del))
    res.push_back(std::stoi(token));

  return res;
}

void NESCAOPTS::printarg(const std::string& name, const std::string& value, bool status)
{
  std::string val;
  if (value.empty())
    val = "";
  else
    val = "=" + value;
  std::cout << "-" << name << val << " (" << std::boolalpha << status << ")\n";
}

std::string NESCAOPTS::split_vector_u16(const std::vector<u16>& vec)
{
  std::string res;
  size_t i;
  for (i = 0; i < vec.size(); ++i) {
    res += std::to_string(vec[i]);
    if (i != vec.size() - 1)
      res += ",";
  }
  return res;
}

bool NESCAOPTS::filestatus(const std::string& path)
{
  std::ifstream file(path);
  return file.good();
}

bool NESCAOPTS::check_randomip(void)
{
  if (randomips > 0)
    return true;
  return false;
}

void NESCAOPTS::set_mtu(int mtu)
{
  if (mtu >! 0 && mtu % 8 != 0)
    nescaerrlog("Data payload MTU must be > 0 and multiple of 8: (8,16,32,64,128...)");
  else
    this->mtu = mtu;
}

bool NESCAOPTS::check_mtu(void)
{
  if (mtu > 0)
    return true;
  return false;
}

void NESCAOPTS::set_prodatapath(const std::string &path)
{
  if (!filestatus(path))
    nescaerrlog("File " + path + " not found!");
  else
    this->procdatapath = path;
}

void NESCAOPTS::set_import(const std::string& importpath)
{
  if (!filestatus(importpath))
    nescaerrlog("File " + importpath + " not found!");
  else
    this->importpath = importpath;
}

void NESCAOPTS::set_ackping(const std::vector<u16>& ports) {
  this->tcpackping_ports = ports;
}

void NESCAOPTS::set_synping(const std::vector<u16>& ports) {
  this->tcpsynping_ports = ports;
}

void NESCAOPTS::set_udpping(const std::vector<u16>& ports) {
  this->udpping_ports = ports;
}

void NESCAOPTS::set_initping(const std::vector<u16>& ports) {
  this->sctpinitping_ports = ports;
}

void NESCAOPTS::set_maxping(bool status)
{
  if (status == true) {
    this->set_echoping(true);
    this->set_infoping(true);
    this->set_timeping(true);
    this->set_synping({80, 443});
    this->set_ackping({80, 443});
    this->set_initping({80});
    this->set_udpping({53});  
  }
  this->maxping = status;
}
void NESCAOPTS::set_ipopt(const std::string &ipopt)
{
  memset(ip_options, 0, sizeof(ip_options));
  this->ipoptslen = parse_ipopts(ipopt.c_str(), this->ip_options, sizeof(this->ip_options),
			   &this->ipopts_first_hop_offset,
			   &this->ipopts_last_hop_offset, NULL, 0);
}

std::string NESCAOPTS::get_strackports(void)
{
  if (!get_ackports().empty())
    return split_vector_u16(get_ackports());
  return "";
}

std::string NESCAOPTS::get_strsynports(void)
{
  if (!get_synports().empty())
    return split_vector_u16(get_synports());
  return "";
}

std::string NESCAOPTS::get_strinitports(void)
{
  if (!get_initports().empty())
    return split_vector_u16(get_initports());
  return "";
}

std::string NESCAOPTS::get_strudpports(void)
{
  if (!get_udpports().empty())
    return split_vector_u16(get_udpports());
  return "";
}

bool NESCAOPTS::check_ipopt(void)
{
  if (this->ipoptslen > 0)
    return true;
  return false;
}

void NESCAOPTS::set_window(int window)
{
  if (window > USHRT_MAX)
    nescaerrlog("Max window is: " + std::to_string(USHRT_MAX));
  else
    this->window = window;
}

bool NESCAOPTS::check_window(void)
{
  if (this->window > 0)
    return true;
  return false;
}

void NESCAOPTS::set_acknum(size_t acknum)
{
  if (acknum > UINT_MAX)
    nescaerrlog("Max acknum is: " + std::to_string(UINT_MAX));
  else
    this->acknum = acknum;
}

bool NESCAOPTS::check_acknum(void)
{
  if (this->acknum > 0)
    return true;
  return false;
}

void NESCAOPTS::set_sctpinitscan(bool status) {
  this->sctpinitscan = status;
}

void NESCAOPTS::set_sctpcookiescan(bool status) {
  this->sctpcookiescan = status;
}

void NESCAOPTS::set_udpscan(bool status) {
  this->udpscan = status;
}

bool NESCAOPTS::check_sctpinitscan(void) {
  return this->sctpinitscan;
}

bool NESCAOPTS::check_sctpcookiescan(void) {
  return this->sctpcookiescan;
}

bool NESCAOPTS::check_udpscan(void) {
  return this->udpscan;
}

std::vector<u16> NESCAOPTS::get_ackports(void) {
  return this->tcpackping_ports;
}

std::vector<u16> NESCAOPTS::get_synports(void) {
  return this->tcpsynping_ports;
}

std::vector<u16> NESCAOPTS::get_initports(void) {
  return this->sctpinitping_ports;
}

std::vector<u16> NESCAOPTS::get_udpports(void) {
  return this->udpping_ports;
}

u32 NESCAOPTS::get_acknum(void) {
  return this->acknum;
}

u16 NESCAOPTS::get_window(void) {
  return this->window;
}

bool NESCAOPTS::check_src(void) {
  return (this->src != 0) ? true : false;
}

bool NESCAOPTS::check_initping(void) {
  return (this->sctpinitping_ports.size() > 0) ? true : false;
}

bool NESCAOPTS::check_udpping(void) {
  return (this->udpping_ports.size() > 0) ? true : false;
}

bool NESCAOPTS::check_synping(void) {
  return (this->tcpsynping_ports.size() > 0) ? true : false;
}

bool NESCAOPTS::check_ackping(void) {
  return (this->tcpackping_ports.size() > 0) ? true : false;
}

void NESCAOPTS::set_adler32(bool status) {
  this->adler32 = status;
}

bool NESCAOPTS::check_adler32(void) {
  return this->adler32;
}

bool NESCAOPTS::check_maxping(void) {
  return this->maxping;
}

void NESCAOPTS::set_timeping(bool status){
  this->timeping = status;
}

bool NESCAOPTS::check_timeping(void){
  return this->timeping;
}

void NESCAOPTS::set_infoping(bool status) {
  this->infoping = status;
}

bool NESCAOPTS::check_infoping(void) {
  return this->infoping;
}

void NESCAOPTS::set_echoping(bool status) {
  this->echoping = status;
}

bool NESCAOPTS::check_echoping(void) {
  return this->echoping;
}

u16 NESCAOPTS::get_srcport(void) {
  return this->srcport;
}

void NESCAOPTS::set_randomip(size_t randomips) {
  if (randomips > SIZE_MAX)
    nescaerrlog("Max randomips is: " + std::to_string(SIZE_MAX));
  else
    this->randomips = randomips;
}

size_t NESCAOPTS::get_randomip(void) {
  return this->randomips;
}

std::string NESCAOPTS::get_import(void) {
  return this->importpath;
}

int NESCAOPTS::get_mtu(void) {
  return this->mtu;
}

void NESCAOPTS::set_badsum(bool status) {
  this->badsum = status;
}

bool NESCAOPTS::check_badsum(void) {
  return (this->badsum);
}

u16 NESCAOPTS::get_ttl(void) {
  return this->ttl;
}

bool NESCAOPTS::check_procdatapath(void)
{
  if (!procdatapath.empty())
    return true;
  return false;
}

std::string NESCAOPTS::get_procdatapath(void) {
  return this->procdatapath;
}

bool NESCAOPTS::check_import(void)
{
  if (!importpath.empty())
    return true;
  return false;
}

void NESCAOPTS::set_ttl(int ttl)
{
  if (ttl > UCHAR_MAX || ttl == 0)
    nescaerrlog("Range TTL is: (1-" + std::to_string(UCHAR_MAX) + ")");
  else
    this->ttl = ttl;
}

bool NESCAOPTS::check_ttl(void)
{
  if (ttl > 0)
    return true;
  return false;
}

void NESCAOPTS::set_origpingtimeout(nescadelay_t time) {
  this->pingtimeout = time;
}

void NESCAOPTS::set_txtsave(const std::string &path)
{
  if (!path.empty())
    this->txtpath = path;
}

void NESCAOPTS::set_nodbcheck(bool status) {
  this->nodbcheck = status;
}

bool NESCAOPTS::check_nodbcheck(void) {
  return this->nodbcheck;
}

const char *NESCAOPTS::get_txtsave(void)
{
  if (!this->txtpath.empty())
    return this->txtpath.c_str();
  return NULL;
}

void NESCAOPTS::set_verbose(int level) {
  this->verbose = level;
}

int NESCAOPTS::get_verbose(void) {
  return this->verbose;
}

bool NESCAOPTS::check_verbose(int level)
{
  if (verbose > 0 && verbose == level)
    return true;
  return false;
}

bool NESCAOPTS::check_txtsave(void)
{
  if (!this->txtpath.empty())
    return true;
  return false;
}

void NESCAOPTS::set_scantimemult(int num) {
  this->scantimemult = num;
}

int NESCAOPTS::get_scantimemult(void) {
  return this->scantimemult;
}

bool NESCAOPTS::check_scantimemult(void)
{
  if (this->scantimemult > 0)
    return true;
  return false;  
}

void NESCAOPTS::set_configpath(const std::string &path) {
  this->configpath = path;
}

std::string NESCAOPTS::get_configpath(void) {
  return this->configpath;
}

bool NESCAOPTS::check_configpath(void)
{
  if (!configpath.empty())
    return true;
  return false;
}

u8 NESCAOPTS::get_tcpflags(u8 method)
{
  struct tcp_flags tf;
  memset(&tf, 0, sizeof(struct tcp_flags));
  tf = tcp_util_exflags(method);
  return tcp_util_setflags(&tf);
}

void NESCAOPTS::args_proc(void)
{
  if (!check_src()) {
    char *templocalip = ip4_util_strsrc();
    set_src(templocalip);
    free(templocalip);
  }
  if (!check_device()) {
    char dev[16];
    get_active_interface_name(dev, 16);
    set_device(dev);
  }
  if (!check_servicespath())
    set_servicespath("resources/nesca-services");
  if (get_verbose() == 3 && !check_pkttrace(2) && !check_pkttrace(3) && !check_pkttrace(1))
    set_pkttrace(2);
  if (!check_procdatapath())
    set_prodatapath(DEFAULT_DATABASE);
  for (const auto& p : get_ports()) {
    if (p.proto == IPPROTO_TCP && !(check_synscan() || check_finscan() ||
				    check_nullscan() || check_ackscan() || check_xmasscan() ||
				    check_windowscan() || check_pshscan() || check_maimonscan() ||
				    check_scanflags()))
      nescaerrlog("You have specified ports for TCP scans, but you have not specified any TCP scans (use: -syn, -ack, -xmas, -fin, -null, -window, -maimon, -psh)");
    if (p.proto == IPPROTO_UDP && !check_udpscan())
      nescaerrlog("You have specified ports for UDP scanning, but have not enabled UDP scanning (use -udp)");
    if (p.proto == IPPROTO_SCTP && !(check_sctpcookiescan() || check_sctpinitscan()))
      nescaerrlog("You specified ports for SCTP scans, but did not specify more than one SCTP scan (use: -sctp-init, -sctp-cookie)");
  }
}
