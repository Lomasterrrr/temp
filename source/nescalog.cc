#include "../include/nescalog.h"
#include <netinet/in.h>
#include <string>

const char *nescalogpath = NULL;
static std::chrono::time_point<std::chrono::high_resolution_clock> startnesca,
    endnesca;
extern std::mutex stop;

std::string graynesca = "\033[38;2;105;105;105m";
std::string golderrod = "\033[38;2;218;165;32m";
std::string seagreen = "\033[38;2;60;179;96;4m";
std::string greenhtml = "\033[38;2;124;252;0m";
std::string redhtml = "\033[38;2;240;50;55m";
std::string yellowhtml = "\033[38;2;253;233;16m";
std::string nocolor = "\033[0m";

void nescalog(const char *p, const char *fmt, ...)
{
  FILE *tmp;
  va_list args;

  if (p) {
    va_start(args, fmt);
    if (!(tmp = fopen(p, "a")))
      return;
    vfprintf(tmp, fmt, args);
    fclose(tmp);
    va_end(args);
  }
  
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

void nescapktlog(const u8 *pkt, u32 len, NESCAOPTS *no)
{
  if (no->get_pkttrace() <= 0)
    return;

  stop.lock();
  nescalog(nescalogpath, "%s\n", read_ippktinfo(pkt, len, no->get_pkttrace()));
  stop.unlock();
}

void nescaerrlog(const std::string &err)
{
  nescalog(nescalogpath, "%s\n", err.c_str());
  exit(1);
}

void nescarunlog(const std::string &version)
{
  char formatted_date[11];
  
  get_current_date(formatted_date, sizeof(formatted_date));
  nescalog(nescalogpath, "Running NESCA4 (v%s) / %s at %s\n",
	   version.c_str(), get_time(), formatted_date);
  startnesca = std::chrono::high_resolution_clock::now();
}

void nescaendlog(ssize_t success)
{
  double duration;
  
  endnesca = std::chrono::high_resolution_clock::now();
  auto duration_scan = std::chrono::duration_cast<std::chrono::microseconds>
    (endnesca - startnesca);
  duration = duration_scan.count() / 1000000.0;
  nescalog(nescalogpath, "NESCA4 finished %zd up IPs (success) in %.2f seconds\n",
	   success, duration);
}

void nescahdrlog(const std::string &dst, const std::string &dns, double rtt)
{
  nescalog(nescalogpath, "Report nesca4 for %s (%s) %.1f ms\n",
	   dst.c_str(), dns.c_str(), rtt);
}

std::string passblock(std::vector<std::string> login, std::vector<std::string> pass)
{
  std::string res;
  
  for (const auto& l : login) {
    res += "'" + l;
    for (const auto& p : pass)
      res += "@" + p + "', ";
  }
  
  res.pop_back();
  res.pop_back();  
  return res;
}

std::string portblock(NESCATARGET *t, NESCAOPTS *no)
{
  std::string protostr, statestr, servicestr, res, methodstr;

  res = "";
  for (const auto& port : t->ports) {
    if (!no->check_failed()) {
#define C(key) port.method == (key)
      if (C(TCP_SYN_SCAN) || C(TCP_FIN_SCAN)     ||
	  C(TCP_PSH_SCAN) || C(TCP_XMAS_SCAN)    ||
	  C(TCP_NULL_SCAN) || C(TCP_WINDOW_SCAN) ||
	  C(0) || C(SCTP_INIT_SCAN) || C(UDP_SCAN))
	if (port.state != PORT_OPEN)
	  continue;
      if (C(TCP_MAIMON_SCAN))
	if (port.state != PORT_OPEN_OR_FILTER)
	  continue;
      if (C(TCP_ACK_SCAN))
	if (port.state != PORT_NO_FILTER)
	  continue;
      if (C(SCTP_COOKIE_SCAN))
	if (port.state != PORT_CLOSED)
	  continue;
#undef C
    }
    res += "'";
    switch (port.proto) {
    case IPPROTO_TCP:
      protostr = "tcp";
      break;
    case IPPROTO_UDP:
      protostr = "udp";
      break;
    case IPPROTO_SCTP:
      protostr = "sctp";
      break;
    default:
      protostr = "unknown???";
      break;
    }
    switch (port.state) {
    case PORT_OPEN:
      statestr = "open";
      break;
    case PORT_CLOSED:
      statestr = "closed";
      break;
    case PORT_FILTER:
      statestr = "filtered";
      break;
    case PORT_ERROR:
      statestr = "error";
      break;
    case PORT_OPEN_OR_FILTER:
      statestr = "open|filtered";
      break;
    case PORT_NO_FILTER:
      statestr = "unfiltered";
      break;
    default:
      statestr = "unknown???";
      break;
    }
    switch (port.method) {
    case TCP_SYN_SCAN:
      methodstr = "syn";
      break;
    case TCP_XMAS_SCAN:
      methodstr = "xmas";
      break;
    case TCP_FIN_SCAN:
      methodstr = "fin";
      break;
    case TCP_ACK_SCAN:
      methodstr = "ack";
      break;
    case TCP_WINDOW_SCAN:
      methodstr = "window";
      break;
    case TCP_NULL_SCAN:
      methodstr = "null";
      break;
    case TCP_MAIMON_SCAN:
      methodstr = "maimon";
      break;
    case TCP_PSH_SCAN:
      methodstr = "psh";
      break;
    case SCTP_INIT_SCAN:
      methodstr = "init";
      break;
    case SCTP_COOKIE_SCAN:
      methodstr = "cookie";
      break;
    case UDP_SCAN:
      methodstr = "udp";
      break;
    default:
      methodstr = "???";
      break;
    }
    servicestr = no->serviceprobe(port.port, port.proto);
    res += std::to_string(port.port) + "/";
    res += protostr + "/";
    res +=  statestr + "/";
    res += servicestr + "(";
    res += methodstr + ")', ";    
  }
  if (res.empty())
    return "";
  
  res.pop_back();
  res.pop_back();  
  return res;
}

std::string identblock(NESCATARGET *t, NESCAOPTS *no)
{
  std::string res;

  res = "";
  if (t->idents.empty())
    return res;

  if (t->checkids(HTTP_SERVICE)) {
    res += join(t->getids(HTTP_SERVICE), "(http); ");
    res += "(http); ";
  }
  if (t->checkids(FTP_SERVICE)) {
    res += join(t->getids(FTP_SERVICE), "(ftp); ");
    res += "(ftp); ";
  }

  res.pop_back();
  res.pop_back();
  return res;
  
}

void nescacontentlog(const std::string & title, const std::string &content)
{
  size_t titlelen = 15;
  std::string fmt; 

  fmt = title + std::string(titlelen - title.size(), ' ');
  
  nescalog(nescalogpath, "  ");
  nescalog(nescalogpath, "%s ", fmt.c_str());
  nescalog(nescalogpath, "%s\n", content.c_str());;
}

void nescausage(char **argv)
{
  nescalog(nescalogpath, "Usage: %s <flags> <targets>\n", argv[0]);
  nescalog(nescalogpath, "\n");
  nescalog(nescalogpath, "TARGET SPECIFICATION:\n");
  nescalog(nescalogpath, "  -import <inputfilename>: Set target(s) from file.\n");
  nescalog(nescalogpath, "  -random-ip <num hosts>: Choose random target(s)\n");
  nescalog(nescalogpath, "PING SCAN OPTIONS:\n");
  nescalog(nescalogpath, "  -PS, -PA, -PY, -PU <ports>: Use SYN/ACK/UDP/SCTP ping.\n");
  nescalog(nescalogpath, "  -PE, -PI, -PM: Use ICMP ping ECHO/INFO/TIMESTAMP\n");
  nescalog(nescalogpath, "  -maxping: Using all ping methods.\n");
  nescalog(nescalogpath, "  -pingtime <time>: Set recv timeout for ping.\n");
  nescalog(nescalogpath, "  -noping: Skip ping scan.\n");
  nescalog(nescalogpath, "HOST RESOLUTION OPTIONS:\n");
  nescalog(nescalogpath, "  -resolv-srcport <port>: Set custom source port for resolv.\n");
  nescalog(nescalogpath, "  -resolv-delay <time>: Set delay for resolv.\n");
  nescalog(nescalogpath, "  -resolvtime <time>: Set recv timeout for resolv.\n");
  nescalog(nescalogpath, "  -noresolv: Skip resolution scan.\n");
  nescalog(nescalogpath, "PORT SCAN OPTIONS:\n");
  nescalog(nescalogpath, "  -fin, -xmas, -null, -psh: Use one of these scanning methods.\n");
  nescalog(nescalogpath, "  -ack, -window -maimon: Use ack or window or maimon scan method.\n");
  nescalog(nescalogpath, "  -scanflags <flags>: Customize TCP scan flag (also read as TCP SYN).\n    Ex: (ACK+SYN) > AS;\n");
  nescalog(nescalogpath, "  -init, -cookie: Use SCTP INIT/COOKIE-ECHO scan method.\n");
  nescalog(nescalogpath, "  -udp: Use UDP scan method and udp ports.\n");
  nescalog(nescalogpath, "  -p <port ranges>: Only scan specified ports.\n    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9\n");
  nescalog(nescalogpath, "  -scantime <time>: Set recv timeout for port scan.\n");
  nescalog(nescalogpath, "  -scantimemult <num>: Set the multiplication number rtt, to calculate the timeout.\n");  
  nescalog(nescalogpath, "  -noscan: Skip port scan.\n");
  nescalog(nescalogpath, "HTTP PROBE OPTIONS:\n");
  nescalog(nescalogpath, "  -httpf <field=val,[..,]>: Set http fields for probe.\n");
  nescalog(nescalogpath, "  -http-ports <port,[..,]>: Set tcp ports for http probe.\n");
  nescalog(nescalogpath, "  -httptime <time>: Set timeout for http probe.\n");
  nescalog(nescalogpath, "  -httptimeretry <time>: Set timeout for retry http probes.\n");
  nescalog(nescalogpath, "  -nohttpretry: Disable retry http probe by redirect.\n");      
  nescalog(nescalogpath, "PROCCESSING OPTIONS:\n");
  nescalog(nescalogpath, "  -database-prc <path file>: Set finds data base.\n");
  nescalog(nescalogpath, "  -nodbcheck: Skip check and detect database.\n");
  nescalog(nescalogpath, "  -services <file path>: Set services data base.\n");
  nescalog(nescalogpath, "FIREWALL/IDS EVASION AND SPOOFING:\n");
  nescalog(nescalogpath, "  -data <hex>: Append a custom data to payload\n");
  nescalog(nescalogpath, "  -data-string <string>: Append a custom ASCII string to payload.\n");
  nescalog(nescalogpath, "  -data-len <num>: Append random data to payload.\n");
  nescalog(nescalogpath, "  -src <ip>: Set custom source_ip.\n");
  nescalog(nescalogpath, "  -srcport <port>: Set custom source_port.\n");
  nescalog(nescalogpath, "  -ipopt <R|S [route]|L [route]|T|U |[HEX]>: Adding ip option in packets.\n");
  nescalog(nescalogpath, "  -mtu <mtu>: Fragment all packets.\n");
  nescalog(nescalogpath, "  -win <num>: Set custom window size.\n");
  nescalog(nescalogpath, "  -ttl <num>: Set custom ip_header_ttl.\n");
  nescalog(nescalogpath, "  -badsum: Send packets with a bogus checksum.\n");
  nescalog(nescalogpath, "  -acknum <num>: Set custom ACK number.\n");
  nescalog(nescalogpath, "  -adler32: Use adler32 checksum for SCTP.\n");
  nescalog(nescalogpath, "SPEED OPTIONS:\n");
  nescalog(nescalogpath, "  -ping-maxg <num>: Set max group len for ping.\n");
  nescalog(nescalogpath, "  -ping-ming <num>: Set min group len for ping.\n");
  nescalog(nescalogpath, "  -ping-pg <num>: Set the value by which the group for ping will be incremented.\n");
  nescalog(nescalogpath, "  -scan-maxg <num>: Set max group len for scan ports.\n");
  nescalog(nescalogpath, "  -scan-ming <num>: Set min group len for scan ports.\n");  
  nescalog(nescalogpath, "  -scan-pg <num>: Set the value by which the group for port scan will be incremented.\n");
  nescalog(nescalogpath, "OUTPUT OPTIONS:\n");
  nescalog(nescalogpath, "  -txt <path file>: Save log on text file.\n");
  nescalog(nescalogpath, "  -failed: Display all no open ports.\n");
  nescalog(nescalogpath, "  -html: Display http response.\n");
  nescalog(nescalogpath, "  -packet-trace <level (1-3)>: Display all raw packets sent.\n");
  nescalog(nescalogpath, "  -v, -vv, -vvv: Increase verbosity level (higher is greater effect).\n");      
  nescalog(nescalogpath, "MISC OPTIONS:\n");
  nescalog(nescalogpath, "  -cfg <file path>: Use a different config.\n");
  nescalog(nescalogpath, "  -help: Display this message and exit.\n");
  nescalog(nescalogpath, "  -printargs: Display all arguments (options).\n");
  nescalog(nescalogpath, "EXAMPLES:\n");
  nescalog(nescalogpath, "  %s google.com -p 80,443\n", argv[0]);
  nescalog(nescalogpath, "  %s 72.230.205.0/24 -p 80,8080,81 -S5\n", argv[0]);
  nescalog(nescalogpath, "  %s https://www.youtube.com\n", argv[0]);
  exit(0);
}

std::string join(const std::vector<std::string>& vec, const std::string& del)
{
  std::string res;
  size_t i;
  
  for (i = 0; i < vec.size(); ++i) {
    res += vec[i];
    if (i != vec.size() - 1)
      res += del;
  }
  
  return res;
}

