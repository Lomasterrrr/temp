#include "../include/nescadata.h"
#include "../include/nescaengine.h"
#include "../ncsock/include/utils.h"
#include "../ncsock/include/ip.h"

#include <cstddef>
#include <sys/types.h>
#include <algorithm>
#include <vector>
#include <iostream>
#include <unordered_map>

#define COPY_VECTOR(source, destination)                                       \
  do {                                                                         \
    for (const auto &item : source) {                                          \
      destination.push_back(item);                                             \
    }                                                                          \
  } while (0)

void
NESCATARGET::addport(u16 port, int state, u8 proto, u8 method)
{
  NESCAPORT tmp;
  tmp.port = port;
  tmp.state = state;
  tmp.proto = proto;
  tmp.method = method;
  ports.push_back(tmp);
}

void
NESCATARGET::addid(int service, const std::string &id)
{
  struct NESCAIDENTSERVICE res;
  
  for (auto& s : idents) {
    if (s.service == service) {
      s.ids.push_back(id);
      return;
    }
  }
  res.service = service;
  idents.push_back(res);
  addid(service, id);
}

bool
NESCATARGET::checkids(int service)
{
  for (auto& s : idents)
    if (s.service == service)
      return true;
  return false;
}

std::vector<std::string>
NESCATARGET::getids(int service)
{
  for (auto& s : idents)
    if (s.service == service)
      return s.ids;
  
  return {};
}

bool
NESCATARGET::checkports(std::vector<u16> ports, int state, int proto)
{
  for (const auto& p : this->ports)
    for (const auto& pp : ports)
      if (p.port == pp && p.state == state && p.proto == proto)
	return true;
  return false;
}

bool
NESCATARGET::checkopenports(void)
{
  for (const auto& p : ports) {
#define C(key) p.method == (key)
    if (C(TCP_SYN_SCAN) || C(TCP_FIN_SCAN)     ||
	C(TCP_PSH_SCAN) || C(TCP_XMAS_SCAN)    ||
	C(TCP_NULL_SCAN) || C(TCP_WINDOW_SCAN) ||
	C(0) || C(SCTP_INIT_SCAN) || C(UDP_SCAN))
      if (p.state == PORT_OPEN)
	return true;
    if (C(TCP_MAIMON_SCAN))
      if (p.state == PORT_OPEN_OR_FILTER)
	return true;
    if (C(TCP_ACK_SCAN))
      if (p.state == PORT_NO_FILTER)
	return true;
    if (C(SCTP_COOKIE_SCAN))
      if (p.state == PORT_CLOSED)
	return true;
#undef C
  }
  return false;
}

bool
NESCATARGET::checkport(u16 port, int state, u8 proto)
{
  for (const auto &p : ports)
    if (p.proto == proto && p.state == state && p.port == port)
      return true;
  return false;
}

std::vector<u16>
NESCATARGET::getports(int state, u8 proto, u8 method)
{
  std::vector<u16> res;
  for (const auto& p : ports)
    if (p.state == state && p.proto == proto && p.method == method)
      res.push_back(p.port);
  return res;
}

void
NESCADATA2::nescadatainit(void)
{
  std::string importpath = "";
  randomip4num = 0;
  importfilelen = 0;
  maxtargets = 0;
  tmptargets.clear();
  nescatargets.clear();
}

size_t
NESCADATA2::goodnumget(void)
{
  size_t res = 0;
  for (const auto& t : nescatargets) {
    if (t.second.good)
      res++;
  }
  return res;
}

NESCATARGET*
NESCADATA2::get_nescadata(const std::string& target)
{
  if (target.empty())
    return nullptr;
  return &this->nescatargets[target];
}

NESCATARGET
*NESCADATA2::targetgetip4(const std::string &dst)
{
  for (auto& pair : this->nescatargets)
    if (pair.second.ip == dst)
      return &(pair.second);
  return nullptr;
}

void
NESCADATA2::updateget(void)
{
  for (auto& pair : this->nescatargets)
    pair.second.get = false;
}

void
NESCADATA2::set_nescadata(std::string target)
{
  if (target.empty())
    return;
  
  NESCATARGET tmp;
  tmp.target = target;
  tmp.get = false;
  tmp.good = false;
  tmp.newdns = "n/a";
  tmp.init = false;
  tmp.ports.clear();
  this->nescatargets[target] = tmp;
}

size_t
NESCADATA2::targetsgetnum(void)
{
  return this->maxtargets;
}

void
NESCADATA2::delnotgood(std::vector<NESCATARGET*> &targets)
{
  std::vector<NESCATARGET*> rem;
  for (auto* target : targets)
    if (!target->good)
      rem.push_back(target);
  for (auto* r : rem)
    targets.erase(std::remove(targets.begin(), targets.end(), r), targets.end());
}

void
NESCADATA2::set_importfile(const std::string &path)
{
  if (!path.empty()) {
    this->importpath = path;
    this->importfilelen = get_numlines(path);
    this->maxtargets += importfilelen;
  }
}

void
NESCADATA2::set_randomip4s(const size_t num)
{
  if (num > 0) {
    this->randomip4num = num;
    this->maxtargets += randomip4num;
  }
}

void
NESCADATA2::set_runtargets(const std::vector<std::string>& targets)
{
  if (!targets.empty()) {
    COPY_VECTOR(targets, this->tmptargets);
    maxtargets += targets.size();
  }
}

std::string
NESCADATA2::get_ip4nescadata(const std::string &target)
{
  if (!target.empty())
    return get_nescadata(target)->ip;
  return "";
}

void
NESCADATA2::del_nescadata(const std::string &target)
{
  nescatargets.erase(target);
}

bool
NESCADATA2::check_initnescadata(const std::string& dst)
{
  NESCATARGET *tmp;
  tmp = get_nescadata(dst);
  if (tmp == nullptr)
    return false;
  return tmp->init;
}

bool
NESCADATA2::check_getnescadata(const std::string &dst)
{
  NESCATARGET *tmp;
  tmp = get_nescadata(dst);
  if (tmp == nullptr)
    return false;
  return tmp->get;
}

void
NESCADATA2::targetsinit(size_t num)
{
  size_t i = 0, n = 0, k = 0, u = 0, j = num;
  struct easyresolvres tmp;
  NESCATARGET *ntmp;
  std::string dtmp;

  if (randomip4num) {
    while(j && randomip4num) {
      dtmp = random_ip4();
      randomip4num--;
      j--;
      tmptargets.push_back(dtmp);
    }
  }
  if (importfilelen) {
    while (n < num && importfilelen) {
      do {
	dtmp = copyfileline(importpath, n);
	if (!check_initnescadata(dtmp))
	  tmptargets.push_back(dtmp);
	n++;
	importfilelen--;
      } while (importfilelen && !check_initnescadata(dtmp));
    }
  }
  while ((i < num) && (k < tmptargets.size())) {
    if (k < tmptargets.size()) {
      if (!check_initnescadata(tmptargets[k]) && !tmptargets.empty()) {
        if ((tmp = easyresolv(tmptargets[k])).success) {
          set_nescadata(tmptargets[k]);
          ntmp = get_nescadata(tmptargets[k]);
	  if (ntmp != nullptr) {
	    ntmp->ip = tmp.ip;
	    if (!tmp.dns.empty())
	      ntmp->dns = tmp.dns;
	    ntmp->init = true;
	    ++i;
	    tmptargets.erase(tmptargets.begin() + k);
	    if (i >= num)
	      break;
	  }
        } else
	    ++k;
      }
      else
	++k;
    }
  }
  u = del_dublicateip4();
  if (u > 0)
    targetsinit(u);
}

 
std::vector<NESCATARGET*>
NESCADATA2::targetsget(size_t num)
{
  std::vector<NESCATARGET*> res;
  size_t i = 0;
  
  for (auto& pair : nescatargets) {
    if (!pair.second.get) {
      pair.second.get = true;
      res.push_back(&pair.second);
      i++;
      if (i >= num)
	break;
    }
  }
  return res;
}

size_t
NESCADATA2::del_dublicateip4(void)
{
  std::unordered_map<std::string, size_t> num;
  size_t res = 0;

  for (auto it = nescatargets.begin(); it != nescatargets.end();) {
    const std::string& ip = it->second.ip;
    if (num.find(ip) == num.end()) {
      num[ip] = 1;
      ++it;
    }
    else {
      ++res;
      it = nescatargets.erase(it);
    }
  }
  return res;
}

size_t
NESCADATA2::get_numlines(const std::string& path)
{
  std::ifstream file(path);
  return std::count(std::istreambuf_iterator<char>(file), 
		    std::istreambuf_iterator<char>(), '\n');
}

std::string
NESCADATA2::copyfileline(const std::string& path, ssize_t num)
{
  std::ifstream file(path);
  std::string line;
  ssize_t i = 0;
  
  if (!file.is_open())
    return "";
  
  while (std::getline(file, line)) {
    if (i == num) {
      file.close();
      return line;
    }
    ++i;
  }
  file.close();
  return "";
}

struct easyresolvres
easyresolv(const std::string &target)
{
  struct easyresolvres res;
  char ip4buf[16];
  char *tmpurl;
  int tmp;

  tmpurl = NULL;
  res.success = false;
  
#define C(key) target == (key)
  if (target.empty())
    goto fail;
  if (C("localhost")) {
    res.ip = LOCALHOST_IPv4;
    res.success = true;
    return res;
  }
  if (C("route") || C("gateway")) {
    get_gateway_ip(ip4buf, 16);
    if (!std::string(ip4buf).empty()) {
      res.ip = std::string(ip4buf);
      res.success = true;
      return res;
    }
    goto fail;
  }
#undef C
  tmp = this_is(target.c_str());
  if (tmp == _URL_) {
    tmpurl = clean_url(target.c_str());
    if (!tmpurl)
      goto fail;
    tmp = ip4_util_strdst(tmpurl, ip4buf, 16);
    if (tmp == -1)
      goto fail;
    res.dns = tmpurl;
    res.ip = std::string(ip4buf);
    res.success = true;
    free(tmpurl);
    return res;
  }
  if (tmp == DNS) {
    tmp = ip4_util_strdst(target.c_str(), ip4buf, 16);
    if (tmp == -1)
      goto fail;
    res.dns = target;
    res.ip = ip4buf;
    res.success = true;
    return res;
  }
  if (tmp == IPv4) {
    res.ip = target;
    res.success = true;
    return res;
  }
  
 fail:
  if (tmpurl)
    free(tmpurl);
  return res;
}

std::vector<std::string>
splitstring(const std::string& str, char del)
{
  std::vector<std::string> result;
  size_t pos = 0, found;
  std::string token;

  while ((found = str.find_first_of(del, pos)) != std::string::npos) {
    token = str.substr(pos, found - pos);
    result.push_back(token);
    pos = found + 1;
  }

  result.push_back(str.substr(pos));
  return result;
}
