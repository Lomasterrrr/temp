#ifndef NESCADATA_HEADER
#define NESCADATA_HEADER

#include <iostream>
#include <sys/types.h>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <string>
#include <limits>
#include <map>

#include "../ncsock/include/types.h"

#define LOCALHOST_IPv4 "127.0.0.1"

struct NESCAPORT { u16 port; int state; u8 proto; u8 method; };
struct NESCAIDENTSERVICE { int service; std::vector<std::string> ids; };
class NESCATARGET {
public:
  std::string target, ip, dns, newdns;
  bool init = false, get = false, good = false;
  std::vector<std::string> databaseres;
  std::vector<NESCAPORT> ports;
  std::string redirect;
  std::vector<NESCAIDENTSERVICE> idents;
  std::vector<std::string> login, pass, html;
  double rtt;

  void addport(u16 port, int state, u8 proto, u8 method);
  std::vector<u16> getports(int state, u8 proto, u8 method);
  bool checkopenports(void);
  bool checkport(u16 port, int state, u8 proto);
  bool checkports(std::vector<u16> ports, int state, int proto);
#define HTTP_SERVICE 1
#define FTP_SERVICE  2
  void addid(int service, const std::string &id);
  std::vector<std::string> getids(int service);
  bool checkids(int service);
};

typedef std::vector<NESCATARGET> nescatargets_t;
std::vector<std::string> splitstring(const std::string &str, char del);

struct easyresolvres {
  std::string ip;
  std::string dns;
  bool success;
};
struct easyresolvres
easyresolv(const std::string &target);

class NESCADATA2
{
  /* nesca 4 database: key = target; NESCATARGET = data */
  std::unordered_map<std::string, NESCATARGET> nescatargets;

  /* transitional buffer for the purposes of */
  std::vector<std::string> tmptargets;

  /* filepath to targets file */
  std::string importpath;
  
  /* number of ips for random generation */
  size_t randomip4num;
  
  /* number of lines in impor file */
  size_t importfilelen;

  /* the total number of targets in a given session */
  size_t maxtargets;

  /* get ip4 from target */
  std::string get_ip4nescadata(const std::string &target);

  /* creates a new datablock */
  void set_nescadata(std::string target);

  /* checks if the block was received earlier */
  bool check_initnescadata(const std::string &dst);
  bool check_getnescadata(const std::string &dst);  

  /* gets the datablock by key */
  NESCATARGET *get_nescadata(const std::string& target);

  /* deletes datablocks with the same addresses and returns the number of deleted datablock */
  size_t del_dublicateip4(void);
  
  /* gets the specified string from the specified file */
  std::string copyfileline(const std::string& path, ssize_t num);
  
  /* gets the number of lines in the file */
  size_t get_numlines(const std::string& path);

public:
  void nescadatainit(void);
  void set_importfile(const std::string& path);
  void set_randomip4s(const size_t num);
  void set_runtargets(const std::vector<std::string>& targets);

  /* preparation of a specified number of targets to obtain startnum is 1 */
  void targetsinit(size_t num);

  /* gets the specified number of targets which get = false, starts counting from 1 */
  std::vector<NESCATARGET*> targetsget(size_t num);

  /* sets all get targets = false, to retrieve again */
  void updateget(void);
  
  /* deletes the not good datablocks */
  void delnotgood(std::vector<NESCATARGET*> &targets);

  /* get the target by its ip4 address */
  NESCATARGET *targetgetip4(const std::string &dst);
  
  /* get the maximum number of targets in this session */
  size_t targetsgetnum(void);

  /* get number of targer which good = true */
  size_t goodnumget(void);

  /* deletes the specified datablock by key */
  void del_nescadata(const std::string& target);
};

#endif
