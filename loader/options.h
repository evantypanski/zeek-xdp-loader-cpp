#pragma once

#include <getopt.h>
#include <string>
#include <xdp/libxdp.h>

// TODO: D:
#define IF_NAMESIZE	16

namespace options {

enum class Command {
  None,
  Load,
  Unload
};

struct config {
  Command cmd = Command::None;

  enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC;
  int ifindex = -1;
  std::string ifname = "";
  std::string pin_path = "/sys/fs/bpf/zeek";
  bool include_vlan = false;

  // Load
  bool load_shunter = false;
  uint32_t conn_id_map_max_size = 65535;
  uint32_t ip_pair_map_max_size = 65535;

  // Unload
  bool unpin_maps = false;
};

bool parse_cmdline(int argc, char **argv, config* cfg);
} // namespace options
