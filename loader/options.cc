#include "options.h"

#include <net/if.h>
#include <charconv>
#include <iostream>
#include <system_error>

namespace options {

void usage(const char* prog_name, bool full) {
    printf("Zeek's XDP loader\n");
    printf("usage: %s [options]", prog_name);
    // TODO
}

bool parse_cmd_load(int argc, char** argv, options::config* cfg) {
    struct option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"dev", required_argument, nullptr, 'd'},
        {"pin-path", required_argument, nullptr, 'p'},
        {"include-vlan", no_argument, nullptr, 'v'},
        {"skb-mode", no_argument, nullptr, 'S'},
        {"native-mode", no_argument, nullptr, 'N'},
        {"auto-mode", no_argument, nullptr, 'A'},
        {"force", no_argument, nullptr, 'F'},
        {"filename", required_argument, nullptr, 1},
        {"progname", required_argument, nullptr, 2},
        {"offload-mode", no_argument, nullptr, 3},

        {"shunter", no_argument, nullptr, 4}, // load shunter
        {"shunt-flow-map-max-entries", required_argument, nullptr, 5},
        {"shunt-ip-pair-map-max-entries", required_argument, nullptr, 6},
        {0, 0, nullptr, 0},
    };

    const char* optstring = "hd:p:vSNA:F";

    int opt;
    int longindex = 0;
    bool full_help = false;

    while ( (opt = getopt_long(argc, argv, optstring, long_opts, &longindex)) != -1 ) {
        switch ( opt ) {
            case 'd': {
                std::string_view optarg_view(optarg);
                cfg->ifname = optarg_view;
                cfg->ifindex = if_nametoindex(cfg->ifname.c_str());

                if ( cfg->ifindex == 0 ) {
                    auto error_msg = std::system_error(errno, std::generic_category()).what();
                    std::cerr << "ERR: --dev name unknown: " << error_msg << "\n";

                    return false;
                }
                break;
            }
            case 'p': cfg->pin_path = optarg; break;
            case 'v': cfg->include_vlan = true; break;
            case 'A': cfg->attach_mode = XDP_MODE_UNSPEC; break;
            case 'S': cfg->attach_mode = XDP_MODE_SKB; break;
            case 'N': cfg->attach_mode = XDP_MODE_NATIVE; break;
            case 'F': cfg->force = true; break;
            case 3: cfg->attach_mode = XDP_MODE_HW; break;
            case 1:
                // TODO: handle --filename
                break;
            case 2:
                // TODO: handle --progname
                break;
            case 4:
                // TODO: handle --progname
                cfg->load_shunter = true;
                break;
            case 5: {
                std::string_view sv(optarg);
                uint32_t value = 0;

                auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
                if ( ec == std::errc::invalid_argument )
                    std::cerr << "ERR: max entries '" << sv << "' is not a valid number\n";
                else if ( ec == std::errc::result_out_of_range )
                    std::cerr << "ERR: max entries '" << sv << "' is out of range\n";

                cfg->conn_id_map_max_size = value;
                break;
            }
            case 6: {
                // TODO: dedup with above
                std::string_view sv(optarg);
                uint32_t value = 0;

                auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
                if ( ec == std::errc::invalid_argument )
                    std::cerr << "ERR: max entries '" << sv << "' is not a valid number\n";
                else if ( ec == std::errc::result_out_of_range )
                    std::cerr << "ERR: max entries '" << sv << "' is out of range\n";

                cfg->ip_pair_map_max_size = value;
                break;
            }
            case 'h': full_help = true; [[fallthrough]];
            default: usage(argv[0], full_help); exit(1);
        }
    }

    return true;
}

bool parse_cmd_unload(int argc, char** argv, options::config* cfg) {
    struct option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"dev", required_argument, nullptr, 'd'},
        {"pin-path", required_argument, nullptr, 'p'},
        {"skb-mode", no_argument, nullptr, 'S'},
        {"native-mode", no_argument, nullptr, 'N'},
        {"auto-mode", no_argument, nullptr, 'A'},
        {"unpin-maps", no_argument, nullptr, 'U'},
        {0, 0, nullptr, 0},
    };

    const char* optstring = "hd:p:vSNAU";

    int opt;
    int longindex = 0;
    bool full_help = false;

    while ( (opt = getopt_long(argc, argv, optstring, long_opts, &longindex)) != -1 ) {
        switch ( opt ) {
            case 'd': {
                std::string_view optarg_view(optarg);
                cfg->ifname = optarg_view;
                cfg->ifindex = if_nametoindex(cfg->ifname.c_str());

                if ( cfg->ifindex == 0 ) {
                    auto error_msg = std::system_error(errno, std::generic_category()).what();
                    std::cerr << "ERR: --dev name unknown: " << error_msg << "\n";

                    return false;
                }
                break;
            }
            case 'p': cfg->pin_path = optarg; break;
            case 'A': cfg->attach_mode = XDP_MODE_UNSPEC; break;
            case 'S': cfg->attach_mode = XDP_MODE_SKB; break;
            case 'N': cfg->attach_mode = XDP_MODE_NATIVE; break;
            case 'U': cfg->unpin_maps = true; break;
            case 3: cfg->attach_mode = XDP_MODE_HW; break;
            case 'h': full_help = true; [[fallthrough]];
            default: usage(argv[0], full_help); exit(1);
        }
    }

    return true;
}

bool parse_cmdline(int argc, char** argv, options::config* cfg) {
    if ( argc < 2 ) {
        std::cerr << "ERR: Missing command\n";
        return false;
    }

    std::string_view cmd(argv[1]);
    if ( cmd == "load" ) {
        cfg->cmd = Command::Load;
        return parse_cmd_load(argc - 1, argv + 1, cfg);
    }
    else if ( cmd == "unload" ) {
        cfg->cmd = Command::Unload;
        return parse_cmd_unload(argc - 1, argv + 1, cfg);
    }

    std::cerr << "ERR: Invalid command '" << cmd << "'\n";
    return false;
}

} // namespace options
