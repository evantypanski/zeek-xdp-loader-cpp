#include "connect.h"

#include <unistd.h>
#include <filesystem>

#include "shunter.skel.h"

namespace zeek::xdp {
uint32_t flags(const options::config& cfg) {
    uint32_t flags = 0;
    switch ( cfg.attach_mode ) {
        case XDP_MODE_UNSPEC: break;
        case XDP_MODE_NATIVE: flags |= (1U << 2); break;
        case XDP_MODE_SKB: flags |= (1U << 1); break;
        case XDP_MODE_HW: flags |= (1U << 3); break;
    }

    return flags;
}

struct bpf_map* get_canonical_id_map(struct shunter* skel) { return skel->maps.shunt_map; }
struct bpf_map* get_ip_pair_map(struct shunter* skel) { return skel->maps.ip_pair_map; }

std::optional<std::string> load_shunter(const options::config& cfg) {
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .pin_root_path = cfg.pin_path.c_str(),
    };
    auto skel = shunter::open(&open_opts);

    // This must be 1 or greater.
    bpf_map__set_max_entries(get_canonical_id_map(skel), cfg.conn_id_map_max_size);
    bpf_map__set_max_entries(get_ip_pair_map(skel), cfg.ip_pair_map_max_size);

    skel->rodata->include_vlan = cfg.include_vlan;

    shunter::load(skel);
    auto prog_fd = bpf_program__fd(skel->progs.xdp_shunt);
    if ( prog_fd < 0 )
        return "Could not find BPF program";

    auto err = bpf_xdp_attach(cfg.ifindex, prog_fd, flags(cfg), nullptr);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

std::optional<std::string> load(const options::config& cfg) {
    if ( cfg.load_shunter ) {
        if ( auto err = load_shunter(cfg) )
            return err;
    }

    return {};
}

void unload_all(const options::config& cfg) {
    bpf_xdp_detach(cfg.ifindex, flags(cfg), nullptr);

    if ( cfg.unpin_maps && std::filesystem::exists(cfg.pin_path) )
        std::filesystem::remove_all(cfg.pin_path);
}
}
