#include "connect.h"

#include <unistd.h>
#include <linux/if_link.h>
#include <filesystem>

#include "shunter.skel.h"

namespace zeek::xdp {
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


    auto sec_name = bpf_program__section_name(skel->progs.xdp_shunt);
    if ( ! sec_name ) {
        shunter::destroy(skel);
        return "Could not determine ELF section name for shunter";
    }

    auto *prog = xdp_program__from_bpf_obj(skel->obj, sec_name);
    if ( ! prog ) {
        shunter::destroy(skel);
        return "Failed to parse BPF object via libxdp";
    }

    int err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
    if ( err ) {
        std::string err_msg = "Libxdp attach failed: ";
        // libxdp uses negative on fail
        err_msg += (err < 0) ? std::generic_category().message(-err) : std::to_string(err);
        shunter::destroy(skel);
        return err_msg;
    }

    return {};
}

std::optional<std::string> load(const options::config& cfg) {
    if ( cfg.force )
        unload_all(cfg);

    if ( cfg.load_shunter ) {
        if ( auto err = load_shunter(cfg) )
            return err;
    }

    return {};
}

void unload_all(const options::config& cfg) {
    bpf_xdp_detach(cfg.ifindex, XDP_FLAGS_DRV_MODE, nullptr);
    bpf_xdp_detach(cfg.ifindex, XDP_FLAGS_SKB_MODE, nullptr);

    if ( cfg.force && std::filesystem::exists(cfg.pin_path) )
        std::filesystem::remove_all(cfg.pin_path);
}
} // namespace zeek::xdp
