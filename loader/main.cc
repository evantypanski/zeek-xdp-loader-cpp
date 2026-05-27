#include "connect.h"
#include "options.h"

int main(int argc, char** argv) {
    options::config cfg;
    options::parse_cmdline(argc, argv, &cfg);
    switch ( cfg.cmd ) {
        case options::Command::Load: zeek::xdp::load(cfg); break;
        case options::Command::Unload: zeek::xdp::unload_all(cfg); break;
        case options::Command::None: exit(1); // already errored
    }

    return 0;
}
