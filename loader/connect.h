#pragma once

#include <net/if.h>
#include <xdp/libxdp.h>
#include <concepts>
#include <optional>
#include <string>

#include "options.h"
#include "shunter.h"

namespace zeek::xdp {
// Helper
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

// Possible key values
template<typename T>
concept SupportedBpfKey = IsAnyOf<T, canonical_tuple, ip_pair_key>;

/**
 * Loads and attaches to the XDP program.
 */
std::optional<std::string> load(const options::config& cfg);

/**
 * Unloads all XDP programs, and optionally the pinned maps at pin_path.
 */
void unload_all(const options::config& cfg);
} // namespace zeek::xdp
