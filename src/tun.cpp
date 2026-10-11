#include <csignal>
#include <cstdio>
#include <exception>

#include <boost/asio.hpp>

#include "Upf.hpp"

int main() {
    try {
        boost::asio::io_context io;

        Upf upf(io, "upf_cn_veth", "192.168.9.1", 2152, "192.168.9.2", "192.168.5.2", "192.168.5.1");

        // Ctrl+C / kill
        boost::asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&io](const boost::system::error_code&, int) { io.stop(); });

        upf.start();
        io.run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
    return 0;
}
