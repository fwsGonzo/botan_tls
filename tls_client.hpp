#pragma once

#include <net/tcp/connection.hpp>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/tls_server.h>
#include <botan/tls_callbacks.h>

using Connection_ptr = net::tcp::Connection_ptr;

class TLS_client : public Botan::TLS::Callbacks
{
public:

};
