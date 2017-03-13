#pragma once

#include <net/tcp/connection.hpp>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>

using Connection_ptr = net::tcp::Connection_ptr;

class TLS_client : public Botan::TLS::Callbacks
{
public:

protected:
    void tls_emit_data(const uint8_t buf[], size_t length) override
    {
      conn->write(buf, length);
    }

    void tls_alert(Botan::TLS::Alert alert) override
    {
      output() << "Alert: " << alert.type_string() << "\n";
    }

    void tls_record_received(uint64_t /*seq_no*/, const uint8_t buf[], size_t buf_size) override
    {
       printf("CLIENT read len=%u:\n%.*s\n",
             buf_size, buf_size, buf);
    }

private:
  Connection_ptr conn;
};
