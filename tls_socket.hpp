#pragma once

#include <net/tcp/connection.hpp>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/tls_server.h>
#include <botan/tls_callbacks.h>

using Connection_ptr = net::tcp::Connection_ptr;

class TLS_socket : public Botan::TLS::Callbacks
{
public:
  TLS_socket(Connection_ptr remote,
             Botan::RandomNumberGenerator& rng,
             Botan::Credentials_Manager& credman) :
    m_rng(rng),
    m_creds(credman),
    m_session_manager(m_rng),
    m_tls(*this, m_session_manager, m_creds, m_policy, m_rng),
    m_socket(remote)
  {
    assert(m_socket);
    m_socket->on_read(8192, 
    [this] (auto buf, size_t n) {
      this->tls_receive(buf.get(), n);
    });
    m_socket->on_disconnect(
    [this] (auto, auto) {
      if (on_disconnect) on_disconnect(*this);
    });
  }

  void tls_receive(const uint8_t* buf, const size_t n)
  {
    try
    {
      int rem = this->m_tls.received_data(buf, n);
      (void) rem;
      //printf("Finished processing (rem: %u)\n", rem);
    }
    catch(Botan::Exception& e)
    {
      printf("Fatal TLS error %s\n", e.what());
      m_socket->close();
    }
    catch(...)
    {
      printf("Unknown error!\n");
      m_socket->close();
    }
  }

  void tls_alert(Botan::TLS::Alert alert) override
  {
    printf("Got a %s alert: %s\n",
          (alert.is_fatal() ? "fatal" : "warning"),
          alert.type_string().c_str());
  }

  bool tls_session_established(const Botan::TLS::Session&) override
  {
    // return true to store session
    return true;
  }

  void tls_emit_data(const uint8_t buf[], size_t len) override
  {
    m_socket->write(buf, len);
  }

  void tls_record_received(uint64_t, const uint8_t buf[], size_t buf_len) override
  {
    if (on_read) on_read(buf, buf_len);
  }

  void tls_session_activated() override
  {
    on_connected(*this);
  }

  void write(const std::string& text)
  {
    m_tls.send(text);
  }

  void close()
  {
    m_socket->close();
  }

  std::string to_string() const {
    return m_socket->to_string();
  }

  auto get_connection() noexcept {
    return m_socket;
  }
  auto get_remote() noexcept {
    return m_socket->remote();
  }

public:
  delegate<void(TLS_socket&)> on_connected;
  delegate<void(TLS_socket&)> on_disconnect;
  delegate<void(const uint8_t[], size_t)> on_read = nullptr;
private:
  Botan::RandomNumberGenerator& m_rng;
  Botan::Credentials_Manager&   m_creds;
  Botan::TLS::Strict_Policy     m_policy;
  Botan::TLS::Session_Manager_In_Memory m_session_manager;

  Botan::TLS::Server m_tls;
  Connection_ptr m_socket;
};
