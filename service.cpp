// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// IncludeOS
#include <service>
#include <net/inet4.hpp>
#include <net/tcp/tcp.hpp>

// Std
#include <cstdio>

// Botan
#include <botan/botan.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/sha2_64.h>
#include <botan/sha2_32.h>
#include <botan/credentials_manager.h>
#include <botan/system_rng.h>

#include <botan/ecdh.h>
#include <botan/ecdsa.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>
#include <botan/x509path.h>
#include <botan/tls_server.h>
#include <botan/tls_callbacks.h>

using Connection_ptr = net::tcp::Connection_ptr;
using Disconnect = net::tcp::Connection::Disconnect;

// Copied straight from tests...
class Credentials_Manager_Test : public Botan::Credentials_Manager
{
public:
  Credentials_Manager_Test(const Botan::X509_Certificate& server_cert,
         const Botan::X509_Certificate& ca_cert,
         Botan::Private_Key* server_key) :
    m_server_cert(server_cert),
      m_ca_cert(ca_cert),
    m_key(server_key)
  {
    std::unique_ptr<Botan::Certificate_Store> store(new Botan::Certificate_Store_In_Memory(m_ca_cert));
    m_stores.push_back(std::move(store));
    m_provides_client_certs = false;
  }

  std::vector<Botan::Certificate_Store*>
  trusted_certificate_authorities(const std::string&,
          const std::string&) override
  {
    std::vector<Botan::Certificate_Store*> v;
    for (auto&& store : m_stores)
        v.push_back(store.get());
    return v;
  }

  std::vector<Botan::X509_Certificate> cert_chain(
              const std::vector<std::string>& cert_key_types,
              const std::string& type,
              const std::string&) override
  {
    std::vector<Botan::X509_Certificate> chain;

    if (type == "tls-server" || (type == "tls-client" && m_provides_client_certs))
    {
      bool have_match = false;
      for (size_t i = 0; i != cert_key_types.size(); ++i)
          if(cert_key_types[i] == m_key->algo_name())
              have_match = true;

      if(have_match)
      {
        chain.push_back(m_server_cert);
        chain.push_back(m_ca_cert);
      }
    }
    return chain;
  }

  Botan::Private_Key* private_key_for(const Botan::X509_Certificate&,
              const std::string&,
              const std::string&) override
  {
    return m_key.get();
  }

  Botan::SymmetricKey psk(const std::string& type,
        const std::string& context,
        const std::string&) override
  {
    //if (type == "tls-server" && context == "session-ticket")
    //  return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");

    return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD"); // PSK key
  }

public:
  Botan::X509_Certificate m_server_cert, m_ca_cert;
  std::unique_ptr<Botan::Private_Key> m_key;
  std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
  bool m_provides_client_certs;
};

Botan::Credentials_Manager* create_creds(Botan::RandomNumberGenerator& rng,
           bool with_client_certs = false)
{
  Botan::EC_Group ec_params("secp256r1");

  std::unique_ptr<Botan::Private_Key> ca_key(new Botan::ECDSA_PrivateKey(rng, ec_params));
  
  Botan::X509_Cert_Options ca_opts;
  ca_opts.common_name = "Test CA";
  ca_opts.country = "VT";
  ca_opts.CA_key(1);

  Botan::X509_Certificate ca_cert =
    Botan::X509::create_self_signed_cert(ca_opts,
           *ca_key,
           "SHA-256",
           rng);

  Botan::Private_Key* server_key = new Botan::ECDSA_PrivateKey(rng, ec_params);

  Botan::X509_Cert_Options server_opts;
  server_opts.common_name = "server.example.com";
  server_opts.country = "VT";

  Botan::PKCS10_Request req = Botan::X509::create_cert_req(server_opts,
                 *server_key,
                 "SHA-256",
                 rng);

  Botan::X509_CA ca(ca_cert, *ca_key, "SHA-256", rng);

  auto now = std::chrono::system_clock::now();
  Botan::X509_Time start_time(now);
  typedef std::chrono::duration<int, std::ratio<31556926>> years;
  Botan::X509_Time end_time(now + years(1));

  Botan::X509_Certificate server_cert = ca.sign_request(req,
              rng,
              start_time,
              end_time);

  Credentials_Manager_Test* cmt (new Credentials_Manager_Test(server_cert, ca_cert, server_key));
  cmt->m_provides_client_certs = with_client_certs;
  return cmt;
}

std::unique_ptr<Botan::RandomNumberGenerator> make_rng()
{
  return std::unique_ptr<Botan::RandomNumberGenerator>(new Botan::System_RNG);
}


class Application : public Botan::TLS::Callbacks
{
public:
  Application(Connection_ptr remote) :
    m_rng(make_rng()),
    m_session_manager(*m_rng),
    m_creds(create_creds(*m_rng)),
    m_tls(*this, m_session_manager, *m_creds, m_policy, *m_rng),
    m_socket(remote)
  {
    m_socket->on_read(8192, 
    [this] (auto buf, size_t n) {
      this->on_client_write(buf.get(), n);
    });
  }

  void on_client_write(const uint8_t* buf, size_t n)
  {
    try
    {
      printf("Finished processing (rem: %u)\n",
             this->m_tls.received_data(buf, n));
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

  bool tls_session_established(const Botan::TLS::Session& session) override
  {
    printf("Handshake complete, %s with %s\n",
     session.version().to_string().c_str(),
     session.ciphersuite().to_string().c_str());

    if (!session.session_id().empty())
        printf("Session ID %s\n", Botan::hex_encode(session.session_id()).c_str());
    return true;
  }

  void tls_emit_data(const uint8_t buf[], size_t len) override
  {
    printf("Emit %d\n", len);
    m_socket->write(buf, len);
  }

  void tls_record_received(uint64_t rec_no, const uint8_t buf[], size_t buf_len) override
  {
    printf("%d bytes in record %d\n", buf_len, rec_no);
    m_hash.update(buf, buf_len);
    std::string reply = "H(" + Botan::hex_encode(buf, buf_len) + ") = " +
      Botan::hex_encode(m_hash.final());

    printf("Replying %s\n", reply.c_str());
    m_tls.send(reply);
  }

  void tls_verify_cert_chain(
    const std::vector<Botan::X509_Certificate>& cert_chain,
    const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
    const std::vector<Botan::Certificate_Store*>& trusted_roots,
    Botan::Usage_Type usage,
    const std::string& hostname,
    const Botan::TLS::Policy& policy) override
   {
      if(cert_chain.empty())
        throw Botan::Invalid_Argument("Certificate chain was empty");

      Botan::Path_Validation_Restrictions restrictions(
                policy.require_cert_revocation_info(),
                policy.minimum_signature_strength());

      Botan::Path_Validation_Result result =
        x509_path_validate(cert_chain,
                          restrictions,
                          trusted_roots,
                          (usage == Botan::Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                          usage,
                          std::chrono::system_clock::now(),
                          tls_verify_cert_chain_ocsp_timeout(),
                          ocsp_responses);

      if (!result.successful_validation())
        throw Botan::Exception("Certificate validation failure: " + result.result_string());
      printf("Cert chain validated\n");
    }

private:
  std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
  Botan::TLS::Strict_Policy m_policy;
  Botan::TLS::Session_Manager_In_Memory m_session_manager;
  std::unique_ptr<Botan::Credentials_Manager> m_creds;

  Botan::TLS::Server m_tls;
  Connection_ptr m_socket;
  Botan::SHA_256 m_hash;
};
static std::map<std::string, std::unique_ptr<Application>> g_apps;

void Service::start()
{
  auto& inet = net::Inet4::ifconfig<0>(
    { 10,0,0,42 },      // IP
    { 255,255,255,0 },  // Netmask
    { 10,0,0,1 },       // Gateway
    { 8,8,8,8 });       // DNS

  // Set up a TCP server on port 443
  auto& server = inet.tcp().bind(443);
  printf("Server listening: %s\n", 
         server.local().to_string().c_str());

  using namespace Botan;

  try {
    server.on_connect(
    [&inet] (Connection_ptr client) {
      printf("New client: %s\n", client->to_string().c_str());
      g_apps[client->to_string()].reset(new Application(client));

      // When client is disconnecting
      client->on_disconnect([](Connection_ptr client, Disconnect reason) {
        printf("Disconnected from %s\n", client->to_string().c_str());
        g_apps.erase(client->to_string());
      });
    });
  } catch(std::exception e) {
    printf("Botan TLS exception: %s\n", e.what());
  }
}
