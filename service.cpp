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
#include <net/inet4>
#include <memdisk>

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
#include <botan/pkcs8.h>
#include <botan/pk_algs.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>
#include <botan/x509path.h>
#include <botan/tls_server.h>
#include <botan/tls_callbacks.h>

using Connection_ptr = net::tcp::Connection_ptr;
using ConnectCB = net::tcp::Connection::ConnectCallback;

typedef std::chrono::duration<int, std::ratio<31556926>> years;

static auto& get_rng()
{
  static auto& g_rng = Botan::system_rng();
  return g_rng;
}

class Credentials_Manager_Test : public Botan::Credentials_Manager
{
public:
  Credentials_Manager_Test(const Botan::X509_Certificate& server_cert,
         const Botan::X509_Certificate& ca_cert,
         std::unique_ptr<Botan::Private_Key> server_key) :
    m_server_cert(server_cert),
    m_ca_cert(ca_cert),
    m_server_key(std::move(server_key))
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
          if(cert_key_types[i] == m_server_key->algo_name())
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
    return m_server_key.get();
  }

  Botan::SymmetricKey psk(const std::string&,
        const std::string&,
        const std::string&) override
  {
    //if (type == "tls-server" && context == "session-ticket")
    //  return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");

    return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD"); // PSK key
  }

public:
  Botan::X509_Certificate             m_server_cert, m_ca_cert;
  std::unique_ptr<Botan::Private_Key> m_server_key;
  std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
  bool m_provides_client_certs;
};

std::string time_string(time_t time)
{
  struct tm* timeinfo;
  timeinfo = localtime(&time);
  
  char buff[32];
  int len = strftime(buff, sizeof(buff), "%b %d %H:%M", timeinfo);
  return std::string(buff, len);
}

static Botan::Credentials_Manager* credman = nullptr;
static auto& get_credentials()
{
  return *credman;
}

/**
 * 3. create private key 2 <server>
 * 4. create certificate request <req> with private key 2
 * 5. create CA with <CA> key and <CA> cert
 * 6, create certificate <server> by signing <req>
 * 
**/
void create_creds(std::unique_ptr<Botan::Private_Key> ca_key,
                  Botan::X509_Certificate& ca_cert,
                  std::unique_ptr<Botan::Private_Key> server_key)
{
  auto& rng = get_rng();

  //  X509_CA(const X509_Certificate& ca_cert,
  //          const Private_Key&      pkey,
  //          const std::string&      hash_fn,
  //          RandomNumberGenerator&  rng);
  Botan::X509_CA ca(ca_cert, *ca_key, "SHA-256", get_rng());

  // create server certificate from CA
  auto now = std::chrono::system_clock::now();
  Botan::X509_Time start_time(now);
  Botan::X509_Time end_time(now + years(1));

  // create certificate request
  Botan::X509_Cert_Options server_opts;
  server_opts.common_name = "server.example.com";
  server_opts.country = "VT";

  auto req = Botan::X509::create_cert_req(server_opts, *server_key, "SHA-256", rng);

  auto server_cert = ca.sign_request(req, rng, start_time, end_time);

  // create credentials manager
  credman = new Credentials_Manager_Test(
                server_cert, ca_cert, std::move(server_key));
}

class TLS_socket : public Botan::TLS::Callbacks
{
public:
  TLS_socket(Connection_ptr remote) :
    m_rng(get_rng()),
    m_creds(get_credentials()),
    m_session_manager(m_rng),
    m_tls(*this, m_session_manager, m_creds, m_policy, m_rng),
    m_socket(remote)
  {
    m_socket->on_read(8192, 
    [this] (auto buf, size_t n) {
      this->tls_receive(buf.get(), n);
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
    printf("Data received from %s:\n%.*s\n", m_socket->to_string().c_str(), buf_len, buf);
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

public:
  delegate<void(TLS_socket&)> on_connected;
private:
  Botan::RandomNumberGenerator& m_rng;
  Botan::Credentials_Manager&   m_creds;
  Botan::TLS::Strict_Policy     m_policy;
  Botan::TLS::Session_Manager_In_Memory m_session_manager;

  Botan::TLS::Server m_tls;
  Connection_ptr m_socket;
};
static std::map<net::tcp::Socket, std::unique_ptr<TLS_socket>> g_apps;

extern "C" void kernel_sanity_checks();

std::unique_ptr<Botan::Private_Key> read_private_key(
      fs::File_system& fs, const std::string& filepath)
{
  auto key_file = fs.read_file(filepath);
  assert(key_file);
  Botan::DataSource_Memory data{key_file.data(), key_file.size()};
  return std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(data, get_rng()));
}

void Service::start()
{
  auto& inet = net::Inet4::ifconfig<0>(
    { 10,0,0,42 },      // IP
    { 255,255,255,0 },  // Netmask
    { 10,0,0,1 },       // Gateway
    { 8,8,8,8 });       // DNS

  // Set up a TCP server on port 443
  auto& server = inet.tcp().bind(443);
  printf("Server listening on %s\n", server.local().to_string().c_str());

  auto disk = fs::new_shared_memdisk();
  disk->init_fs(
  [&server] (auto err, auto& filesys) {
    assert(!err);

    // CA certificate
    auto der_cert = filesys.read_file("/test.der");
    assert(der_cert);
    std::vector<uint8_t> vec_ca_cert(
                der_cert.data(), der_cert.data() + der_cert.size());
    Botan::X509_Certificate ca_cert(vec_ca_cert);
    // CA private key
    auto ca_key = read_private_key(filesys, "/test.key");
    // server private key
    auto srv_key = read_private_key(filesys, "/server.key");

    create_creds(std::move(ca_key), ca_cert, std::move(srv_key));

    server.on_connect(
    [] (Connection_ptr client)
    {
      printf("New client from %s\n", client->to_string().c_str());
      auto* tls_client = new TLS_socket(client);
      tls_client->on_connected = 
      [] (TLS_socket& socket) {
        socket.write("<html><body>Hello world</body><html>\r\n");
        socket.close();
      };
      g_apps[client->remote()].reset(tls_client);

      // When client is disconnecting
      client->on_disconnect(
      [] (Connection_ptr client, auto) {
        printf("Disconnected from %s\n", client->to_string().c_str());
        g_apps.erase(client->remote());
      });
    });

    kernel_sanity_checks();
  });
}
