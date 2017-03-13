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

#include <service>
#include <net/inet4>
#include <memdisk>
#include <cstdio>
#include <botan/system_rng.h>
#include <botan/pkcs8.h>

#include "tls_server.hpp"
#include "credman.hpp"

static inline auto& get_rng()
{
  static auto& g_rng = Botan::system_rng();
  return g_rng;
}

static Botan::Credentials_Manager* credman = nullptr;
static auto& get_credentials()
{
  return *credman;
}

static std::map<net::tcp::Socket, std::unique_ptr<net::TLS_server>> g_apps;

void new_client(net::tcp::Connection_ptr conn)
{
  //printf("New client from %s\n", conn->to_string().c_str());
  // create TLS socket
  auto* tls_client = new net::TLS_server(conn, get_rng(), get_credentials());
  // add to map of sockets in application
  g_apps[conn->remote()].reset(tls_client);

  tls_client->on_connect(
  [] (net::Stream& stream)
  {
    printf("TLS connection to %s\n", stream.to_string().c_str());
  });

  tls_client->on_read(8192,
  [tls_client] (auto buf, size_t buf_len)
  {
    printf("TLS data received from %s:\n%.*s\n", tls_client->to_string().c_str(), buf_len, buf.get());
    // send response
    tls_client->write("<html><body>Hello encrypted world!</body><html>\r\n");
    tls_client->close();
  });

  tls_client->on_close(
  [tls_client] {
    printf("TLS disconnected from %s\n", tls_client->to_string().c_str());
    g_apps.erase(tls_client->remote());
  });
}

inline std::unique_ptr<Botan::Private_Key> read_private_key(
      fs::File_system& fs, const std::string& filepath)
{
  auto key_file = fs.read_file(filepath);
  assert(key_file);
  Botan::DataSource_Memory data{key_file.data(), key_file.size()};
  return std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(data, get_rng()));
}

extern "C" void kernel_sanity_checks();

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

    // load CA certificate
    auto der_cert = filesys.read_file("/test.der");
    assert(der_cert);
    std::vector<uint8_t> vec_ca_cert(
                der_cert.data(), der_cert.data() + der_cert.size());
    Botan::X509_Certificate ca_cert(vec_ca_cert);
    // load CA private key
    auto ca_key = read_private_key(filesys, "/test.key");
    // load server private key
    auto srv_key = read_private_key(filesys, "/server.key");

    credman = Credman::create(
            get_rng(),
            std::move(ca_key),
            ca_cert,
            std::move(srv_key));

    server.on_connect(new_client);

    kernel_sanity_checks();
  });
}
