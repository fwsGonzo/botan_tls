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

inline static auto& get_rng() { return Botan::system_rng(); }

inline std::unique_ptr<Botan::Private_Key> read_private_key(
      fs::File_system& fs, const std::string& filepath)
{
  auto key_file = fs.read_file(filepath);
  assert(key_file);
  Botan::DataSource_Memory data{key_file.data(), key_file.size()};
  return std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(data, get_rng()));
}

#include "http_tls_server.hpp"

extern "C" void kernel_sanity_checks();

void Service::start()
{
  auto& inet = net::Inet4::ifconfig<0>(
    { 10,0,0,42 },      // IP
    { 255,255,255,0 },  // Netmask
    { 10,0,0,1 },       // Gateway
    { 8,8,8,8 });       // DNS

  auto disk = fs::new_shared_memdisk();
  disk->init_fs(
  [&inet] (auto err, auto& filesys) {
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

    auto* credman = net::Credman::create(
            get_rng(),
            std::move(ca_key),
            ca_cert,
            std::move(srv_key));

    // Set up a TCP server on port 443
    static http::Secure_HTTP httpd(
        *credman, get_rng(), inet.tcp(),

    [] (auto req, auto resp) {
      
      resp->write_header(http::Not_Found);
      resp->write("<html><body>Hello encrypted world!</body><html>\r\n");

    });

    httpd.listen(443);

    kernel_sanity_checks();
  });
}
