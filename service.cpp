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

#include <https>
#include "tls_client.hpp"
#include "client_credman.hpp"

extern "C" void kernel_sanity_checks();

void Service::start()
{
  auto& inet = net::Inet4::ifconfig<0>(
    { 10,0,0,42 },      // IP
    { 255,255,255,0 },  // Netmask
    { 10,0,0,1 },       // Gateway
    { 8,8,8,8 });       // DNS

  fs::memdisk().init_fs(
  [&inet] (auto err, auto& filesys) {
    assert(!err);

    // load CA certificate
    auto ca_cert = filesys.stat("/test.der");
    // load CA private key
    auto ca_key  = filesys.stat("/test.key");
    // load server private key
    auto srv_key = filesys.stat("/server.key");

    // Set up a TCP server on port 443
    static http::Secure_server httpd(
        inet.tcp().address().to_string(), // server name
        ca_key, ca_cert, srv_key, inet.tcp(),

    [] (auto req, auto resp) {
      
      (void) req;
      resp->write_header(http::Not_Found);
      resp->write("<html><body>Hello encrypted world!</body><html>\r\n");

    });
    httpd.listen(443);
    return;

    static auto* credman = net::Client_creds::create(filesys, "/certs");

    auto conn = inet.tcp().connect({{10,0,0,1}, 8001});
    conn->on_connect(
    [] (auto conn) {
      printf("Connected!\n");

      new net::tls::Client(conn, Botan::system_rng(), *credman);
      
    });

    kernel_sanity_checks();
  });

}
