// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2016-2017 Oslo and Akershus University College of Applied Sciences
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

#pragma once

#include <net/http/server.hpp>
#include "credman.hpp"
#include "tls_server.hpp"

namespace http {

class Secure_HTTP : public http::Server
{
public:
  Secure_HTTP(
      Botan::Credentials_Manager&   in_credman,
      Botan::RandomNumberGenerator& in_rng,
      TCP& tcp,
      Request_handler cb)
    : http::Server(tcp, cb), rng(in_rng), credman(in_credman)
  {
    on_connect = {this, &Secure_HTTP::secure_connect};
  }
  
  void secure_connect(TCP_conn conn)
  {
    auto* ptr = new net::TLS_server(conn, rng, credman);

    ptr->on_connect(
    [this, ptr] (net::Stream&)
    {
      // create and pass TLS socket
      Server::connect(std::unique_ptr<net::TLS_server>(ptr));
    });
    ptr->on_close([ptr] {
      printf("Secure_HTTP::on_close on %s\n", ptr->to_string().c_str());
      delete ptr;
    });
  }

private:
  Botan::RandomNumberGenerator& rng;
  Botan::Credentials_Manager&   credman;
};

} // http
