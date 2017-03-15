// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2017 Oslo and Akershus University College of Applied Sciences
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
#ifndef NET_TLS_CLIENT_CREDS_HPP
#define NET_TLS_CLIENT_CREDS_HPP

#include <fs/filesystem.hpp>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <botan/x509cert.h>
#include <memory>

namespace net
{
typedef std::chrono::duration<int, std::ratio<31556926>> years;

class Client_creds : public Botan::Credentials_Manager
{
public:
  Client_creds()
    : m_store(new Botan::Certificate_Store_In_Memory())
  {
    m_provides_client_certs = false;
  }

  std::vector<Botan::Certificate_Store*>
  trusted_certificate_authorities(const std::string&,
          const std::string&) override
  {
    std::vector<Botan::Certificate_Store*> v { m_store.get() };
    return v;
  }

  std::vector<Botan::X509_Certificate> cert_chain(
              const std::vector<std::string>&,
              const std::string& type,
              const std::string&) override
  {
    std::vector<Botan::X509_Certificate> chain;
    return chain;
  }

  void add(std::shared_ptr<const Botan::X509_Certificate> cert)
  {
    m_store->add_certificate(cert);
  }

  static Client_creds* create(fs::File_system& fs, const std::string& path);

public:
  std::unique_ptr<Botan::Certificate_Store_In_Memory> m_store;
  bool m_provides_client_certs;
};

inline Client_creds* Client_creds::create(fs::File_system& fs, const std::string& path)
{
  auto* creds = new Client_creds();
  int added = 0, total = 0;
  for (auto& ent : fs.ls(path))
  if (ent.is_file())
  {
    auto buffer = ent.read(0, ent.size());
    std::vector<uint8_t> cert(buffer.data(), buffer.data() + buffer.size());
    try {
      total++;
      creds->add(std::make_shared<const Botan::X509_Certificate> (cert));
      added ++;
    }
    catch (std::exception e) {
      printf("Item size: %llu\n", ent.size());
      printf("Failed decoding: %s\n", e.what());
    }
  }
  printf("Added %d / %d certificates\n", added, total);
  return creds;
}

} // net

#endif
