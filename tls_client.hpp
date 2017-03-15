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
#ifndef NET_TLS_CLIENT_HPP
#define NET_TLS_CLIENT_HPP

#include <net/tcp/connection.hpp>
#include <botan/credentials_manager.h>
#include <botan/ocsp.h>
#include <botan/rng.h>
#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/x509path.h>

using Connection_ptr = net::tcp::Connection_ptr;

namespace net
{
namespace tls
{
class Client : public Botan::TLS::Callbacks, public tcp::Stream
{
public:
  Client(tcp::Connection_ptr conn,
         Botan::RandomNumberGenerator& rng,
         Botan::Credentials_Manager& credman) 
    : tcp::Stream({conn}),
      m_creds(credman),
      m_session_manager(rng),
      m_tls(*this, m_session_manager, m_creds, m_policy, rng)
    {
      assert(tcp->is_connected());
      // default read callback
      tcp->on_read(4096, {this, &Client::tls_read});
    }

protected:
  bool tls_session_established(const Botan::TLS::Session&) override
  {
    // return true to store session
    return true;
  }

  void tls_read(buffer_t buf, const size_t n)
  {
    try
    {
      int rem = m_tls.received_data(buf.get(), n);
      (void) rem;
      //printf("Finished processing (rem: %u)\n", rem);
    }
    catch(Botan::Exception& e)
    {
      printf("Fatal TLS error %s\n", e.what());
      this->close();
    }
    catch(...)
    {
      printf("Unknown error!\n");
      this->close();
    }
  }

  void tls_emit_data(const uint8_t buf[], size_t length) override
  {
    tcp->write(buf, length);
  }

  void tls_alert(Botan::TLS::Alert alert) override
  {
    printf("Alert: %s\n", alert.type_string().c_str());
  }

  void tls_record_received(uint64_t /*seq_no*/, const uint8_t buf[], size_t buf_size) override
  {
     printf("CLIENT read len=%u:\n%.*s\n",
           buf_size, buf_size, buf);
  }

  void tls_session_activated() override
  {
    if (o_connect) o_connect(*this);
  }

  void tls_verify_cert_chain(
     const std::vector<Botan::X509_Certificate>& cert_chain,
     const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
     const std::vector<Botan::Certificate_Store*>& trusted_roots,
     Botan::Usage_Type usage,
     const std::string& hostname,
     const Botan::TLS::Policy& policy) override
   {
     printf("Verifying certificate chain...\n");
     if(cert_chain.empty())
        throw std::invalid_argument("Certificate chain was empty");

     Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                      policy.minimum_signature_strength());

     auto ocsp_timeout = std::chrono::milliseconds(1000);

     Botan::Path_Validation_Result result =
        Botan::x509_path_validate(cert_chain,
                                  restrictions,
                                  trusted_roots,
                                  hostname,
                                  usage,
                                  std::chrono::system_clock::now(),
                                  ocsp_timeout,
                                  ocsp);

      std::cout << "Certificate validation status: " << result.result_string() << "\n";
      if(result.successful_validation())
      {
        auto status = result.all_statuses();

        if(status.size() > 0 && status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD))
           std::cout << "Valid OCSP response for this server\n";
      }
   }

private:
  Stream::ReadCallback    o_read;
  Stream::WriteCallback   o_write;
  Stream::ConnectCallback o_connect;

  Botan::Credentials_Manager&  m_creds;
  Botan::TLS::Strict_Policy    m_policy;
  Botan::TLS::Session_Manager_In_Memory m_session_manager;
  std::shared_ptr<Botan::Certificate_Store> m_certstore;

  Botan::TLS::Client           m_tls;
};

} // tls
} // net

#endif
