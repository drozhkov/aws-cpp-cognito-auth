/*
* MIT License
*
* Copyright (c) 2018 Denis Rozhkov <denis@rozhkoff.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef __AWS_CPP_COGNITO_AUTH_CRYPT_H
#define __AWS_CPP_COGNITO_AUTH_CRYPT_H


#include <vector>

#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "openssl/hmac.h"


namespace awsx {

	class Digest {
	protected:
		EVP_MD_CTX * m_context;

	protected:
		void Sha256( std::vector<uint8_t> & out, void * d, size_t cnt )
		{
			EVP_DigestInit_ex( m_context, EVP_sha256(), nullptr );
			EVP_DigestUpdate( m_context, d, cnt );

			out.resize( EVP_MD_size( EVP_sha256() ) );
			EVP_DigestFinal_ex( m_context, out.data(), NULL );
		}

		void free()
		{
			if (m_context != NULL) {
				EVP_MD_CTX_destroy( m_context );
				m_context = NULL;
			}
		}

	public:
		Digest()
		{
			m_context = EVP_MD_CTX_create();
		}

		Digest( const Digest & ) = delete;

		virtual ~Digest()
		{
			free();
		}

		void Sha256( std::vector<uint8_t> & out, const std::vector<uint8_t> & message )
		{
			Sha256( out, static_cast<void *>(const_cast<uint8_t *>(message.data())), message.size() );
		}

		void Sha256( std::vector<uint8_t> & out, const std::string & message )
		{
			Sha256( out, static_cast<void *>(const_cast<char *>(message.c_str())), message.size() );
		}
	};

	class Key {
	protected:
		EVP_PKEY_CTX * m_context;

	public:
		Key()
		{
			m_context = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, NULL );
		}

		Key( const Key & ) = delete;

		virtual ~Key()
		{
			if (m_context != NULL) {
				EVP_PKEY_CTX_free( m_context );
			}
		}

		void HkdfSha256(
			std::vector<uint8_t> & out,
			const std::vector<uint8_t> & salt,
			const std::vector<uint8_t> & secret,
			const std::vector<uint8_t> & label )
		{
			EVP_PKEY_derive_init( m_context );
			EVP_PKEY_CTX_set_hkdf_md( m_context, EVP_sha256() );
			EVP_PKEY_CTX_set1_hkdf_salt( m_context, salt.data(), static_cast<int>(salt.size()) );
			EVP_PKEY_CTX_set1_hkdf_key( m_context, secret.data(), static_cast<int>(secret.size()) );
			EVP_PKEY_CTX_add1_hkdf_info( m_context, label.data(), static_cast<int>(label.size()) );

			size_t keyLen = 16;
			EVP_PKEY_derive( m_context, NULL, &keyLen );

			out.resize( keyLen );
			EVP_PKEY_derive( m_context, out.data(), &keyLen );
		}
	};

	class Hmac {
	public:
		static void ComputeSha256( std::vector<uint8_t> & out, std::vector<uint8_t> & key, std::vector<uint8_t> & d )
		{
			HMAC( EVP_sha256(), key.data(), static_cast<int>(key.size()), d.data(), static_cast<int>(d.size()), out.data(), NULL );
		}
	};

}


#endif
