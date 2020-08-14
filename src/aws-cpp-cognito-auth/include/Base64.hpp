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
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __AWS_CPP_COGNITO_AUTH_BASE64_H
#define __AWS_CPP_COGNITO_AUTH_BASE64_H


#include <vector>

#include "openssl/bio.h"
#include "openssl/evp.h"


namespace awsx {

	class BasicIo {
	protected:
		BIO * m_bio;

	public:
		BasicIo( BIO * p )
			: m_bio( p )
		{
		}

		BasicIo( const BasicIo & ) = delete;

		virtual ~BasicIo()
		{
		}

		void setFlags( int flags )
		{
			BIO_set_flags( m_bio, flags );
		}

		void push( BasicIo & b )
		{
			BIO_push( m_bio, b.get() );
		}

		void write( const std::vector<uint8_t> data )
		{
			BIO_write( m_bio, data.data(), static_cast<int>( data.size() ) );
		}

		void flush()
		{
			BIO_flush( m_bio );
		}

		std::string data()
		{
			uint8_t * data;
			auto len = BIO_get_mem_data( m_bio, &data );

			return std::string( data, data + len - 1 );
		}

		void read( std::vector<uint8_t> & out )
		{
			auto len
				= BIO_read( m_bio, out.data(), static_cast<int>( out.size() ) );

			out.resize( len );
		}

		BIO * get() const
		{
			return m_bio;
		}
	};

	class Base64 : public BasicIo {
	public:
		Base64()
			: BasicIo( BIO_new( BIO_f_base64() ) )
		{
		}

		Base64( const Base64 & ) = delete;

		~Base64() override
		{
			BIO_free_all( m_bio );
		}

		std::string Encode( const std::vector<uint8_t> & binary )
		{
			setFlags( BIO_FLAGS_BASE64_NO_NL );

			BasicIo sink( BIO_new( BIO_s_mem() ) );
			push( sink );

			write( binary );
			flush();

			return sink.data();
		}

		void Decode( std::vector<uint8_t> & out, const std::string & encoded )
		{
			setFlags( BIO_FLAGS_BASE64_NO_NL );

			BasicIo source( BIO_new_mem_buf(
				encoded.c_str(), static_cast<int>( encoded.length() + 1 ) ) );

			push( source );

			const size_t maxlen = encoded.length() / 4 * 3 + 1;
			out.resize( maxlen );
			read( out );
		}
	};

} // namespace awsx


#endif
