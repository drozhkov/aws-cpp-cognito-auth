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

#ifndef __AWS_CPP_COGNITO_AUTH_BIGNUMBER_H
#define __AWS_CPP_COGNITO_AUTH_BIGNUMBER_H


#include <string>
#include <vector>

#include "openssl/bn.h"


namespace awsx {

	class BigNumberContext {
	protected:
		BN_CTX * m_context;

	public:
		BigNumberContext()
			: m_context( BN_CTX_new() )
		{
		}

		virtual ~BigNumberContext()
		{
			BN_CTX_free( m_context );
		}

		BN_CTX * get() const
		{
			return m_context;
		}
	};

	class BigNumberString {
	protected:
		char * m_ptr;

	protected:
		void free()
		{
			if (m_ptr != nullptr) {
				OPENSSL_free( m_ptr );
				m_ptr = nullptr;
			}
		}

	public:
		BigNumberString()
			: m_ptr( nullptr )
		{
		}

		virtual ~BigNumberString()
		{
			free();
		}

		char * get() const
		{
			return m_ptr;
		}

		void set( char * v )
		{
			free();
			m_ptr = v;
		}
	};

	class BigNumber {
	protected:
		BIGNUM * m_value;

	public:
		BigNumber()
			: m_value( BN_new() )
		{
		}

		virtual ~BigNumber()
		{
			BN_free( m_value );
		}

		void rand( int bits, int top, int bottom )
		{
			BN_rand( m_value, bits, top, bottom );
		}

		void mod( const BigNumber & m, const BigNumber & d, BigNumberContext & context )
		{
			BN_mod( m_value, m.get(), d.get(), context.get() );
		}

		void modExp( const BigNumber & a, const BigNumber & p, const BigNumber & m, BigNumberContext & context )
		{
			BN_mod_exp( m_value, a.get(), p.get(), m.get(), context.get() );
		}

		void mul( const BigNumber & a, const BigNumber & b, BigNumberContext & context )
		{
			BN_mul( m_value, a.get(), b.get(), context.get() );
		}

		void sub( const BigNumber & a, const BigNumber & b )
		{
			BN_sub( m_value, a.get(), b.get() );
		}

		void add( const BigNumber & a, const BigNumber & b )
		{
			BN_add( m_value, a.get(), b.get() );
		}

		void fromHex( const std::string & hex )
		{
			BN_hex2bn( &m_value, hex.c_str() );
		}

		void toHex( BigNumberString & s )
		{
			s.set( BN_bn2hex( m_value ) );
		}

		void fromBin( const std::vector<uint8_t> & bin )
		{
			BN_bin2bn( bin.data(), static_cast<int>(bin.size()), m_value );
		}

		BIGNUM * get() const
		{
			return m_value;
		}
	};

}


#endif
