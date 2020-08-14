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

#ifndef __AWS_CPP_COGNITO_AUTH_H
#define __AWS_CPP_COGNITO_AUTH_H


#include <string>

#include "aws/core/auth/AWSCredentialsProvider.h"

#include "Exception.hpp"


namespace awsx {

	class CognitoTokens {
	protected:
		std::string m_accessToken;
		std::string m_idToken;
		std::string m_refreshToken;
		int m_expiresIn;

	public:
		CognitoTokens( const std::string & accessToken,
			const std::string & idToken,
			const std::string & refreshToken,
			int expiresIn )
			: m_accessToken( accessToken )
			, m_idToken( idToken )
			, m_refreshToken( refreshToken )
			, m_expiresIn( expiresIn )
		{
		}

		std::string & GetAccessToken()
		{
			return m_accessToken;
		}
		std::string & GetIdToken()
		{
			return m_idToken;
		}
		std::string & GetRefreshToken()
		{
			return m_refreshToken;
		}
		int GetExpiresIn()
		{
			return m_expiresIn;
		}
	};

	class CognitoAuth {
	protected:
		std::string m_clientId;
		std::string m_regionId;

		template <class TException, typename TResult>
		void ThrowIf( TResult & result )
		{
			if ( !result.IsSuccess() ) {
				throw TException(
					std::string( result.GetError().GetExceptionName().c_str() )
					+ ": " + result.GetError().GetMessage().c_str() );
			}
		}

		CognitoTokens AuthenticateWithUserPoolInternal(
			Aws::Client::ClientConfiguration & clientConfig,
			const std::string & username,
			const std::string & userPoolId,
			const std::string & password );

	public:
		CognitoAuth(
			const std::string & regionId, const std::string & clientId )
			: m_regionId( regionId )
			, m_clientId( clientId )
		{
		}

		Aws::Auth::AWSCredentials Authenticate( const std::string & username,
			const std::string & password,
			const std::string & userPoolId,
			const std::string & identityPoolId );

		CognitoTokens AuthenticateWithUserPool( const std::string & username,
			const std::string & password,
			const std::string & userPoolId );
	};

} // namespace awsx


#endif
