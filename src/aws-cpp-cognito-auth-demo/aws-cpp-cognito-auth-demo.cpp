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

#include "stdafx.h"

void authDemo( const std::string & regionId,
	const std::string & clientId,
	const std::string & username,
	const std::string & password,
	const std::string & userPoolId,
	const std::string & identityPoolId )
{
	awsx::CognitoAuth auth( regionId, clientId );
	auto creds
		= auth.Authenticate( username, password, userPoolId, identityPoolId );

	if ( !creds.GetAWSAccessKeyId().empty() ) {
		std::cout << "access key = " << creds.GetAWSAccessKeyId() << std::endl;
	}
}

void authDemoWithUserPool( const std::string & regionId,
	const std::string & clientId,
	const std::string & username,
	const std::string & password,
	const std::string & userPoolId )
{
	awsx::CognitoAuth auth( regionId, clientId );
	auto creds
		= auth.AuthenticateWithUserPool( username, password, userPoolId );

	if ( !creds.GetAccessToken().empty() ) {
		std::cout << "access token = " << creds.GetAccessToken() << std::endl;
		std::cout << "id token = " << creds.GetIdToken() << std::endl;
		std::cout << "refresh token = " << creds.GetRefreshToken() << std::endl;
		std::cout << "expires in = " << creds.GetExpiresIn() << std::endl;
	}
}

int main()
{
	Aws::SDKOptions options;
	Aws::InitAPI( options );

	try {
		std::string regionId = "us-west-2";
		std::string clientId = "";
		std::string username = "";
		std::string password = "";
		std::string userPoolId = "";	 // without region
		std::string identityPoolId = ""; // without region

		authDemo( regionId,
			clientId,
			username,
			password,
			userPoolId,
			identityPoolId );
		// Alternate usage
		// authDemoWithUserPool( regionId, clientId, username, password,
		// userPoolId );
	}
	catch ( const std::exception & x ) {
		std::cerr << x.what() << std::endl;
	}
	catch ( ... ) {
		std::cerr << "error" << std::endl;
	}

	Aws::ShutdownAPI( options );

	return 0;
}
