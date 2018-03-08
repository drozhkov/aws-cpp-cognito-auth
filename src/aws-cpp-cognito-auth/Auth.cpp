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

#include <vector>
#include <ctime>
#include <iomanip>

#include "aws/core/utils/Outcome.h"

#include "aws/cognito-idp/CognitoIdentityProviderClient.h"
#include "aws/cognito-idp/model/InitiateAuthRequest.h"
#include "aws/cognito-idp/model/InitiateAuthResult.h"
#include "aws/cognito-idp/model/RespondToAuthChallengeRequest.h"

#include "aws/cognito-identity/CognitoIdentityClient.h"
#include "aws/cognito-identity/model/GetIdRequest.h"
#include "aws/cognito-identity/model/GetIdResult.h"
#include "aws/cognito-identity/model/GetCredentialsForIdentityResult.h"
#include "aws/cognito-identity/model/GetCredentialsForIdentityRequest.h"

#include "include/Helpers.hpp"
#include "include/Srp.hpp"

#include "../../include/aws-cpp-cognito-auth/Auth.hpp"


using namespace awsx;


Aws::Auth::AWSCredentials CognitoAuth::Authenticate(
	const std::string & username,
	const std::string & password,
	const std::string & userPoolId,
	const std::string & identityPoolId )
{
	Aws::Auth::AWSCredentials result;

	Aws::Client::ClientConfiguration clientConfig;
	clientConfig.region = Aws::String( m_regionId.c_str() );

	Srp srp;

	Aws::Map<Aws::String, Aws::String> authParameters;
	authParameters["USERNAME"] = username.c_str();
	authParameters["SRP_A"] = srp.A();

	Aws::CognitoIdentityProvider::CognitoIdentityProviderClient cipClient( clientConfig );

	Aws::CognitoIdentityProvider::Model::InitiateAuthRequest authRequest;
	authRequest.SetClientId( m_clientId.c_str() );
	authRequest.SetAuthFlow( Aws::CognitoIdentityProvider::Model::AuthFlowType::USER_SRP_AUTH );
	authRequest.SetAuthParameters( authParameters );

	auto authResult = cipClient.InitiateAuth( authRequest );
	ThrowIf<Exception>( authResult );

	auto challengeParameters = authResult.GetResult().GetChallengeParameters();

	auto now = time( nullptr );
	struct tm tm;

#ifdef __GNUC__
	gmtime_r( &now, &tm );
#else
	gmtime_s( &tm, &now );
#endif

	std::stringstream ss;
	ss << std::put_time( &tm, (std::string( "%a %b" ) + (tm.tm_mday > 9 ? " " : "") + "%e %H:%M:%S UTC %Y").c_str() );

	std::string timestamp( ss.str() );

	const Aws::String salt = challengeParameters["SALT"];
	const Aws::String srpB = challengeParameters["SRP_B"];
	const Aws::String secretBlock = challengeParameters["SECRET_BLOCK"];

	auto claim = srp.GeneratePasswordClaim(
		userPoolId,
		username,
		password,
		salt.c_str(),
		srpB.c_str(),
		secretBlock.c_str(),
		timestamp );

	Aws::CognitoIdentityProvider::Model::RespondToAuthChallengeRequest challengeRequest;
	challengeRequest.SetClientId( m_clientId.c_str() );
	challengeRequest.SetChallengeName( authResult.GetResult().GetChallengeName() );
	challengeRequest.AddChallengeResponses( "PASSWORD_CLAIM_SECRET_BLOCK", secretBlock );
	challengeRequest.AddChallengeResponses( "PASSWORD_CLAIM_SIGNATURE", claim.c_str() );
	challengeRequest.AddChallengeResponses( "USERNAME", username.c_str() );
	challengeRequest.AddChallengeResponses( "TIMESTAMP", timestamp.c_str() );

	auto challengeResult = cipClient.RespondToAuthChallenge( challengeRequest );
	ThrowIf<Exception>( challengeResult );

	auto token = challengeResult.GetResult().GetAuthenticationResult().GetIdToken().c_str();

	std::string login = ("cognito-idp." + m_regionId + ".amazonaws.com/" + m_regionId + "_" + userPoolId);

	Aws::CognitoIdentity::CognitoIdentityClient ciClient( clientConfig );

	Aws::CognitoIdentity::Model::GetIdRequest idRequest;
	idRequest.SetIdentityPoolId( identityPoolId.c_str() );
	idRequest.AddLogins( login.c_str(), token );
	idRequest.SetIdentityPoolId( (m_regionId + ":" + identityPoolId).c_str() );

	auto idResult = ciClient.GetId( idRequest );
	ThrowIf<Exception>( idResult );

	Aws::CognitoIdentity::Model::GetCredentialsForIdentityRequest credForIdRequest;
	credForIdRequest.SetIdentityId( idResult.GetResult().GetIdentityId() );
	credForIdRequest.AddLogins( login.c_str(), token );

	auto credForIdResult = ciClient.GetCredentialsForIdentity( credForIdRequest );
	ThrowIf<Exception>( credForIdResult );

	auto & cred = credForIdResult.GetResult().GetCredentials();
	result = Aws::Auth::AWSCredentials( cred.GetAccessKeyId(), cred.GetSecretKey(), cred.GetSessionToken() );

	return result;
}
