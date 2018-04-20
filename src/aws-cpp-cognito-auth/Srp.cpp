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

#include <iostream>

#include "include/Helpers.hpp"
#include "include/Crypt.hpp"
#include "include/Base64.hpp"

#include "include/Srp.hpp"


using namespace awsx;


static const std::string __awsAuthSrpPrimeN =
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

// SHA256 digest for AWS N prime
static const std::vector<uint8_t> s_nPrimeDigest {
	0x53, 0x82, 0x82, 0xc4, 0x35, 0x47, 0x42, 0xd7,
	0xcb, 0xbd, 0xe2, 0x35, 0x9f, 0xcf, 0x67, 0xf9,
	0xf5, 0xb3, 0xa6, 0xb0, 0x87, 0x91, 0xe5, 0x01,
	0x1b, 0x43, 0xb8, 0xa5, 0xb6, 0x6d, 0x9e, 0xe6
};


void Srp::GenerateSrpA()
{
	m_random.rand( 256, 1, 1 );
	m_N.fromHex( __awsAuthSrpPrimeN );
	m_g.fromHex( "2" );

	m_k.fromBin( s_nPrimeDigest );

	BigNumberContext context;
	BigNumber a;
	BigNumber A;

	a.mod( m_random, m_N, context );
	A.modExp( m_g, a, m_N, context );

	A.toHex( m_A );
}

void Srp::GenerateKey(
	std::vector<uint8_t> & out,
	const std::string & id,
	const std::string & sSaltIn,
	const std::string & sB )
{
	Digest d;

	std::vector<uint8_t> salt;
	std::vector<uint8_t> ab;
	Helpers::HexToBinary( ab, Helpers::PadLeftZero( m_A.get() ) + Helpers::PadLeftZero( sB ) );
	d.Sha256( salt, ab );
	salt = Helpers::PadLeftZero( salt );

	std::vector<uint8_t> idDigest;
	d.Sha256( idDigest, id );

	std::vector<uint8_t> saltIn;
	Helpers::HexToBinary( saltIn, Helpers::PadLeftZero( sSaltIn ) );

	std::vector<uint8_t> x_array( saltIn.size() + idDigest.size() );
	x_array.assign( saltIn.begin(), saltIn.end() );
	x_array.insert( x_array.end(), idDigest.begin(), idDigest.end() );

	std::vector<uint8_t> x_digest;
	d.Sha256( x_digest, x_array );
	x_digest = Helpers::PadLeftZero( x_digest );

	BigNumber x;
	BigNumber u;
	BigNumber B;

	x.fromBin( x_digest );
	u.fromBin( salt );
	B.fromHex( sB );

	BigNumber g_mod_xn;
	BigNumber k_mult;
	BigNumber b_sub;
	BigNumber u_x;
	BigNumber a_add;
	BigNumber b_sub_modpow;
	BigNumber S;
	BigNumber a;

	BigNumberContext context;
	a.mod( m_random, m_N, context );

	g_mod_xn.modExp( m_g, x, m_N, context );
	k_mult.mul( m_k, g_mod_xn, context );
	b_sub.sub( B, k_mult );
	u_x.mul( u, x, context );
	a_add.add( a, u_x );
	b_sub_modpow.modExp( b_sub, a_add, m_N, context );
	S.mod( b_sub_modpow, m_N, context );

	BigNumberString sS;
	S.toHex( sS );
	std::vector<uint8_t> secret;
	Helpers::HexToBinary( secret, sS.get() );
	secret = Helpers::PadLeftZero( secret );

	const std::string labelS = "Caldera Derived Key";
	std::vector<uint8_t> label( labelS.begin(), labelS.end() );

	Key().HkdfSha256( out, salt, secret, label );
}

std::string Srp::GeneratePasswordClaim(
	const std::string & userPoolId,
	const std::string & username,
	const std::string & password,
	const std::string & salt,
	const std::string & sB,
	const std::string & sSecretBlock,
	const std::string & timestamp )
{
	std::vector<uint8_t> secretBlock;
	Base64().Decode( secretBlock, sSecretBlock );

	std::vector<uint8_t> key;
	GenerateKey( key, userPoolId + username + ":" + password, salt, sB );

	std::vector<uint8_t> content( userPoolId.size() + username.size() + secretBlock.size() + timestamp.size() );
	content.assign( userPoolId.begin(), userPoolId.end() );
	content.insert( content.end(), username.begin(), username.end() );
	content.insert( content.end(), secretBlock.begin(), secretBlock.end() );
	content.insert( content.end(), timestamp.begin(), timestamp.end() );

	std::vector<uint8_t> hmac( 32 );
	Hmac::ComputeSha256( hmac, key, content );

	return Base64().Encode( hmac );
}
