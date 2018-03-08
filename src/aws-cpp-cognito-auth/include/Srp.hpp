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

#ifndef __AWS_CPP_COGNITO_AUTH_SRP_H
#define __AWS_CPP_COGNITO_AUTH_SRP_H


#include "BigNumber.hpp"


namespace awsx {

	class Srp {
	protected:
		BigNumber m_k;
		BigNumber m_random;
		BigNumber m_N;
		BigNumber m_g;

		BigNumberString m_A;

	protected:
		void GenerateSrpA();
		void GenerateKey(
			std::vector<uint8_t> & out,
			const std::string & id,
			const std::string & salt,
			const std::string & sB );

	public:
		Srp()
		{
			GenerateSrpA();
		}

		std::string GeneratePasswordClaim(
			const std::string & userPoolId,
			const std::string & username,
			const std::string & password,
			const std::string & salt,
			const std::string & sB,
			const std::string & secretBlock,
			const std::string & timestamp );

		const char * A() const
		{
			return m_A.get();
		}
	};

}


#endif
