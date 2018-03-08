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

#ifndef __AWS_CPP_COGNITO_AUTH_HELPERS_H
#define __AWS_CPP_COGNITO_AUTH_HELPERS_H


#include <string>
#include <vector>
#include <sstream>


namespace awsx {

	class Helpers {
	public:
		static void BinaryToHex( std::stringstream & stream, uint8_t b )
		{
			static const char * s_digits = "0123456789abcdef";

			stream << s_digits[b >> 4] << s_digits[b & 0x0f];
		}

		static std::string BinaryToHex( uint8_t b )
		{
			std::stringstream stream;
			BinaryToHex( stream, b );

			return stream.str();
		}

		static std::string BinaryToHex( const std::vector<uint8_t> & data )
		{
			std::stringstream stream;

			for (size_t i = 0; i < data.size(); i++) {
				auto b = data[i];
				BinaryToHex( stream, b );
			}

			return stream.str();
		}

		static void HexToBinary( std::vector<uint8_t> & out, const std::string & hex )
		{
			auto getNibble = []( char ch ) {
				uint8_t result = 0;

				if (ch >= 'a') {
					result = ch - 'a' + 10;
				}
				else if (ch >= 'A') {
					result = ch - 'A' + 10;
				}
				else {
					result = ch - '0';
				}

				return result;
			};

			for (size_t i = 0; i < hex.length(); i += 2) {
				uint8_t b = (getNibble( hex[i] ) << 4) | getNibble( hex[i + 1] );
				out.push_back( b );
			}
		}

		static std::string PadLeftZero( const std::string & hex )
		{
			std::string result;

			if ((hex.size() & 1) == 1) {
				result = "0" + hex;
			}
			else if (hex[0] > '7') {
				result = "00" + hex;
			}
			else {
				result = hex;
			}

			return result;
		}

		static std::vector<uint8_t> PadLeftZero( const std::vector<uint8_t> & v )
		{
			if (v.front() > 0x69) {
				std::vector<uint8_t> result( v );
				result.insert( result.begin(), 0 );

				return result;
			}

			return v;
		}
	};

}


#endif
