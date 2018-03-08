#include <iostream>

#include "aws/core/Aws.h"

//#include "include/Auth.hpp"
//#include "include/DynamoDb.hpp"
//#include "include/S3.hpp"
//
//
//int main()
//{
//	Aws::SDKOptions options;
//	Aws::InitAPI(options);
//
//	try	{
//		// var region='us-west-2';
//		// var identity_pool_id = 'us-west-2:b0a3b7a2-09b0-4948-80a8-cef75c771c3d';
//		// var user_pool_id= 'us-west-2_b7a8Pn960';
//		// var client_app_id='4o3caaqt0dnqfo3m2c5t0i1vck';		//for Cognito App client
//		// var identity_provider='cognito-idp.us-west-2.amazonaws.com/'+user_pool_id; //https://cognito-idp.{region}.amazonaws.com/{userPoolId}
//
//		std::string regionId = "us-west-2";
//
//		awspp::Auth auth( "b7a8Pn960", "4o3caaqt0dnqfo3m2c5t0i1vck", regionId );
//		auto creds = auth.Authenticate( "upwork0", "Denis1234", "b0a3b7a2-09b0-4948-80a8-cef75c771c3d" );
//
//		if (!creds.GetAWSAccessKeyId().empty()) {
//			awspp::DynamoDb db( regionId, creds );
//			std::clog << db.key( "dynamodbtesttable" ) << std::endl;
//
//			db.PutItem( "dynamodbtesttable", "aws-cpp", "test-result", "passed" );
//			db.GetItem( "dynamodbtesttable", "aws-cpp" );
//
//			awspp::S3 s3( regionId, creds );
//			s3.Upload( "s3test.txt", "upworktests3bucket", "serverfilenamedenis" );
//			s3.Download( "upworktests3bucket", "serverfilenamedenis" );
//		}
//	}
//	catch (...) {
//		std::cerr << "error" << std::endl;
//	}
//
//	Aws::ShutdownAPI(options);
//
//	return 0;
//}
