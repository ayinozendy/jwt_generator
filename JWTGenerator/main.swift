//
//  main.swift
//  JWTGenerator
//
//  Created by Ino Gamalinda on 11/17/23.
//  Copyright © 2023 Ino Gamalinda. All rights reserved.

import CryptoKit
import Foundation
import CommonCrypto

let jwt = try generateZoomSDKJWTForNative(
  key: "12345abc"
)

print(jwt) //Verify at https://jwt.io/#debugger-io
//If you have a different secret key, provide it to the debugger signature verification

//Learn how it works here: https://jwt.io/introduction
func generateZoomSDKJWTForNative(key appKey: String, secret: String? = nil) throws -> String {
  let expirationInterval: TimeInterval = 3600 * 24 * 365 //One year
  let iat = Int(Date().timeIntervalSince1970) //Now
  let expirationTime = iat + Int(expirationInterval) //Now + One Year
  let tokenExpirationTime = Int(expirationTime) //Same as Expiration Time
  
  let header = [
    "typ" : "JWT",
    "alg" : "HS256"
  ]
  
  //List of claims can be found here: https://developers.zoom.us/docs/meeting-sdk/auth/
  let claims = [
    "appKey": appKey,
    "iat": iat,
    "exp": expirationTime,
    "tokenExp": tokenExpirationTime
  ] as [String : Any]
  
  let secretWord = secret ?? "your-256-bit-secret" //jwt.io default
  let headerData = try JSONSerialization.data(withJSONObject: header)
  let claimsData = try JSONSerialization.data(withJSONObject: claims)
  
  let encodedHeader = Data(headerData)
  let encodedClaims = Data(claimsData)
  let secretWordData = Data(secretWord.utf8)
  
  let dataToSign = encodedHeader.base64EncodedURLString() + "." + encodedClaims.base64EncodedURLString()
  let hmacSHA256 = HMAC<SHA256>.authenticationCode(for: Data(dataToSign.utf8), using: SymmetricKey(data: secretWordData))
  let hashData = Data(hmacSHA256).base64EncodedURLString()
  
  return "\(encodedHeader.base64EncodedURLString()).\(encodedClaims.base64EncodedURLString()).\(hashData)"
}

extension Data {
  func base64EncodedURLString() -> String {
    return base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .trimmingCharacters(in: CharacterSet(charactersIn: "="))
  }
}
