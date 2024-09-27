'''
    -> Message body: 
        # RFC 7519 - Registered Claim Names
        iss (Issuer)
        sub (Subject)
        aud (Audience)
        exp (Expiration Time)
        nbf (Not Before)
        iat (Issued At)
        jti (JWT ID)
        
        # private claims
        cdi (Credentials ID) 
        atkn (Auth Token)
'''

# Implementation needed. Use JWT library to encrypt? Do not send sensitive details. Save in cookie httponly.
import datetime
from typing import Tuple
import jwt
from cryptography.hazmat.primitives import serialization

class JWTHandler:
    @staticmethod
    def validate_jwt_token(jwt_token: str, jwt_pub_key: bytes):
        try:
            data = jwt.decode(jwt_token, jwt_pub_key, algorithms=['RS256'], issuer="schedule-easy/auth-service", audience="schedule-easy/*")
            if data['tkn'] != "auth token":
                print("Invalid token type, expected auth token, received:", data['tkn'])
                return False
        except jwt.ExpiredSignatureError:
            print("Expired Signature")
            return False
        except jwt.InvalidAudienceError:
            print("Invalid Audience")
            return False
        except jwt.InvalidIssuerError:
            print("Invalid Issuer")
            return False
        except jwt.InvalidIssuedAtError:
            print("Invalid Issued At")
            return False
        return True

    @staticmethod
    def validate_refresh_token(refresh_token: str, refresh_pub_key: bytes):
        try:
            data = jwt.decode(refresh_token, refresh_pub_key, algorithms=['RS256'], issuer="schedule-easy/auth-service", audience="schedule-easy/*")
            if data['tkn'] != "refresh token":
                print("Invalid token, expected refresh token, received:", data['tkn'])
                return False
        except jwt.ExpiredSignatureError:
            print("Error with Refresh token")
            return False
        except jwt.InvalidIssuerError:
            print("Invalid Issuer")
            return False
        except jwt.InvalidIssuedAtError:
            print("Invalid Issued At")
            return False
        except jwt.InvalidAudienceError:
            print("Invalid Audience")
            return False
        return True