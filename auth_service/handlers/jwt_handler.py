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
import uuid
import jwt
from cryptography.hazmat.primitives import serialization

class JWTHandler:
    # authorization server ,ust verify that the user who is requesting for
    # refresh token is the same user who was issued the JWT token.
    # issue a new refresh token whenever refresh is called. (refresh token rotation)
    # If a refresh token is
    #    compromised and subsequently used by both the attacker and the
    #    legitimate client, one of them will present an invalidated refresh
    #    token, which will inform the authorization server of the breach.
    #   The authorization server can then revoke the refresh token.
    # access token should be short lived, refresh token should be long lived.
    # access token should only be requested with the minimum scope required.
    @staticmethod
    def create_tokens(user: str, jwt_id: str, jwt_pvt_key: bytes, jwt_key_password: bytes, refresh_id: str, refresh_key: bytes, refresh_key_password: bytes)-> Tuple[str, str]:
        jwt_payload = {
            "iss": "schedule-easy/auth-service",
            "sub": user,
            "aud": "schedule-easy/*",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
            "nbf": datetime.datetime.now(datetime.timezone.utc),
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "jti": jwt_id,
            "tkn": "auth token"
        }

        refresh_payload = {
            "iss": "schedule-easy/auth-service",
            "sub": user,
            "aud": "schedule-easy/*",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30),
            "nbf": datetime.datetime.now(datetime.timezone.utc),
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "jti": refresh_id,
            "tkn": "refresh token"
        }
        
        jwt_pvt_key_serialized = serialization.load_pem_private_key(jwt_pvt_key, password=jwt_key_password)
        jwt_token = jwt.encode(jwt_payload, jwt_pvt_key_serialized, algorithm='RS256')
        
        refresh_pvt_key_serialized = serialization.load_pem_private_key(refresh_key, password=refresh_key_password)
        refresh_token = jwt.encode(refresh_payload, refresh_pvt_key_serialized, algorithm='RS256')

        return jwt_token, refresh_token 

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