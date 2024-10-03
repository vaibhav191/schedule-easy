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
from logging import Logger
from typing import Tuple
import jwt
from cryptography.hazmat.primitives import serialization

class JWTHandler:
    @staticmethod
    def validate_jwt_token(jwt_token: str, jwt_pub_key: bytes, logger: Logger):
        try:
            data = jwt.decode(jwt_token, jwt_pub_key, algorithms=['RS256'], issuer="schedule-easy/auth-service", audience="schedule-easy/*")
            logger.debug(f"{__class__.__name__}: Data: {data if data else 'No data found'}")
            if data['tkn'] != "auth token":
                logger.debug(f"{__class__.__name__}: Invalid token type, expected auth token, received: {data['tkn']}")
                return False
        except jwt.ExpiredSignatureError:
            logger.debug(f"{__class__.__name__}: Session Expired")
            return False
        except jwt.InvalidAudienceError:
            logger.debug(f"{__class__.__name__}: Invalid Audience")
            return False
        except jwt.InvalidIssuerError:
            logger.debug(f"{__class__.__name__}: Invalid Issuer")
            return False
        except jwt.InvalidIssuedAtError:
            logger.debug(f"{__class__.__name__}: Invalid Issued At")
            return False
        return True

    @staticmethod
    def validate_refresh_token(refresh_token: str, refresh_pub_key: bytes, logger: Logger):
        try:
            data = jwt.decode(refresh_token, refresh_pub_key, algorithms=['RS256'], issuer="schedule-easy/auth-service", audience="schedule-easy/*")
            logger.debug(f"{__class__.__name__}: Data: {data if data else 'No data found'}")
            if data['tkn'] != "refresh token":
                logger.debug(f"{__class__.__name__}: Invalid token type, expected refresh token, received: {data['tkn']}")
                return False
        except jwt.ExpiredSignatureError:
            logger.debug(f"{__class__.__name__}: Session Expired")
            return False
        except jwt.InvalidIssuerError:
            logger.debug(f"{__class__.__name__}: Invalid Issuer")
            return False
        except jwt.InvalidIssuedAtError:
            logger.debug(f"{__class__.__name__}: Invalid Issued At")
            return False
        except jwt.InvalidAudienceError:
            logger.debug(f"{__class__.__name__}: Invalid Audience")
            return False
        return True