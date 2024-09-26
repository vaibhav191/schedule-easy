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
    def create_jwt_token():
        pass
    @staticmethod
    def create_refresh_token():
        pass
    def validate_jwt_token():
        pass
    def validate_refresh_token():
        pass
