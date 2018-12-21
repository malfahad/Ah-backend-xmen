import jwt
from authors.settings import SECRET_KEY
from django.conf import settings
from rest_framework import authentication, exceptions
from .models import User

"""Configure JWT Here"""

class JWTAuthentication:
    def authenticate_header(self,request):
        return authentication.get_authorization_header(request)

    def authenticate(self,request):
        auth_header =   self.authenticate_header(request)
        auth_header_parts = auth_header.split()
        print(auth_header_parts)
        if not auth_header_parts:
            return None

        if auth_header_parts[0].lower() != b'bearer' :
            return None

        if len(auth_header_parts) != 2 :
           message = "Invalid Authorization header."
           raise exceptions.AuthenticationFailed(message) 
        token = auth_header_parts[1]

        return self.authenticate_user(token,User)

    def authenticate_user(self,token,model):
        try:
            payload = jwt.decode(token,
                                SECRET_KEY,
                                verify=True, 
                                algorithms=['HS256'])
                                
        except jwt.ExpiredSignature as e:
           raise exceptions.AuthenticationFailed(e)
        
        except jwt.DecodeError as e:
           raise exceptions.AuthenticationFailed(e)
        
        except jwt.InvalidTokenError as e:
           raise exceptions.AuthenticationFailed(e)
        
        try:
            username = payload['username']
            email = payload['email']
            
            user = model.objects.get(
                                    email=email,
                                    username=username
                                    )

            return (user, token)

        except model.DoesNotExist:
           message = "Authorized user does not exist"
           raise exceptions.AuthenticationFailed(message) 

      