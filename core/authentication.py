from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
import datetime, jwt
from core.models import User, UserToken
from app import settings

class JWTAuthentication(BaseAuthentication):
    
    def authenticate(self, request):
        is_financeiro = 'api/financeiro' in request.path

        token = request.COOKIES.get('jwt')

        if not token:
            return None
        
        payload = JWTAuthentication.get_payload(token)
        
        # if (is_financeiro and payload['scope'] != 'financeiro') or ((not is_financeiro) and payload['scope'] != 'admin'):
        if not is_financeiro and payload['scope'] == 'financeiro':
            raise exceptions.AuthenticationFailed('Escopo invalido')

        user = User.objects.get(pk=payload['user_id'])

        if user is None:
            raise exceptions.AuthenticationFailed('usuario nao encontrado')
        
        if not UserToken.objects.filter(user_id=user.id, 
                                        token=token, 
                                        expired_at__gt=datetime.datetime.utcnow()
                                        ).exists():
            raise exceptions.AuthenticationFailed('Nao autenticado')

        return (user, None)


    @staticmethod
    def get_payload(token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('nao autenticado')

        return payload

    @staticmethod
    def generate_jwt(id, scope):
        payload = {
            'user_id': id,
            'scope': scope,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow()
        }

        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    