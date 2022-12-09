from django.shortcuts import render
from rest_framework.views import APIView, Response
from rest_framework import exceptions
from rest_framework.permissions import IsAuthenticated
from .authentication import JWTAuthentication
import datetime

from core.models import User, UserToken

from .serializers import UserSerializer


class RegisterApiView(APIView):
    def post(self, request):
        data = request.data
        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Senha nao iguais')

        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginApiView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        scope = request.data['scope']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise exceptions.AuthenticationFailed('Usuario nao encontrado')

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Senha incorreta')

        if not user.is_financeiro and scope == 'financeiro':
            raise exceptions.AuthenticationFailed('Sem autorizacao')

        token = JWTAuthentication.generate_jwt(user.id, scope)

        UserToken.objects.create(
            user_id=user.id,
            token=token,
            created_at=datetime.datetime.utcnow(),
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=1)
        )

        return Response({
            'jwt': token
        })


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, scope = ''):
        token = request.COOKIES.get('jwt')

        if not token:
            raise exceptions.AuthenticationFailed('Nao autenticado')

        payload = JWTAuthentication.get_payload(token)

        user = User.objects.get(pk=payload['user_id'])

        if user is None:
            raise exceptions.AuthenticationFailed('usuario nao encontrado')
        
        if not UserToken.objects.filter(user_id=user.id, 
                                        token=token, 
                                        expired_at__gt=datetime.datetime.utcnow()
                                        ).exists():
            raise exceptions.AuthenticationFailed('Nao autenticado')
        
        if not user.is_financeiro and payload['scope'] == 'financeiro' or payload['scope'] != scope:
            raise exceptions.AuthenticationFailed('Escopo invalido')

        return Response(UserSerializer(user).data)


class LogoutAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise exceptions.AuthenticationFailed('Nao autenticado')
        payload = JWTAuthentication.get_payload(token)
        UserToken.objects.filter(user_id=payload['user_id']).delete()
        
        response = Response()
        response.delete_cookie(key='jwt')
        response.data = {
            'message': 'Success'
        }
        return response


class ProfileInfoAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ProfilePasswordAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk=None):
        user = request.user
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Senha nao iguais')

        user.set_password(data['password'])
        user.save()
        return Response(UserSerializer(user).data)


class UsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, _, pk=None):
        if pk is None:
            return Response(UserSerializer(User.objects.all(), many=True).data)
        
        return Response(UserSerializer(User.objects.get(pk=pk)).data)
