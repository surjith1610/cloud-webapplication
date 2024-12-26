from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from app.models import User
from django.urls import reverse
import base64
from unittest.mock import patch

# Create your tests here
class UserViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.valid_data = {
            "email": "testemail@outlook.com",
            "password": "testpassword",
            "first_name": "Allen",
            "last_name": "Anish",
        }
        self.create_user_url = reverse('create_user')
        self.get_update_user_url = reverse('get_update_user')

    # Test for creating a user successfully
    @patch('app.views.user.sns_client.publish')
    def test_create_user_success(self,mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        response = self.client.post(self.create_user_url, self.valid_data, format='json')
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(response.json()['email'], self.valid_data['email'])

    # Test to create a user and get user details
    @patch('app.views.user.sns_client.publish')
    def test_create_and_get_user_success(self, mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        self.client.post(self.create_user_url, self.valid_data, format='json')

        user = User.objects.get(email=self.valid_data['email'])
        user.is_verified = True
        user.save()

        credentials = base64.b64encode(f"{self.valid_data['email']}:{self.valid_data['password']}".encode('utf-8')).decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        response = self.client.get(self.get_update_user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['email'], self.valid_data['email'])

     # Test to update user details
    @patch('app.views.user.sns_client.publish')
    def test_create_and_update_user_success(self, mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        response = self.client.post(self.create_user_url, self.valid_data, format='json')

        user = User.objects.get(email=self.valid_data['email'])
        user.is_verified = True
        user.save()

        credentials = base64.b64encode(f"{self.valid_data['email']}:{self.valid_data['password']}".encode('utf-8')).decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        updated_data = {
            'first_name': 'testfirstname',
            'last_name': 'testlastname'
        }
        response = self.client.put(self.get_update_user_url, updated_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        response = self.client.get(self.get_update_user_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['first_name'], updated_data['first_name'])
        self.assertEqual(response.json()['last_name'], updated_data['last_name'])

    # Test to create user with missing data
    @patch('app.views.user.sns_client.publish')
    def test_create_user_with_missing_data(self,mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        data = self.valid_data.copy()
        del data["last_name"]
        response = self.client.post(self.create_user_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # Test to create user with an existing email
    @patch('app.views.user.sns_client.publish')
    def test_create_user_with_email_already_exists(self,mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        self.client.post(self.create_user_url, self.valid_data, format='json')
        response = self.client.post(self.create_user_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # Test to create user with invalid first name
    def test_create_user_with_invalid_field(self):
        data = self.valid_data.copy()
        data["extra_field"] = "extra_value"
        response = self.client.post(self.create_user_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        

    # Test to get user details with invalid credentials
    def test_get_user_with_invalid_auth(self):
        self.client.post(self.create_user_url, self.valid_data, format='json')

        user = User.objects.get(email=self.valid_data['email'])
        user.is_verified = True
        user.save()

        credentials = base64.b64encode(b'testemail@outlook.com:testpassw').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        response = self.client.get(self.get_update_user_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # Test to get user details without authentication
    def test_get_user_without_auth(self):
        response = self.client.get(self.get_update_user_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # Test to update user with invalid auth
    def test_update_user_with_invalid_auth(self):
        self.client.post(self.create_user_url, self.valid_data, format='json')
        updated_data = {'first_name': 'new_name'}
        credentials = base64.b64encode(b'testemail@outlook.com:invalidpassword').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        response = self.client.put(self.get_update_user_url, updated_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
