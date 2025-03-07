# dashboard/superset_service.py

import requests
import json
from django.conf import settings
import logging
import traceback
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SupersetService:
    def __init__(self):
        self.base_url = settings.SUPERSET_DOMAIN
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.session = requests.Session()
        self.csrftoken = None
        
    def login(self):
        """Authenticate with Superset using API authentication"""
        try:
            logger.info(f"Attempting to login to Superset at: {self.base_url}")
            
            # Login request
            login_url = f"{self.base_url}/api/v1/security/login"
            login_payload = {
                "username": settings.SUPERSET_USERNAME,
                "password": settings.SUPERSET_PASSWORD,
                "provider": "db",
                "refresh": True
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"Logging in with username: {settings.SUPERSET_USERNAME}")
            
            login_response = self.session.post(
                login_url, 
                headers=headers, 
                data=json.dumps(login_payload)
            )
            
            if login_response.status_code != 200:
                logger.error(f"Login failed: {login_response.status_code}")
                logger.error(f"Response: {login_response.text}")
                return False
                
            login_data = login_response.json()
            self.access_token = login_data.get('access_token')
            self.refresh_token = login_data.get('refresh_token')
            
            # Set token expiry (default to 1 hour if not provided)
            expiry_seconds = login_data.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expiry_seconds)
            
            logger.info(f"Login successful, token valid until {self.token_expiry}")
            
            # Now get CSRF token using the access token
            return self._get_csrf_token()
        except Exception as e:
            logger.error(f"Exception during Superset login: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def _get_csrf_token(self):
        """Get CSRF token using the access token"""
        try:
            if not self.access_token:
                logger.error("Cannot get CSRF token: No access token available")
                return False
                
            csrf_url = f"{self.base_url}/api/v1/security/csrf_token/"
            headers = {
                "Authorization": f"Bearer {self.access_token}"
            }
            
            logger.debug("Getting CSRF token")
            csrf_response = self.session.get(csrf_url, headers=headers)
            
            if csrf_response.status_code != 200:
                logger.error(f"Failed to get CSRF token: {csrf_response.status_code}")
                logger.error(f"Response: {csrf_response.text}")
                return False
                
            csrf_data = csrf_response.json()
            self.csrftoken = csrf_data.get('result')
            logger.debug(f"CSRF Token obtained successfully")
            return True
        except Exception as e:
            logger.error(f"Exception getting CSRF token: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def ensure_authenticated(self):
        """Ensure we have a valid authentication token and CSRF token"""
        # If we don't have a token or it's about to expire (within 5 minutes), get a new one
        if (not self.access_token or 
            not self.token_expiry or 
            datetime.now() > (self.token_expiry - timedelta(minutes=5))):
            
            logger.info(f"Token needs refresh: access_token exists: {bool(self.access_token)}, " 
                       f"expiry exists: {bool(self.token_expiry)}, "
                       f"current time: {datetime.now()}, "
                       f"token expiry: {self.token_expiry}")
            
            # Try to refresh the token if we have a refresh token
            if self.refresh_token:
                logger.info("Attempting token refresh...")
                if self._refresh_token():
                    logger.info("Token refresh successful")
                    # After refreshing, also get a new CSRF token
                    return self._get_csrf_token()
                logger.warning("Token refresh failed, falling back to login")
            else:
                logger.info("No refresh token available, proceeding to login")
            
            # If refresh fails or we don't have a refresh token, login again
            return self.login()
            
        logger.debug("Token is still valid")
        
        # If we have an access token but no CSRF token, get one
        if not self.csrftoken:
            logger.info("No CSRF token, requesting new one")
            return self._get_csrf_token()
            
        return True
    
    def _refresh_token(self):
        """Refresh the access token using the refresh token""" #TODO: fix this to make it work
        try:
            logger.debug("Attempting to refresh access token")
            
            refresh_url = f"{self.base_url}/api/v1/security/refresh"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.refresh_token}"
            }
            
            response = self.session.post(refresh_url, headers=headers)
            
            if response.status_code != 200:
                logger.warning(f"Token refresh failed: {response.status_code}")
                logger.warning(f"Response: {response.text}")
                return False
                
            refresh_data = response.json()
            self.access_token = refresh_data.get('access_token')
            
            # Update token expiry
            expiry_seconds = refresh_data.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expiry_seconds)
            
            logger.debug(f"Token refreshed successfully, valid until {self.token_expiry}")
            return True
            
        except Exception as e:
            logger.error(f"Exception during token refresh: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def get_guest_token(self, dashboard_id, user_info=None):
        """
        Get a guest token for dashboard embedding
        
        Args:
            dashboard_id (str): ID of the dashboard to embed
            user_info (dict): Information about the user (optional)
                Should include dealer_id if available for RLS filtering
                
        Returns:
            str: Guest token if successful, None otherwise
        """
        try:
            # Ensure we have a valid authentication token and CSRF token
            if not self.ensure_authenticated():
                logger.error("Failed to authenticate with Superset")
                return None
            
            guest_token_url = f"{self.base_url}/api/v1/security/guest_token/"
            logger.debug(f"Getting guest token from: {guest_token_url}")
            
            # Default user info if none provided
            if user_info is None:
                user_info = {"username": "guest"}
            
            # Define the resources to be accessed
            resources = [{
                "type": "dashboard",
                "id": dashboard_id
            }]
            
            # Initialize RLS rules array
            rls_rules = []
            
            # Add dealerId-based RLS rule
            if 'dealer_id' in user_info and user_info['dealer_id']:
                dealer_id = user_info['dealer_id']
                # Create RLS rule to filter by dealerId
                rls_rules.append({
                    "clause": f"dealerId = '{dealer_id}'"
                })
                logger.debug(f"Added RLS rule for dealerId: {dealer_id}")
            else:
                # If no dealer_id is available, add a rule that will return no data
                rls_rules.append({
                    "clause": "dealerId = 'NO_ACCESS'"
                })
                logger.warning("No dealer_id found in user_info, adding NO_ACCESS restriction rule")
            
            # Payload for guest token request
            payload = {
                "user": user_info,
                "resources": resources,
                "rls": rls_rules
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.access_token}",
                "X-CSRFToken": self.csrftoken
            }
            
            response = self.session.post(
                guest_token_url,
                headers=headers,
                data=json.dumps(payload)
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get guest token: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
            token_data = response.json()
            guest_token = token_data.get('token')
            logger.info(f"Successfully obtained guest token")
            return guest_token
            
        except Exception as e:
            logger.error(f"Exception while getting guest token: {str(e)}")
            logger.error(traceback.format_exc())
            return None