# complete_superset_test.py
# Run with: python complete_superset_test.py

import requests
import json
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
SUPERSET_DOMAIN = "http://192.168.183.31:8088"
SUPERSET_USERNAME = "arinaB"
SUPERSET_PASSWORD = "arinaB4578"
DASHBOARD_ID = "1d82f347-fc3f-45ae-ba06-8ddb984e3bcb"  # Replace with your actual dashboard ID

def test_complete_authentication():
    """Test the full Superset authentication flow"""
    print("\n=== TESTING SUPERSET AUTHENTICATION FLOW ===\n")
    
    session = requests.Session()
    
    # Step 1: Login to get access token
    print("\n--- STEP 1: Login to get access token ---")
    login_url = f"{SUPERSET_DOMAIN}/api/v1/security/login"
    login_payload = {
        "username": SUPERSET_USERNAME,
        "password": SUPERSET_PASSWORD,
        "provider": "db",
        "refresh": True
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        print(f"POST {login_url}")
        print(f"Headers: {headers}")
        print(f"Payload: {login_payload}")
        
        login_response = session.post(
            login_url,
            headers=headers,
            data=json.dumps(login_payload)
        )
        
        print(f"Response status: {login_response.status_code}")
        
        if login_response.status_code != 200:
            print(f"Login failed: {login_response.text}")
            return
            
        login_data = login_response.json()
        access_token = login_data.get('access_token')
        refresh_token = login_data.get('refresh_token')
        
        print(f"Access token: {access_token[:20]}...")
        print(f"Refresh token: {refresh_token[:20]}...")
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return
    
    # Step 2: Get CSRF token
    print("\n--- STEP 2: Get CSRF token ---")
    csrf_url = f"{SUPERSET_DOMAIN}/api/v1/security/csrf_token/"
    csrf_headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    try:
        print(f"GET {csrf_url}")
        print(f"Headers: {csrf_headers}")
        
        csrf_response = session.get(csrf_url, headers=csrf_headers)
        
        print(f"Response status: {csrf_response.status_code}")
        
        if csrf_response.status_code != 200:
            print(f"CSRF token request failed: {csrf_response.text}")
            return
            
        csrf_data = csrf_response.json()
        csrf_token = csrf_data.get('result')
        
        print(f"CSRF token: {csrf_token}")
        
    except Exception as e:
        print(f"CSRF token error: {str(e)}")
        return
    
    # Step 3: Get guest token
    print("\n--- STEP 3: Get guest token ---")
    guest_token_url = f"{SUPERSET_DOMAIN}/api/v1/security/guest_token/"
    
    # Sample user info with dealer ID
    user_info = {
        "username": "test_user",
        "first_name": "Test",
        "last_name": "User",
        "dealer_id": "test_dealer"  # Replace with valid dealer ID if needed
    }
    
    # Define resources to be accessed
    resources = [{
        "type": "dashboard",
        "id": DASHBOARD_ID
    }]
    
    # Define RLS rules
    rls_rules = [{
        "clause": f"dealerId = '{user_info['dealer_id']}'"
    }]
    
    # Payload for guest token request
    payload = {
        "user": user_info,
        "resources": resources,
        "rls": rls_rules
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "X-CSRFToken": csrf_token
    }
    
    try:
        print(f"POST {guest_token_url}")
        print(f"Headers: {headers}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        response = session.post(
            guest_token_url,
            headers=headers,
            data=json.dumps(payload)
        )
        
        print(f"Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"Guest token request failed: {response.text}")
            return
            
        token_data = response.json()
        guest_token = token_data.get('token')
        
        print(f"Guest token: {guest_token[:30]}...")
        print("\n=== AUTHENTICATION FLOW SUCCESSFUL ===")
        
        # Print instructions on how to use this token
        print("\nTo use this guest token for embedding, update your frontend code:")
        print("""
async function fetchGuestToken() {
    // Return the guest token from backend or directly
    return "${guest_token}";
}

supersetEmbeddedSdk.embedDashboard({
    id: "${DASHBOARD_ID}", 
    supersetDomain: "${SUPERSET_DOMAIN}",
    mountPoint: document.getElementById("dashboard-container"),
    fetchGuestToken: fetchGuestToken,
    // Other config...
});
""".replace("${guest_token}", guest_token).replace("${DASHBOARD_ID}", DASHBOARD_ID).replace("${SUPERSET_DOMAIN}", SUPERSET_DOMAIN))
        
    except Exception as e:
        print(f"Guest token error: {str(e)}")
        return

if __name__ == "__main__":
    test_complete_authentication()