# dashboard/views.py

from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .superset_service import SupersetService
import logging
import traceback

logger = logging.getLogger(__name__)

# Create a singleton instance of SupersetService
# This allows reuse of the authentication token across requests
superset_service = SupersetService()

@login_required
def dashboard_view(request):
    """Render the dashboard page"""
    context = {
        'dashboard_id': settings.SUPERSET_DASHBOARD_ID,
        'superset_domain': settings.SUPERSET_DOMAIN,
        'user': request.user
    }
    return render(request, 'dashboard/dashboard.html', context)

@login_required
def get_guest_token(request):
    """API endpoint to get a guest token for the dashboard with RLS for dealerId"""
    try:
        logger.info("Guest token request received")
        
        # Simple check if settings are configured
        if not settings.SUPERSET_DOMAIN:
            error_msg = "Superset domain is not configured. Please check settings."
            logger.error(error_msg)
            return JsonResponse({'error': error_msg}, status=500)
            
        if not settings.SUPERSET_DASHBOARD_ID:
            error_msg = "Superset dashboard ID is not configured. Please check settings."
            logger.error(error_msg)
            return JsonResponse({'error': error_msg}, status=500)
        
        # Get the dealer_id from user profile or session
        dealer_id = None
        
        # Method 1: Extract from user profile (preferred)
        if hasattr(request.user, 'profile') and hasattr(request.user.profile, 'dealer_id'):
            dealer_id = request.user.profile.dealer_id
        
        # Method 2: Extract directly from user model if it's been extended
        elif hasattr(request.user, 'dealer_id'):
            dealer_id = request.user.dealer_id
        
        # Method 3: Extract from session
        elif 'dealer_id' in request.session:
            dealer_id = request.session['dealer_id']
        
        # Extract user information from the logged in user
        user_info = {
            "username": request.user.username,
            "first_name": request.user.first_name,
            "last_name": request.user.last_name,
        }
        
        # Add dealer_id to user_info if available
        if dealer_id:
            user_info["dealer_id"] = dealer_id
            logger.info(f"Using dealerId: {dealer_id} for user: {request.user.username}")
        else:
            logger.warning(f"No dealerId found for user: {request.user.username}. Will restrict access to all data.")
        
        # Get guest token with RLS rules using the singleton service
        token = superset_service.get_guest_token(
            dashboard_id=settings.SUPERSET_DASHBOARD_ID,
            user_info=user_info
        )
        
        if not token:
            error_msg = "Failed to get guest token. Check server logs for details."
            logger.error(error_msg)
            return JsonResponse({'error': error_msg}, status=500)
        
        logger.info(f"Successfully provided guest token for user: {request.user.username}")
        return JsonResponse({'token': token})
        
    except Exception as e:
        error_msg = f"Error getting guest token: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return JsonResponse({'error': error_msg}, status=500)