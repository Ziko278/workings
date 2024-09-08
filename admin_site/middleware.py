from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse


class AdminUserRestrictionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip checking for URLs containing 'login'
        if 'login' in request.path:
            response = self.get_response(request)
            return response

        # Check for admin access
        if request.path.startswith('/admin/'):
            if request.user.is_authenticated and not request.user.is_superuser:
                messages.error(request, 'ACCESS DENIED FOR CURRENT USER, LOGIN WITH APPROPRIATE ACCOUNT')
                return redirect(reverse('user_dashboard'))

        # Check for student access
        elif request.path.startswith('/user/'):
            if request.user.is_authenticated and request.user.is_superuser:
                messages.error(request, 'ACCESS DENIED FOR CURRENT USER, LOGIN WITH APPROPRIATE ACCOUNT')
                return redirect(reverse('admin_dashboard'))

        # Process the request
        response = self.get_response(request)
        return response
