import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import useAuthStore from '../store/authStore';

/**
 * Custom hook to handle authentication state and protected routes
 * @param requireAuth Whether the current route requires authentication
 * @param redirectTo Redirect path for unauthenticated users (if requireAuth is true)
 * @param redirectIfAuth Redirect path for authenticated users (if requireAuth is false)
 * @returns Authentication state and helper methods
 */
const useAuth = ({
  requireAuth = false,
  redirectTo = '/login',
  redirectIfAuth = '/dashboard',
}: {
  requireAuth?: boolean;
  redirectTo?: string;
  redirectIfAuth?: string;
} = {}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    user,
    isAuthenticated,
    isLoading,
    error,
    login,
    register,
    logout,
    refreshAccessToken,
    clearError,
  } = useAuthStore();

  // Handle route protection and redirects
  useEffect(() => {
    if (isLoading) return;

    // If the route requires authentication and the user is not authenticated
    if (requireAuth && !isAuthenticated) {
      // Store the current location to redirect back after login
      const redirectPath = location.pathname !== '/login' ? location.pathname + location.search : undefined;
      navigate(redirectTo, {
        state: { from: redirectPath },
        replace: true,
      });
    }

    // If the route is for auth pages and the user is already authenticated
    if (!requireAuth && isAuthenticated) {
      const from = (location.state as any)?.from?.pathname || redirectIfAuth;
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, isLoading, requireAuth, navigate, location, redirectTo, redirectIfAuth]);

  // Handle token refresh on mount and periodically
  useEffect(() => {
    if (!isAuthenticated) return;

    const checkAuth = async () => {
      try {
        await refreshAccessToken();
      } catch (error) {
        console.error('Failed to refresh token:', error);
        logout();
      }
    };

    // Check auth status on mount
    checkAuth();

    // Set up periodic token refresh (every 14 minutes)
    const refreshInterval = setInterval(checkAuth, 14 * 60 * 1000);

    return () => clearInterval(refreshInterval);
  }, [isAuthenticated, refreshAccessToken, logout]);

  return {
    user,
    isAuthenticated,
    isLoading,
    error,
    login,
    register,
    logout,
    clearError,
  };
};

export default useAuth;
