import errorStore from '../store/errorStore';
import useAuthStore from '../store/authStore';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface RequestOptions extends RequestInit {
  useAuth?: boolean;
  isFormData?: boolean;
}

/**
 * A custom fetch wrapper that handles authentication, error handling, and response parsing
 */
async function api<T = any>(
  endpoint: string,
  { useAuth = true, isFormData = false, ...options }: RequestOptions = {}
): Promise<T> {
  const authStore = useAuthStore.getState();
  const headers: HeadersInit = {};

  // Set content type if not FormData
  if (!isFormData) {
    headers['Content-Type'] = 'application/json';
  }

  // Add authorization header if needed
  if (useAuth && authStore.accessToken) {
    headers['Authorization'] = `Bearer ${authStore.accessToken}`;
  }

  // Add credentials for cookies
  const config: RequestInit = {
    ...options,
    headers: {
      ...headers,
      ...options.headers,
    },
    credentials: 'include', // Important for HTTP-only cookies
  };

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    
    // Handle error responses
    if (!response.ok) {
      let errorData;
      const contentType = response.headers.get('content-type');
      
      try {
        errorData = contentType?.includes('application/json') 
          ? await response.json()
          : await response.text();
      } catch (e) {
        errorData = { message: 'Failed to parse error response' };
      }
      
      const error = new Error(errorData.message || `Request failed with status ${response.status}`);
      (error as any).status = response.status;
      (error as any).data = errorData;
      throw error;
    }
    
    // Parse successful response
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else if (response.status !== 204) {
      // If not a 204 No Content response, try to parse as text
      data = await response.text();
    }

    // Handle 401 Unauthorized (token expired or invalid)
    if (response.status === 401 && useAuth) {
      try {
        // Try to refresh the token
        const newToken = await authStore.refreshAccessToken();
        
        if (newToken) {
          // Retry the original request with the new token
          return api<T>(endpoint, {
            ...options,
            headers: {
              ...options.headers,
              'Authorization': `Bearer ${newToken}`,
            },
          });
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError);
        // If refresh fails, let the error propagate to be handled by the global error handler
      }
      
      // If we get here, either refresh failed or we didn't have a refresh token
      authStore.logout();
      throw new Error('Session expired. Please log in again.');
    }

    return data;
  } catch (error) {
    // Use the error store to handle the error
    const errorHandler = errorStore.getState();
    
    // Handle network errors specifically
    if (error instanceof TypeError && error.message === 'Failed to fetch') {
      errorHandler.handleError({
        type: 'network',
        message: 'Unable to connect to the server. Please check your internet connection.',
        details: error,
      });
    } else {
      // For other errors, include the endpoint in the context for better debugging
      const context = `API call to ${endpoint}`;
      errorHandler.handleError(error, context);
    }
    
    // Re-throw the error for the caller to handle if needed
    throw error;
  }
}

// Auth API methods
export const authApi = {
  login: (credentials: { email: string; password: string }) =>
    api<{ user: any; accessToken: string; refreshToken: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    }),

  register: (userData: { name: string; email: string; password: string }) =>
    api<{ user: any; accessToken: string; refreshToken: string }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    }),

  logout: () => api('/api/auth/logout', { method: 'POST' }),

  refreshToken: (refreshToken: string) =>
    api<{ accessToken: string; refreshToken: string }>('/api/auth/refresh-token', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    }),

  verifyEmail: (token: string) =>
    api<{ message: string }>(`/api/auth/verify-email?token=${token}`, {
      method: 'GET',
    }),

  forgotPassword: (email: string) =>
    api<{ message: string }>('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  resetPassword: (token: string, password: string) =>
    api<{ message: string }>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    }),
};

// User API methods
export const userApi = {
  getProfile: () => api<any>('/api/users/me'),
  updateProfile: (userData: any) =>
    api<any>('/api/users/me', {
      method: 'PATCH',
      body: JSON.stringify(userData),
    }),
  changePassword: (currentPassword: string, newPassword: string) =>
    api<{ message: string }>('/api/users/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
};

// Camera API methods
export const cameraApi = {
  getCameras: () => api<any[]>('/api/cameras'),
  getCamera: (id: string) => api<any>(`/api/cameras/${id}`),
  createCamera: (cameraData: any) =>
    api<any>('/api/cameras', {
      method: 'POST',
      body: JSON.stringify(cameraData),
    }),
  updateCamera: (id: string, cameraData: any) =>
    api<any>(`/api/cameras/${id}`, {
      method: 'PUT',
      body: JSON.stringify(cameraData),
    }),
  deleteCamera: (id: string) =>
    api<{ message: string }>(`/api/cameras/${id}`, {
      method: 'DELETE',
    }),
};

export default api;
