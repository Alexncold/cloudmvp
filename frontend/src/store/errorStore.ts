import { create } from 'zustand';
import { toast } from 'sonner';
import useAuthStore from './authStore';

type ErrorType = 'auth' | 'validation' | 'server' | 'network' | 'unknown';

interface ErrorState {
  errors: Array<{
    id: string;
    type: ErrorType;
    message: string;
    timestamp: number;
    details?: any;
  }>;
  addError: (error: { type: ErrorType; message: string; details?: any }) => void;
  removeError: (id: string) => void;
  clearErrors: () => void;
  handleError: (error: unknown, context?: string) => void;
}

const createErrorStore = () => {
  return create<ErrorState>((set, get) => ({
    errors: [],

    addError: (error) => {
      const id = Math.random().toString(36).substring(2, 9);
      const timestamp = Date.now();
      
      set((state) => ({
        errors: [...state.errors, { ...error, id, timestamp }],
      }));

      // Show toast notification
      const errorMessage = error.message || 'An error occurred';
      toast.error(errorMessage, {
        id,
        duration: 5000,
        onDismiss: () => get().removeError(id),
      });
    },

    removeError: (id) => {
      set((state) => ({
        errors: state.errors.filter((error) => error.id !== id),
      }));
    },

    clearErrors: () => {
      set({ errors: [] });
    },

    handleError: (error, context) => {
      console.error(`[Error${context ? ` in ${context}` : ''}]`, error);
      
      let errorType: ErrorType = 'unknown';
      let message = 'An unexpected error occurred';
      let details = error;

      if (error instanceof Error) {
        message = error.message;
        
        if (message.includes('NetworkError') || message.includes('Failed to fetch')) {
          errorType = 'network';
          message = 'Unable to connect to the server. Please check your internet connection.';
        } else if (message.toLowerCase().includes('unauthorized') || 
                  message.toLowerCase().includes('token')) {
          errorType = 'auth';
          message = 'Your session has expired. Please log in again.';
        } else if (message.toLowerCase().includes('validation') || 
                  message.toLowerCase().includes('invalid')) {
          errorType = 'validation';
        }
      } else if (typeof error === 'string') {
        message = error;
      }

      get().addError({
        type: errorType,
        message,
        details,
      });

      // If it's an auth error, log the user out
      if (errorType === 'auth') {
        const authStore = useAuthStore.getState();
        if (authStore.isAuthenticated) {
          setTimeout(() => authStore.logout(), 2000); // Give time for the error to be displayed
        }
      }
    },
  }));
};

// Create the store instance
const errorStore = createErrorStore();

// Export a hook to use the error store with a simpler API
export const useErrorHandler = () => {
  const { handleError, clearErrors, errors } = errorStore();
  
  return {
    handleError,
    clearErrors,
    hasErrors: errors.length > 0,
    errors,
  };
};

// Export the store and the hook
export const useErrorStore = errorStore;
export default errorStore;
