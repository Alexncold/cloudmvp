/**
 * Standard API response format
 */
export interface ApiResponse<T = unknown> {
  /**
   * Indicates if the request was successful
   */
  success: boolean;
  
  /**
   * Response data (only present if success is true)
   */
  data?: T;
  
  /**
   * Error details (only present if success is false)
   */
  error?: {
    /**
     * Error code (e.g., 'VALIDATION_ERROR', 'NOT_FOUND')
     */
    code: string;
    
    /**
     * Human-readable error message
     */
    message: string;
    
    /**
     * Additional error details (only in development)
     */
    details?: any;
  };
  
  /**
   * ISO timestamp of when the response was generated
   */
  timestamp: string;
}

/**
 * Paginated API response
 */
export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  /**
   * Pagination metadata
   */
  pagination: {
    /**
     * Current page number (1-based)
     */
    page: number;
    
    /**
     * Number of items per page
     */
    pageSize: number;
    
    /**
     * Total number of items across all pages
     */
    totalItems: number;
    
    /**
     * Total number of pages
     */
    totalPages: number;
  };
}

/**
 * Standard error response
 */
export interface ErrorResponse extends Omit<ApiResponse<null>, 'data'> {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
}
