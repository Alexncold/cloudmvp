import { Request, Response, NextFunction } from 'express';

declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      isAdmin: boolean;
    }

    interface Request {
      user?: User;
    }
  }
}

export interface MockRequest extends Partial<Request> {
  body: any;
  params: Record<string, string>;
  query: Record<string, string | string[]>;
  cookies: Record<string, string>;
  header: jest.Mock;
  user?: {
    id: string;
    email: string;
    isAdmin: boolean;
  };
  [key: string]: any; // Para permitir propiedades adicionales
}

// Create a type that matches the Express Response but makes all methods optional
type PartialResponse = {
  [P in keyof Response]?: Response[P] extends (...args: infer A) => infer R 
    ? jest.Mock<R, A> 
    : Response[P];
};

// Extend the Express Response type to make all methods optional and mockable
type MockedResponse = {
  [P in keyof Response]?: Response[P] extends (...args: infer A) => infer R 
    ? jest.Mock<R, A> 
    : Response[P];
};

export interface MockResponse extends MockedResponse {
  // Required methods that we know we'll be using in our tests
  status: jest.Mock<MockResponse, [number]>;
  json: jest.Mock<MockResponse, [any?]>;
  send: jest.Mock<MockResponse, [any?]>;
  cookie: jest.Mock<MockResponse, [string, string, any?]>;
  clearCookie: jest.Mock<MockResponse, [string, any?]>;
  
  // Add sendStatus which is required by Express Response
  sendStatus: jest.Mock<MockResponse, [number]>;
  
  // Add other commonly used methods with proper typing
  setHeader: jest.Mock<MockResponse, [string, string | string[]]>;
  getHeader: jest.Mock<string | string[] | undefined, [string]>;
  removeHeader: jest.Mock<MockResponse, [string]>;
  redirect: jest.Mock<MockResponse, [string | number, string?]>;
  
  // Add locals property which is commonly used
  locals: Record<string, any>;
  
  // Allow any other properties
  [key: string]: any;
}

export type MockNextFunction = jest.MockedFunction<NextFunction>;
