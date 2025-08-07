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
  query: Record<string, string>;
  cookies: Record<string, string>;
  header: jest.Mock;
}

// Create a type that matches the Express Response but makes all methods optional
type PartialResponse = {
  [P in keyof Response]?: Response[P] extends (...args: infer A) => infer R 
    ? jest.Mock<R, A> 
    : Response[P];
};

export interface MockResponse extends PartialResponse {
  // Required methods that we know we'll be using in our tests
  status: jest.Mock<MockResponse, [number]>;
  json: jest.Mock<Response, [any?]>;
  send: jest.Mock<Response, [any?]>;
  cookie: jest.Mock<Response, [string, string, any?]>;
  clearCookie: jest.Mock<Response, [string, any?]>;
  
  // Add sendStatus which is required by Express Response
  sendStatus: jest.Mock<Response, [number]>;
  
  // Add other commonly used methods with proper typing
  setHeader?: jest.Mock<Response, [string, string | string[]]>;
  getHeader?: jest.Mock<string | string[] | undefined, [string]>;
  removeHeader?: jest.Mock<Response, [string]>;
  redirect?: jest.Mock<Response, [string | number, string?]>;
  
  // Allow any other properties
  [key: string]: any;
}

export type MockNextFunction = jest.MockedFunction<NextFunction>;
