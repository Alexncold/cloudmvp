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

export type MockRequest = Partial<Request> & {
  body: any;
  params: Record<string, string>;
  query: Record<string, string>;
  cookies: Record<string, string>;
  header: jest.Mock;
};

export type MockResponse = Partial<Response> & {
  status: jest.Mock<MockResponse>;
  json: jest.Mock<Response>;
  send: jest.Mock<Response>;
  cookie: jest.Mock<Response>;
  clearCookie: jest.Mock<Response>;
};

export type MockNextFunction = jest.MockedFunction<NextFunction>;

export const createMockRequest = (overrides: Partial<MockRequest> = {}): MockRequest => ({
  body: {},
  params: {},
  query: {},
  cookies: {},
  header: jest.fn(),
  ...overrides,
});

export const createMockResponse = (): MockResponse => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis(),
  cookie: jest.fn().mockReturnThis(),
  clearCookie: jest.fn().mockReturnThis(),
});
