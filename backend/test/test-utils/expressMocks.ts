import { MockRequest, MockResponse } from '../types/express.types';

export const createMockRequest = (overrides: Partial<MockRequest> = {}): MockRequest => ({
  body: {},
  params: {},
  query: {},
  cookies: {},
  header: jest.fn(),
  ...overrides,
});

export const createMockResponse = (): MockResponse => {
  const res: any = {};
  
  // Core methods that we'll use in our tests
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.cookie = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.sendStatus = jest.fn().mockReturnValue(res);
  
  // Add other commonly used methods with proper mocks
  res.setHeader = jest.fn().mockReturnValue(res);
  res.getHeader = jest.fn().mockReturnValue(undefined);
  res.removeHeader = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  
  // Add any other properties that might be accessed
  res.headersSent = false;
  res.locals = {};
  
  return res as unknown as MockResponse;
};

export const createMockNext = (): jest.Mock => {
  return jest.fn();
};
