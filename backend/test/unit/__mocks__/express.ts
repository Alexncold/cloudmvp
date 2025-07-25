import { Request, Response, NextFunction, RequestHandler } from 'express';
import { jest } from '@jest/globals';

// Mock json middleware
const json = jest.fn<RequestHandler>(() => (req: Request, res: Response, next: NextFunction) => {
  next();
});

// Mock urlencoded middleware
const urlencoded = jest.fn<RequestHandler>(() => (req: Request, res: Response, next: NextFunction) => {
  next();
});

// Create a mock for HTTP methods (get, post, put, delete, etc.)
const createHttpMethodMock = () => {
  const mock = jest.fn<RequestHandler>();
  mock.mockImplementation(() => mock as unknown as RequestHandler);
  return mock;
};

// Mock Router
const Router = jest.fn().mockImplementation(() => ({
  get: createHttpMethodMock(),
  post: createHttpMethodMock(),
  put: createHttpMethodMock(),
  delete: createHttpMethodMock(),
  patch: createHttpMethodMock(),
  use: jest.fn<RequestHandler>(),
  all: createHttpMethodMock(),
  route: jest.fn().mockReturnThis()
}));

// Mock Request
const mockRequest = (options: Partial<Request> = {}): Partial<Request> & { [key: string]: any } => {
  const req: any = {
    body: {},
    params: {},
    query: {},
    headers: {},
    cookies: {},
    user: undefined,
    ...options,
    get(name: string) {
      return this.headers?.[name.toLowerCase()] || '';
    },
    header: function(name: string) {
      return this.get(name);
    }
  };
  return req;
};

// Mock Response
const mockResponse = (): Partial<Response> => {
  const res: any = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  res.set = jest.fn().mockReturnValue(res);
  res.cookie = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.locals = {};
  return res;
};

// Mock NextFunction
const mockNext = jest.fn<NextFunction>();

// Create a mock for the Express application
const createAppMock = () => {
  const app: any = function() {};
  
  // Add HTTP methods
  const methods = ['get', 'post', 'put', 'delete', 'patch', 'all', 'use', 'route'];
  methods.forEach(method => {
    app[method] = createHttpMethodMock();
  });
  
  // Add other Express app methods
  app.listen = jest.fn();
  app.set = jest.fn();
  app.engine = jest.fn();
  app.enable = jest.fn();
  app.disable = jest.fn();
  
  // Add middleware
  app.use = jest.fn().mockReturnValue(app);
  
  // Add other Express static methods
  app.json = json;
  app.urlencoded = urlencoded;
  app.static = jest.fn();
  
  return app;
};

// Create the mock Express function
const express = jest.fn(createAppMock) as any;

// Add static methods to the Express mock
express.Router = jest.fn().mockImplementation(Router);
express.json = jest.fn().mockImplementation(() => json);
express.urlencoded = jest.fn().mockImplementation(() => urlencoded);
express.static = jest.fn();

export {
  express,
  mockRequest,
  mockResponse,
  mockNext,
  Router,
  json,
  urlencoded,
  createAppMock as createApplication
};

export default express;
