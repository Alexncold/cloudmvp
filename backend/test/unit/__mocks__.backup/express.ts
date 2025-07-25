// Mocks para Express
/// <reference types="@types/jest" />
interface MockRequest {
  body: any;
  params: Record<string, any>;
  query: Record<string, any>;
  headers: Record<string, any>;
  session: Record<string, any>;
  cookies: Record<string, any>;
  get: (name: string) => any;
  [key: string]: any;
}

const mockRequest = (
  body: any = {},
  params: Record<string, any> = {},
  query: Record<string, any> = {},
  headers: Record<string, any> = {}
): MockRequest => ({
  body,
  params,
  query,
  headers,
  session: {},
  cookies: {},
  get(name: string) {
    return this.headers[name];
  },
});

interface MockResponse {
  status: jest.Mock<MockResponse, [number]>;
  json: jest.Mock<MockResponse, [any]>;
  send: jest.Mock<MockResponse, [any?]>;
  redirect: jest.Mock<MockResponse, [string]>;
  cookie: jest.Mock<MockResponse, [string, string, any?]>;
  [key: string]: any;
}

const mockResponse = (): any => {
  const res: any = {};
  
  // Common methods used in tests
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.sendStatus = jest.fn().mockReturnValue(res);
  
  // Handle both redirect signatures: (url) and (status, url)
  res.redirect = jest.fn().mockImplementation((...args: any[]) => {
    if (args.length === 1 && typeof args[0] === 'string') {
      // Handle redirect(url)
      return res;
    } else if (args.length === 2 && typeof args[0] === 'number' && typeof args[1] === 'string') {
      // Handle redirect(status, url)
      return res;
    }
    return res;
  });
  
  res.cookie = jest.fn().mockReturnValue(res);
  res.clearCookie = jest.fn().mockReturnValue(res);
  res.links = jest.fn().mockReturnValue(res);
  res.jsonp = jest.fn().mockReturnValue(res);
  res.sendFile = jest.fn().mockReturnValue(res);
  res.download = jest.fn().mockReturnValue(res);
  res.contentType = jest.fn().mockReturnValue(res);
  res.type = jest.fn().mockReturnValue(res);
  res.format = jest.fn().mockReturnValue(res);
  res.attachment = jest.fn().mockReturnValue(res);
  res.set = jest.fn().mockReturnValue(res);
  res.header = jest.fn().mockReturnValue(res);
  res.get = jest.fn();
  res.render = jest.fn();
  res.locals = {};
  return res;
};

export { mockRequest, mockResponse };
