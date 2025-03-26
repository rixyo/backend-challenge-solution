import bcrypt from "bcrypt";
import { Request, Response } from "express";
import dotenv from "dotenv";
import User from "../../src/models/User";
import { login, logout, signup } from "../../src/controllers/authController";
import { ERROR_MESSAGES } from "../../src/constants/messages";
import { redisClient } from "../../src/utils/redis";
dotenv.config();
jest.mock("../../src/models/User");

jest.mock("../../src/utils/redis", () => ({
  redisClient: {
    set: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
    expireAt: jest.fn(),
  },
}));

jest.mock("../../src/utils/jwt", () => ({
  generateAccessToken: jest.fn(() => "mockAccessToken"),
  generateRefreshToken: jest.fn(() => "mockRefreshToken"),
}));
const getMockReqAndRes = () => {
  const mockReq = {
    body: { email: "test1@test.com", password: "passWord1" },
  } as Request;

  const mockRes = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  } as unknown as Response;

  return { mockReq, mockRes };
};

describe("Signup Controller", () => {
  let mockReq: any;
  let mockRes: any;

  beforeEach(() => {
    mockReq = getMockReqAndRes().mockReq;
    mockRes = getMockReqAndRes().mockRes;

    (User.prototype.save as jest.Mock).mockResolvedValue({
      _id: "1",
      password: "hashed_value",
      email: "test1@test.com",
    });
  });

  it("should return 201 for creating a new user", async () => {
    await signup(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.any(String),
      })
    );
  });

  it("should return 400 if email already exists", async () => {
    const duplicateKeyError: any = new Error("Duplicate key error");
    duplicateKeyError.code = 11000;

    (User.prototype.save as jest.Mock).mockRejectedValue(duplicateKeyError);

    await signup(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: ERROR_MESSAGES.SIGNUP_FAILED,
    });
  });

  it("should return 500 for unexpected errors", async () => {
    (User.prototype.save as jest.Mock).mockRejectedValue(
      new Error("Database error")
    );

    await signup(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: "Internal server error",
    });
  });
});

describe("Login Controller", () => {
  let mockReq: any;
  let mockRes: any;

  beforeEach(() => {
    mockReq = getMockReqAndRes().mockReq;
    mockRes = getMockReqAndRes().mockRes;

    (User.findOne as jest.Mock).mockResolvedValue({
      _id: "1",
      password: "hashed_value",
      email: "test1@test.com",
    });
  });

  it("should return 200 for successful login", async () => {
    bcrypt.compare = jest.fn().mockResolvedValue(true);
    mockRes.cookie = jest.fn().mockReturnValue(true);

    await login(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.any(String),
        accessToken: expect.any(String),
      })
    );
    expect(mockRes.cookie).toHaveBeenCalled();
  });

  it("should return 401 for unmatched credential", async () => {
    bcrypt.compare = jest.fn().mockResolvedValue(false);

    await login(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: ERROR_MESSAGES.INVALID_CREDENTIALS,
    });
  });

  it("should return 500 for error", async () => {
    bcrypt.compare = jest
      .fn()
      .mockRejectedValue(new Error("Something went wrong"));

    await login(mockReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR,
    });
  });
});

describe("logout Controller", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;

  beforeEach(() => {
    // Reset mocks and create fresh request/response objects for each test
    jest.clearAllMocks();
    req = {
      headers: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      end: jest.fn(),
    };
  });

  it("should return 400 if no token is provided", async () => {
    // Simulate a request with no token
    req.headers = {};

    await logout(req as Request, res as Response);

    // Assertions
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: "No token provided." });
    expect(redisClient.set).not.toHaveBeenCalled();
    expect(redisClient.expireAt).not.toHaveBeenCalled();
  });

  it("should invalidate the token and return 204 if token is provided", async () => {
    // Simulate a request with a token
    const token = "valid-token";
    req.headers = { authorization: `Bearer ${token}` };

    // Mock Redis methods to resolve successfully
    (redisClient.set as jest.Mock).mockResolvedValue("OK");
    (redisClient.expireAt as jest.Mock).mockResolvedValue(1);

    await logout(req as Request, res as Response);

    // Assertions
    expect(redisClient.set).toHaveBeenCalledWith(
      `invalidated:${token}`,
      "true"
    );
    expect(redisClient.expireAt).toHaveBeenCalledWith(
      `invalidated:${token}`,
      Math.floor(Date.now() / 1000) + 3600
    );
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
  });
});
