import jwt from "jsonwebtoken";
import crypto from "crypto";
import { IncomingMessage, ServerResponse } from "http";
import { User, CookieOptions, TokenStorage } from "./types";

class Auth {
  private accessSecret: string;
  private refreshSecret: string;
  private tokenStorage: TokenStorage;
  private accessExpiry: string;
  private refreshExpiry: string;

  constructor(
    accessSecret: string,
    refreshSecret: string,
    tokenStorage: TokenStorage,
    accessExpiry: string = "15m",
    refreshExpiry: string = "3d"
  ) {
    this.accessSecret = accessSecret;
    this.refreshSecret = refreshSecret;
    this.tokenStorage = tokenStorage;
    this.accessExpiry = accessExpiry;
    this.refreshExpiry = refreshExpiry;
  }

  private setCookie(res: ServerResponse, name: string, value: string, options: CookieOptions = {}) {
    const attributes = [
      `${name}=${encodeURIComponent(value)}`,
      options.httpOnly && "HttpOnly",
      options.secure && "Secure",
      options.sameSite ? `SameSite=${options.sameSite}` : null,
      options.maxAge ? `Max-Age=${options.maxAge}` : null,
      "Path=/",
    ].filter(Boolean).join("; ");
  
    res.setHeader("Set-Cookie", attributes);
  }

  private generateToken(userId: string, secret: string, expiresIn: string) {
    const jti = crypto.randomUUID();
    const token = jwt.sign({ userId, jti }, secret, { expiresIn, algorithm: "HS256" });

    const { exp } = jwt.decode(token) as { exp: number };
    return { token, jti, exp };
  }

  async generateAccessAndRefreshToken(user: User, res: ServerResponse) {
    try {
      const { token: accessToken } = this.generateToken(user._id, this.accessSecret, this.accessExpiry);
      const { token: refreshToken } = this.generateToken(user._id, this.refreshSecret, this.refreshExpiry);
  
      const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex");
  
      if (user.save) {
        user.refreshToken = hashedRefreshToken;
        await user.save({ validateBeforeSave: false });
      }
  
      this.setCookie(res, "accessToken", accessToken, { httpOnly: true, secure: true, maxAge: this.getExpiryInSeconds(this.accessExpiry) });
      this.setCookie(res, "refreshToken", refreshToken, { httpOnly: true, secure: true, maxAge: this.getExpiryInSeconds(this.refreshExpiry) });
  
      return { accessToken, refreshToken };
    } catch (error) {
      console.error("Error in generateAccessAndRefreshToken:", error);
      throw new Error("Failed to Generate Tokens");
    }
  }
  

  private getExpiryInSeconds(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 0;

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case "s": return value;
      case "m": return value * 60;
      case "h": return value * 60 * 60;
      case "d": return value * 24 * 60 * 60;
      default: return 0;
    }
  }

  private async verifyToken(token: string, secret: string) {
    try {
      const decoded = jwt.verify(token, secret) as { userId: string; jti: string };
  
      if (await this.tokenStorage.isTokenRevoked(decoded.jti)) {
        throw new Error("Token has been revoked");
      }
      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        console.error("Token expired:", error);
        throw new Error("Token expired");
      } else if (error instanceof jwt.JsonWebTokenError) {
        console.error("Invalid token:", error);
        throw new Error("Invalid token");
      } else {
        console.error("Token verification failed:", error);
        return null;
      }
    }
  }

  async verifyRefreshToken(providedToken: string, storedHashedToken: string): Promise<boolean> {
    const hashedProvidedToken = crypto.createHash("sha256").update(providedToken).digest("hex");
    return hashedProvidedToken === storedHashedToken;
  }
  
  async revokeToken(token: string) {
    try {
      const decoded = jwt.decode(token) as { jti: string; exp: number } | null;
      if (decoded && decoded.jti) {
        const alreadyRevoked = await this.tokenStorage.isTokenRevoked(decoded.jti);
        if (!alreadyRevoked) {
          await this.tokenStorage.saveRevokedToken(decoded.jti, decoded.exp);
        }
      }
    } catch (error) {
      console.error("Error in revoking token:", error);
    }
  }

  async logout(res: ServerResponse, refreshToken?: string) {
    try {
      if (refreshToken) {
        await this.revokeToken(refreshToken);
      }
      this.setCookie(res, "accessToken", "", { httpOnly: true, secure: true, maxAge: 0 });
      this.setCookie(res, "refreshToken", "", { httpOnly: true, secure: true, maxAge: 0 });

      console.log("User logged out successfully.");
    } catch (error) {
      console.error("Error in logout:", error);
      throw new Error("Failed to Logout");
    }
  }

  async authenticate(req: IncomingMessage, res: ServerResponse) {
    try {
      const cookies = req.headers.cookie || "";

      const token =
        cookies
          .split("; ")
          .map((c) => c.split("="))
          .reduce(
            (acc, [key, value]) => ({
              ...acc,
              [key]: decodeURIComponent(value),
            }),
            {} as Record<string, string>
          )["accessToken"] || "";

      if (!token) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Unauthorized! Token missing." }));
        return false;
      }

      const decoded = await this.verifyToken(token, this.accessSecret);
      if (!decoded) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Invalid or Revoked Token!" }));
        return false;
      }

      (req as unknown as { user: { userId: string; jti: string } }).user = decoded;
      return true;
    } catch (error) {
      console.error("Error in authenticate:", error);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Internal Server Error" }));
      return false;
    }
  }
}

export default Auth;
