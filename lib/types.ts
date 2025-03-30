export interface User {
    _id: string;
    refreshToken?: string;
    save: (options?: any) => Promise<void>;
  }
  
  export interface CookieOptions {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Strict" | "Lax" | "None";
    maxAge?: number;
  }
  
  export interface TokenStorage {
    saveRevokedToken: (jti: string, exp: number) => Promise<void>;
    isTokenRevoked: (jti: string) => Promise<boolean>;
  }
  