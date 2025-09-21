# jwks_server
# Aarya Shrestha  

---
## Project Overview
This project implements a simple FastAPI application that supports JSON Web Key Sets (JWKS) and JSON Web Tokens (JWT).  
The server can:
- Generate RSA keys with expiration times
- Provide unexpired public keys through a JWKS endpoint
- Issue JWT tokens signed with either valid or expired keys

The project also includes a pytest test suite to verify functionality.

## Features
1. **Valid JWT Authentication**  
   - Issues a valid JWT signed with an active key  
2. **Expired JWT Authentication**  
   - Issues an expired JWT when requested  
3. **JWKS Endpoint**  
   - Provides only unexpired public keys  
4. **Error Handling**  
   - Returns correct HTTP status codes  
5. **Test Suite**  
   - Covers key generation, JWT issuance, JWKS endpoint, and error cases  
