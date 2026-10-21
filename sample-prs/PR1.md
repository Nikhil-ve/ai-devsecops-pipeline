Fix Hardcoded JWT Secret

Issue: Hardcoded JWT secret detected.



Fix: Move secret to environment variable.



Before: JWT\_SECRET="secret"



After: JWT\_SECRET=os.getenv("JWT\_SECRET")

