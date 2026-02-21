# Security Rules for AI Coding

1. **NEVER hardcode secrets**: Do not generate code with actual API keys, passwords, or tokens. Always use environment variables (e.g., `os.Getenv("TELEGRAM_BOT_TOKEN")`).
2. **Use .env.example**: When creating new features requiring config, always update `.env.example` with placeholder values (e.g., `YOUR_TOKEN_HERE`).
3. **No Logs of Secrets**: Never log sensitive information like passwords, full tokens, or PII (Personally Identifiable Information) to stdout or files. Mask them (e.g., `tok_****xyz`).
4. **Validate Inputs**: Always validate and sanitize user inputs in API endpoints.
5. **Error Handling**: Do not expose stack traces or internal DB errors to the client response. Return generic error messages.
