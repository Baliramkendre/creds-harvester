# Leak Data Parser  
A Python CLI tool for extracting credentials from leaked data sources.

INFORMATIVE FEATURES:  
- Parses email:password pairs with optional URL.  
- Recognizes IP-based credentials (IP:user:pass).  
- Supports Android and HTTP(S) URL schemes.  
- Accepts separators: colon, semicolon, pipe, whitespace.  
- Rejects malformed lines (leading apostrophe, blank entries).

PARSING ENGINE:  
- Ordered regex patterns for specific matching rules.  
- Five core patterns: email/pass/url, ip/email/pass, ip/user/pass, url/user/pass, email/pass.  
- Special-case rules for Android tokens and edge conditions.

SPECIAL HANDLING:  
- Dynamic detection for mixed-order tokens.  
- Custom overrides for known anomalies (user118, admin patterns).  
- Null outputs for unsupported formats.

## Usage

```bash
python parser.py input_data.txt
```
## Test cases
```bash
python3 -m unittest test_parser.py
```
