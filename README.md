# This Python script verifying the DKIM signature of EML files  
  
  
Hash algorithms : RSA-SHA1 and RSA-SHA256  
Canonicalization of headers and body: simple and/or relaxed  
Extraction of the public DKIM key from DNS records, except of 20120113._domainkey.gmail.com and 20161025._domainkey.gmail.com because they are old and revoked by Google, but hardcoded in this script.  
Verify more than one headers of same type and/or DKIM signatures.  
  
Python programming language is needed.  
Syntax : verify-dkim-signature.py "email.eml"  
  
Requirements:  
dnspython  
typed-ast  
typing  
typing-extensions  
mypy  
mypy-extensions  
pycryptodome  

