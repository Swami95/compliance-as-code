from fastapi import FastAPI
from scanner.aws_scanner import scan_aws_account

app = FastAPI()

@app.get("/")
def health():
    return {"status": "ok"}

@app.post("/scan")
def scan(credentials: dict):
    results = scan_aws_account(credentials)
    return results
