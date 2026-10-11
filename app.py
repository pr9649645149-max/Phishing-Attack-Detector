from fastapi import FastAPI
from pydantic import BaseModel
from phishing_detector import score_url, score_email_text

app = FastAPI(title="Phishing Attack Detector")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str

@app.get("/")
def root():
    return {"message": "Phishing Attack Detector API is running"}

@app.post("/detect/url")
def detect_url(payload: URLRequest):
    score, label = score_url(payload.url)
    return {
        "url": payload.url,
        "score": score,
        "label": label
    }

@app.post("/detect/email")
def detect_email(payload: EmailRequest):
    score, label = score_email_text(payload.text)
    return {
        "score": score,
        "label": label
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)