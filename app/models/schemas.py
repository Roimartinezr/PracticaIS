from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    text: str

class AnalyzeUrlRequest(BaseModel):
    url: str

class HistoryEntry(BaseModel):
    type: str
    input: str
    verdict: str
    percentage: int | None = None

class Credentials(BaseModel):
    username: str
    password: str
