import uvicorn

if __name__ == "__main__":
    # Windows-friendly run (igual que en tu monolito)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
