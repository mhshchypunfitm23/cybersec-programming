from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/items")
def items(q: str = Query("", max_length=100)):
    # НАВМИСНО спрощено — для моделювання ризиків/SQLi у теорії; не під'єднано БД.
    return {"echo": q, "note": "demo only"}
