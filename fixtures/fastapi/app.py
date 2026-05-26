from fastapi import FastAPI

app = FastAPI()


@app.get("/health", response_model=dict[str, str])
async def health() -> dict[str, str]:
    return {"status": "ok"}
