import os
from fastapi import FastAPI


def load_user(user_id: int) -> str:
    return str(user_id)


async def fetch_user(user_id: int) -> str:
    return str(user_id)


def outer() -> int:
    def inner() -> int:
        return 1

    return inner()


def traced(fn):
    return fn


class Repository:
    @traced
    def save(self, value: str) -> str:
        return value


app = FastAPI()
os.getcwd()
