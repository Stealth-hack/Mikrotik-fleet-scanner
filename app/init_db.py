"""Run once to create tables: python -m app.init_db"""
from app.database import Base, engine
from app import models  # noqa: F401 — import so models register on Base.metadata

if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    print("Tables created.")
