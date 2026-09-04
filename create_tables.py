from app.database.database import Base, engine

# IMPORTANT:
# Import every model before create_all()
from app.database import models

print("Creating tables...")

Base.metadata.create_all(bind=engine)

print("Tables created successfully.")
print("Tables:", list(Base.metadata.tables.keys()))