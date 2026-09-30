"""
Simple DB connection helper for MSSQL using pyodbc.
Uses Windows Authentication (Trusted_Connection) - no username/
password needed, it uses whichever Windows account is running
this script.

For a beginner project, a fresh connection per request is fine.
Later, swap this for a connection pool (e.g. SQLAlchemy engine)
once traffic/complexity grows.
"""

import os
import pyodbc
from dotenv import load_dotenv

load_dotenv()

DB_SERVER = os.getenv("DB_SERVER")
DB_NAME = os.getenv("DB_NAME")
DB_DRIVER = os.getenv("DB_DRIVER")


def get_connection():
    """
    Opens and returns a new pyodbc connection using Windows
    Authentication. Caller is responsible for closing it
    (use 'with' where possible).
    """
    conn_str = (
        f"DRIVER={DB_DRIVER};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        f"Trusted_Connection=yes;"
        f"Encrypt=yes;TrustServerCertificate=yes;"
    )
    return pyodbc.connect(conn_str)