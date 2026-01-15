"""Main module for run FastAPI application"""

import uvicorn

from src.app import app
from src.config import load_config
from src.constants import CONFIG_FILE

if __name__ == '__main__':
    cfg = load_config(CONFIG_FILE)
    host = cfg.listen_host
    port = cfg.listen_port
    uvicorn.run(app, host=host, port=int(port))
