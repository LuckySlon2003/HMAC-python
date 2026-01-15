test:
	uv run pytest tests

run/api:
	uv run main.py

sync:
	uv sync

rotate-secret:
	uv run rotate-secret --print
