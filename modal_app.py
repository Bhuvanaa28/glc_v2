"""
Modal deployment wrapper for glc_v1  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
# Pinned, reproducible base image by digest.
image = (
    modal.Image.from_registry(
        "python:3.11-slim-bookworm@sha256:d8c558caff1ca2c49ee6900ee9c31405b0c72f10b2170f074d4850faad83ff6e"
    )
    .pip_install("uv")
    .add_local_file("pyproject.toml", "/root/pyproject.toml")
    .add_local_file("uv.lock", "/root/uv.lock")
    .run_commands("cd /root && uv sync --frozen --no-dev --no-install-project")
    .env(
        {
            "GLC_CONFIG_DIR": "/data/glc",
            "GLC_ENV": "production",
            "PATH": "/root/.venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)


# A persistent Volume. The audit db and pairing db live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")

# The master installation token, injected as an environment variable (GLC_INSTALL_TOKEN).
install_token_secret = modal.Secret.from_name("glc-install-token")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, install_token_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    max_containers=1,  # pin container concurrency to prevent SQLite volume writes corruption
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is

    return web
