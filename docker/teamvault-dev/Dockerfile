FROM ubuntu:latest

# Install system-level dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libldap2-dev \
    libpq-dev \
    postgresql-client \
    postgresql-contrib \
    libsasl2-dev \
    python3-dev \
    python3-venv

# Copy the TeamVault application code
COPY . /teamvault

# Create a virtual environment
RUN python3 -m venv /tvenv

# Activate the virtual environment and install Python dependencies
RUN /tvenv/bin/pip install -U pip
RUN /tvenv/bin/pip install -e /teamvault

# Expose the application port
EXPOSE 8000
# Set the entrypoint to start the application
ENTRYPOINT ["/teamvault/docker/teamvault-dev/entrypoint"]
