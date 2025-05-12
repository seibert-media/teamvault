# To build use: docker build -t teamvault-dev -f docker/Dockerfile .
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
RUN /tvenv/bin/pip install psycopg2-binary -e /teamvault

# Copy the entrypoint script
COPY docker/entrypoint /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint
#COPY ./tv.cfg /etc/teamvault.conf

# Expose the application port
EXPOSE 8000

# Set the entrypoint to start the application
ENTRYPOINT ["/usr/local/bin/entrypoint"]
