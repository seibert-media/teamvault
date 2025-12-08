export TEAMVAULT_CONFIG_FILE := "teamvault.cfg"

# just run
default: run

# Check lint, formatting, types and tests
qa: check-lint check-format types test

# Run ruff linter
check-lint:
  uvx ruff check

# Fix ruff linting issues
fix-lint:
  uvx ruff check --fix

# Check ruff formatting
check-format:
  uvx ruff format --check

# Reformat using ruff
format:
  uvx ruff format

# Check types with ty
types:
  uvx ty check

# Run tests (once we have them)
test:
  uv run teamvault/manage.py test

# Bring up postgres
db:
  # prefixed with '-' so the recipe doesn't fail if the container's already up
  -docker run --rm --detach --publish=5432:5432 --name teamvault-postgres -e POSTGRES_USER=teamvault -e POSTGRES_PASSWORD=teamvault postgres:latest

# wait until Postgres answers before starting servers
db_ready:
  until pg_isready -h localhost -p 5432 -U teamvault; do sleep 0.2; done

# Run webpack (bun)
webpack:
  bun run serve

# Start DB and then teamvault
teamvault: db db_ready
  uv run teamvault run

# Run teamvault and webpack together
[parallel]
run: webpack teamvault

# Run our install steps
install: db db_ready 
  uv sync
  -uv run teamvault setup
  vim teamvault.cfg  # base_url = http://localhost:8000; session_cookie_secure = False; database config as needed
  uv run teamvault upgrade
  uv run teamvault plumbing createsuperuser

