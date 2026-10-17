# tatou SOFSETC 2026 Group 04
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

Tatou is a Flask based PDF watermarking platform developed and maintained for the SOFSEC group project. Users can register, authenticate, upload PDFs, generate watermarked versions and retreive documents using links. The platform also implements RMAP endpoints for encrypted group authentication and distribution of watermarked PDFs.

The repository builds on the course provided Tatou-project:
```bash
git clone https://github.com/nharrand/tatou-2026.git
```

To clone this repo:

```bash
git clone https://github.com/Ollehuss/SOFTSEC-PROJECT-GROUP4.git
```

Note that you should probably fork the repo and clone your own repo.

## Architecture and repository layout
server/src/ - Flask API, watermarking implementations, CLI and utilities
server/test - pytest test suite
Platform_specifications.md - platform requirements
server/pyproject.toml - Python package, dependencies, pytest settings
server/Dockerfile and server/entrypoint.sh - server image and Gunicorn startup
docker-compose.yml - server, MariaDB, and phpMyAdmin services
db/tatou.sql - database initialization script
sample.env - enviroment variable template

The application stores PDF files in the user-files Docker volume and MariaDB in the dm-data volume. On the universety VM (softsec-group-04) Docker Compose is running three services:
Flask/Gunicorn server on port 5000
MariaDB db on port 3306
phpmyadmin on port 8080

## Requirements
Ptthon 3.11 or newer for local development (the Docker image uses Python 3.12)
pip and Python virtual enviroments
Docker engine with the Docker Compose plugin for container deployment
Git for cloning the repository
Access to the RMAP key files and assigned PDF for the full RMAP workflow

## Instructions
The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

Run commands from the repository root unless a section says otherwise.

### Local setup

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate 
python -m pip install -e '.[dev]' 
```

### Unit and component tests

```bash
#From server/, with the virtual environment active
python -m pytest

#Run a specific test module example
python -m pytest test/test_visible_repeat.py

#Run the watermarking-related tests
python -m pytest test/test_watermarking_all_methods.py test/test_metadata_watermark.py test/test_hidden_object.py test/test_visible_repeat.py
```

### API tests

```bash
#From server/
python -m pytest test/test_api.py test/test_remaining_endpoints.py test/test_endpoint_validation.py test/test_fuzz_api.py

#Other relevant checks
python -m pytest test/test_token.py test/test_docker_config.py

test_fuzz_api.py containes API robustness/security oriented tests. Running that files is not necessarily the same as executing a separate long running fuzzing campaign.
```

### Coverage analysis
Install the coverage tooling if is it not already present in your enviroment

```bash
python -m pip install pytest-cov

#From server/; collect statement and branch coverage
python -m pytest --cov=src --cov-branch --cov-report=term-missing --cov-report=html
```

Open server/htmlcov/index.html in a browser to inspect covered/uncovered lines and branches. The Repository also includes server/coverage_report.txt from a previous run.

## Development workflow and CI/CD status
The group implemented an automated pytest suite and ran it locally. Coverage was generated with pytest-cov. No GitHub Actions workflow or other automated CI/CD pipeline has been implemented therefore, this repository should not be described as providing automatic testing on push or automatic deployment.

## Docker Deployment
Deployment to the universety VM is performed with Docker Compose ad described below.

### Configure enviroment variables

```bash
#From repository root on university VM
cp sample.env .env

#Edit .env and set uniqe strong values for:
MARIADB_ROOT_PASSWORD=replace-with-strong-root-password
MARIADB_USER=tatou
MARIADB_PASSWORD=replace-with-strong-database-password
SECRET_KEY=replace-with-long-random-secret
RMAP_PASSPHRASE=replace-with-key-passphrase-if-required
FLAG_2=replace-with-course-provided-value

```

In group 04 project on the university VM (softsec-group-04) sample.env does not contain SECRET_KEY or RMAP_PASSPHRASE
Do not commit .env , private keys, passwords or real flags.

### Prepare RMAP mounts
The current docker-compose.yml uses host-specific bind mounts. Before deploying ensure these paths exist on the Docker host or edit the compose file to match the machine.

Host path: ../rmap-keys
Container path: /app/keys
Purpose: Server openPGP keys and known client public keys

Host path: /home/softsec/Group_4.pdf
Container path: /app/assigned/Group_4.pdf
Purpose: Course assigned confidential PDF

The configured key locations inside the container are
/app/keys/server_pub.asc, /app/keys/server_priv.asc, /app/keys/clients/

RMAP key locations on our university VM:
Our application is deployed on softsec-group-04.dsv.local.su.se. The RMAP keys are stored outside the Git repository in /home/softsec/PROJECT/rmap-keys/.

The directory contains:
server_pub.asc — Our server's public OpenPGP key.
server_priv.asc — Our server's passphrase-protected private OpenPGP key.
clients/ — Public keys belonging to other groups and authorized clients.

Docker Compose mounts this directory as /app/keys inside the application container in read-only mode.

### Build and start

```bash
#From repository root on university VM
docker compose config
docker compose up --build -d
docker compose ps
docker compose logs -f server
```

### Verify deployment
curl -i http://localhost:5000/healthz

### Operate and update

```bash
docker compose logs -f
docker compose restart server
docker compose up --build -d

#stop and removes the Compose containers/network
docker compose down
```

## API overview
The Flask backend exposes the following routes. See server/API.md for request/response formats, authentication requirements and the full specification.

Healt check GET /Healthz
Registration and login: POST /api/create-user, POST /api/login
Upload and list PDFs: POST /api/upload-document, GET /api/list-documents
Retrieve/delete documents: GET /api/get-document/<id>, DELETE /api/delete-document/<id>
List watermarked versions: GET /api/list-versions/<id>, GET /api/list-all-versions
Create/read watermarks: POST /api/create-watermark/<id>, POST /api/read-watermark/<id>
List available watermarking methods: GET /api/get-watermarking-methods
Download using a link: GET /api/get-version/<link>
RMAP handshake: POST /api/rmap-initiate, POST /api/rmap-get-link

## Watermarking methods
The repository now includes the three group watermarkin implementations:

Visible Repeat - visible repeated PDF watermarking (server/src/visible_repeat_watermark.py)
Metadata Watermark - metadata based watermarking with HMAC related verification (server/src/olles_metadata_watermark.py)
Hidden Object - PDF hidden object watermarking (server/src/watermarking_joshua.py)

The common interface and registry are in server/src/watermarking_method.py and server/src/watermarking_utils.py

## Documentation
Test Coverage Report: Sepeately supplied testing summary
Mapping between specifications and tests: separately submitted requirements-to-test assessment



