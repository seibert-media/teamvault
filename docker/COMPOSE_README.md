# Local Dev-Environment
The purpose of these Dockerfiles and the docker-compose.yml is to test code changes directly locally during development.

## Setting up the local environment
To build the containers, run the following commands from the project root directory:
### Building the containers

Build the containers you have to run the following commands from the project root directory:
```bash
docker build -t webpack-dev -f docker/webpack-dev/Dockerfile .
docker build -t teamvault-dev -f docker/teamvault-dev/Dockerfile .
```
### Start the services with docker compose

To start the services via Docker Compose, run the following command from the project root directory:
```bash
docker compose up
```
Or, if you want to run the services in the background, use the following command:
```bash
docker compose up -d
```
### Stop the services with docker compose

To stop the services via Docker Compose, run the following command from the project root directory:
```bash
docker compose down
```
### To-Dos after code changes

After changing the source code, you need to rebuild the corresponding container.

#### Teamvault Django Backend:
```bash
docker build -t teamvault-dev -f docker/teamvault-dev/Dockerfile .
```
#### Teamvault Webpack Frontend:
```bash
docker build -t webpack-dev -f docker/webpack-dev/Dockerfile .
```