# docker buildx build -t teamvault-dev . --load
# docker-compose up
#
# If you want to enter the container, make sure to use "sh -l" to load
# the file in /etc/profile.d:
#
#   docker exec -ti teamvault sh -l

FROM python:3.12-alpine

RUN apk add build-base libpq-dev libffi-dev openldap-dev postgresql15

COPY . /teamvault

RUN sh -c 'echo ". /teamvault/docker/profile.d.sh" >/etc/profile.d/tv.sh'
RUN pip install -U pip
RUN sh -c 'python3 -mvenv /tvenv'
RUN sh -c '. /teamvault/docker/profile.d.sh && cd /teamvault && pip install -e .'

EXPOSE 8000

ENTRYPOINT ["/teamvault/docker/entrypoint"]
