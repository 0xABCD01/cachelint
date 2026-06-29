# A Python service that reinstalls all pip dependencies on every code edit,
# updates apt in a separate layer, and never cleans the apt cache.
FROM python:3.12-slim

WORKDIR /srv

RUN apt-get update
RUN apt-get install -y build-essential

COPY . .

RUN pip install -r requirements.txt

CMD ["python", "-m", "app"]
