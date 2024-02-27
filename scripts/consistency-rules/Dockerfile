# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory in the container
WORKDIR /app

COPY requirements.txt .

# Install elasticsearch backend from source
COPY ./pySigma-backend-elasticsearch /app/pySigma-backend-elasticsearch
RUN cd /app/pySigma-backend-elasticsearch && \
    pip install .

# Install insight_idr backend from source
COPY ./pySigma-backend-insightidr /app/pySigma-backend-insightidr
RUN cd /app/pySigma-backend-insightidr && \
    pip install .

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app
COPY ./pipelines/elastic-pipeline.yaml /etc/sigma/elastic.yaml
COPY ./pipelines/splunk-pipeline.yaml /etc/sigma/splunk.yaml
COPY ./pipelines/insight-pipeline.yaml /etc/sigma/insight.yaml

ENV TERM xterm-256color

# Run app.py when the container launches
ENTRYPOINT ["python3", "main.py"]
