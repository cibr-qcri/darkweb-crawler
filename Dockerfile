# As Scrapy runs on Python, I choose the official Python 3 Docker image.
FROM python:3

ARG elasticsearch_ip

ENV ELASTICSEARCH_IP=$elasticsearch_ip

# Set the working directory to /usr/src/app.
WORKDIR /usr/src/app

# Copy the file from the local host to the filesystem of the container at the working directory.
COPY requirements.txt ./

# Install Scrapy specified in requirements.txt.
RUN pip3 install -r requirements.txt

# Copy the project source code from the local host to the filesystem of the container at the working directory.
COPY . .

# Run the crawler when the container launches.
CMD [ "scrapy", "crawl", "darkweb-crawler" ]