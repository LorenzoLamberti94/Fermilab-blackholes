FROM python:3.7

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "faust", "-A", "blackhole_detector", "worker", "-l", "info" ]
