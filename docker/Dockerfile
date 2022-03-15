FROM alpine:3.15
RUN apk add git python3 py3-pip gcc python3-dev musl-dev freetds freetds-dev lksctp-tools-dev linux-headers
RUN git clone https://github.com/toddeye/pyhss.git
WORKDIR pyhss
RUN mkdir -p log
RUN pip3 install -r requirements.txt
CMD python3 hss.py