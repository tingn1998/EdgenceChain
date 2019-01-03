FROM python:3.6.7
ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD edgencechain.py ./

CMD ["./edgencechain.py", "serve"]
