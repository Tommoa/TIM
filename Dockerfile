FROM python:3.7.1

LABEL Author="Dylan"
LABEL E-mail="21711951@student.uwa.edu.au"
LABEL version="0.0.1"

ENV PYTHONDONTWRITEBYTECODE 1
ENV FLASK_APP "TIM"
ENV FLASK_ENV "production"
ENV FLASK_DEBUG True

RUN mkdir /app
COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

ADD . /app

EXPOSE 5000

CMD flask run --host=0.0.0.0
