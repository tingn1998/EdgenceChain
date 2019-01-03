#!/bin/bash

sudo virtualenv --python=python3.6 venv && . venv/bin/activate

sudo pip install -r requirements.txt

sudo docker-compose up
