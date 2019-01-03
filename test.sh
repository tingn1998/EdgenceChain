sudo virtualenv --python=python3.6 venv && . venv/bin/activate

sudo pip install -r requirements.test.txt
py.test --cov test_edgencechain.py

