## file layout

hw2/
├── baseline_ctr.py
├── handshake.py
├── secure_record.py
├── ffdhe3072.pem
├── report.pdf
├── README.md
├── AI_USAGE.md
├── task 1 screenshot
├── test result output txt files
└── tests/
    ├── test_handshake.py
    └── test_secure_record.py

## Environment Requirements

Python 3.12.3
cryptography==49.0.0
pytest==9.1.1
OpenSSL

## Set up

cd ~/csce465-agentsec

python3 -m venv .venv
source .venv/bin/activate

python -m pip install cryptography==49.0.0 pytest==9.1.1

## Running Task files

cd hw2

Task 1:
python baseline_ctr.py

Task 2:
python handshake.py

Task 3:
python secure_record.py

## Running Test files

pytest -v (from in hw2 folder)

## Tests

The test files contain 13 seperate tests set by the requirements in the assignment documentation. All 13 tests passed when the pytest was ran and the results can be found in the github repo. 